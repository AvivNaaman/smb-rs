//! Session state

use std::sync::Arc;

use crate::sync_helpers::*;
use maybe_async::*;

use crate::connection::negotiation_state::NegotiateState;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::crypto::{
    kbkdf_hmacsha256, make_encrypting_algo, make_signing_algo, CryptoError, DerivedKey, KeyToDerive,
};
use crate::packets::smb2::{Dialect, EncryptionCipher, SessionFlags, SigningAlgorithmId};

use super::{MessageDecryptor, MessageEncryptor, MessageSigner};

/// Holds the state of a session, to be used for actions requiring data from session,
/// without accessing the entire session object.
/// This struct should be single-per-session, and wrapped in a shared pointer.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: u64,

    flags: SessionFlags,

    signer: Option<MessageSigner>,
    decryptor: Option<MessageDecryptor>,
    encryptor: Option<MessageEncryptor>,
}

impl SessionState {
    const SIGNING_KEY_LABEL: &[u8] = b"SMBSigningKey\x00";
    const S2C_DECRYPTION_KEY_LABEL: &[u8] = b"SMBS2CCipherKey\x00";
    const C2S_ENCRYPTION_KEY_LABEL: &[u8] = b"SMBC2SCipherKey\x00";

    #[maybe_async]
    pub async fn set(
        state: &mut Arc<Mutex<Self>>,
        session_key: &KeyToDerive,
        preauth_hash: &PreauthHashValue,
        negotation_state: &NegotiateState,
    ) -> crate::Result<()> {
        let deriver = KeyDeriver::new(session_key, preauth_hash);

        let signer = if let Some(signing_algo) = negotation_state.signing_algo() {
            Self::make_signer(&deriver, signing_algo)?
        } else {
            // Defaults to HMAC-SHA256 for SMB3.1.1, AES-CMAC for SMB3.1
            Self::make_signer(
                &deriver,
                match negotation_state.selected_dialect {
                    Dialect::Smb0311 => SigningAlgorithmId::AesCmac,
                    _ => SigningAlgorithmId::HmacSha256,
                },
            )?
        };

        let (dec, enc) = if let Some(cipher) = negotation_state.cipher() {
            (
                Some(Self::make_decryptor(&deriver, cipher)?),
                Some(Self::make_encryptor(&deriver, cipher)?),
            )
        } else {
            (None, None)
        };

        let mut state = state.lock().await?;
        state.signer = Some(signer);
        state.decryptor = dec;
        state.encryptor = enc;

        Ok(())
    }

    fn make_signer(
        deriver: &KeyDeriver,
        signing_algo: SigningAlgorithmId,
    ) -> Result<MessageSigner, CryptoError> {
        let signing_key = deriver.derive(Self::SIGNING_KEY_LABEL)?;
        Ok(MessageSigner::new(make_signing_algo(
            signing_algo,
            &signing_key,
        )?))
    }

    fn make_encryptor(
        deriver: &KeyDeriver,
        cipher: EncryptionCipher,
    ) -> Result<MessageEncryptor, CryptoError> {
        let c2s_encryption_key = deriver.derive(Self::C2S_ENCRYPTION_KEY_LABEL)?;
        Ok(MessageEncryptor::new(make_encrypting_algo(
            cipher,
            &c2s_encryption_key,
        )?))
    }

    fn make_decryptor(
        deriver: &KeyDeriver,
        cipher: EncryptionCipher,
    ) -> Result<MessageDecryptor, CryptoError> {
        let s2c_decryption_key = deriver.derive(Self::S2C_DECRYPTION_KEY_LABEL)?;

        Ok(MessageDecryptor::new(make_encrypting_algo(
            cipher,
            &s2c_decryption_key,
        )?))
    }

    #[maybe_async]
    pub async fn set_flags(state: &mut Arc<Mutex<Self>>, flags: SessionFlags) -> crate::Result<()> {
        state.lock().await?.flags = flags;
        Ok(())
    }

    #[maybe_async]
    pub async fn invalidate(state: &Arc<Mutex<Self>>) -> crate::Result<()> {
        let mut state = state.lock().await?;
        state.signer = None;
        state.decryptor = None;
        state.encryptor = None;
        Ok(())
    }

    #[maybe_async]
    pub async fn signing_enabled(state: &Arc<Mutex<Self>>) -> crate::Result<bool> {
        Ok(state.lock().await?.signer.is_some())
    }

    #[maybe_async]
    pub async fn encryption_enabled(state: &Arc<Mutex<Self>>) -> crate::Result<bool> {
        let state = state.lock().await?;
        return Ok(state.flags.encrypt_data()
            && state.encryptor.is_some()
            && state.decryptor.is_some());
    }

    #[maybe_async]
    pub async fn is_set_up(state: &Arc<Mutex<Self>>) -> crate::Result<bool> {
        Ok(Self::encryption_enabled(state).await? || Self::signing_enabled(state).await?)
    }

    pub fn decryptor(&mut self) -> Option<&mut MessageDecryptor> {
        self.decryptor.as_mut()
    }

    pub fn encryptor(&mut self) -> Option<&mut MessageEncryptor> {
        self.encryptor.as_mut()
    }

    pub fn signer(&mut self) -> Option<&mut MessageSigner> {
        self.signer.as_mut()
    }
}

/// A helper struct for deriving SMB2 keys from a session key and preauth hash.
struct KeyDeriver<'a> {
    session_key: &'a KeyToDerive,
    preauth_hash: &'a PreauthHashValue,
}

impl<'a> KeyDeriver<'a> {
    #[inline]
    pub fn new(session_key: &'a KeyToDerive, preauth_hash: &'a PreauthHashValue) -> Self {
        Self {
            session_key,
            preauth_hash,
        }
    }

    #[inline]
    pub fn derive(&self, label: &[u8]) -> Result<DerivedKey, CryptoError> {
        kbkdf_hmacsha256::<16>(self.session_key, label, self.preauth_hash)
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: Default::default(),
            flags: SessionFlags::new(),
            signer: Default::default(),
            decryptor: Default::default(),
            encryptor: Default::default(),
        }
    }
}
