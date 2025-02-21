use crate::sync_helpers::*;
use crate::{
    compression::*,
    msg_handler::*,
    packets::{netbios::*, smb2::*},
    session::SessionState,
};
use binrw::prelude::*;
use maybe_async::*;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use super::{
    negotiation_state::NegotiateState,
    preauth_hash::{PreauthHashState, PreauthHashValue},
};

/// This struct is tranforming messages to plain, parsed SMB2,
/// including (en|de)cryption, (de)compression, and signing/verifying.
#[derive(Default, Debug)]
pub struct Transformer {
    /// Sessions opened from this connection.
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionState>>>>,

    config: RwLock<TransformerConfig>,

    preauth_hash: Mutex<Option<PreauthHashState>>,
}

#[derive(Default, Debug)]
struct TransformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,
}

impl Transformer {
    /// When the connection is negotiated, this function is called to set up additional transformers,
    /// according to the allowed in the negotiation state.
    #[maybe_async]
    pub async fn negotiated(&self, neg_state: &NegotiateState) -> crate::Result<()> {
        {
            let config = self.config.read().await?;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await?;

        let compress = match &neg_state.compression {
            Some(compression) => {
                Some((Compressor::new(compression), Decompressor::new(compression)))
            }
            None => None,
        };
        config.compress = compress;
        config.negotiated = true;

        Ok(())
    }

    /// Adds the session to the list of active sessions.
    #[maybe_async]
    pub async fn session_started(&self, session: Arc<Mutex<SessionState>>) -> crate::Result<()> {
        let rconfig = self.config.read().await?;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = session.lock().await?.session_id;
        self.sessions
            .lock()
            .await?
            .insert(session_id, session.clone());

        Ok(())
    }

    #[maybe_async]
    pub async fn session_ended(&self, session_id: u64) -> crate::Result<()> {
        let s = { self.sessions.lock().await?.remove(&session_id) };
        match s {
            Some(_) => Ok(()),
            None => Err(crate::Error::InvalidState("Session not found!".to_string())),
        }
    }

    #[maybe_async]
    #[inline]
    pub async fn get_session(&self, session_id: u64) -> crate::Result<Arc<Mutex<SessionState>>> {
        if session_id == 0 {
            return Err(crate::Error::InvalidState("Session ID is 0!".to_string()));
        }
        self.sessions
            .lock()
            .await?
            .get(&session_id)
            .cloned()
            .ok_or(crate::Error::InvalidState("Session not found!".to_string()))
    }

    /// Calculate preauth integrity hash value, if required.
    #[maybe_async]
    async fn step_preauth_hash(&self, raw: &Vec<u8>) -> crate::Result<()> {
        let mut pa_hash = self.preauth_hash.lock().await?;
        // If already finished -- do nothing.
        if matches!(*pa_hash, Some(PreauthHashState::Finished(_))) {
            return Ok(());
        }
        // Initialize the hash if it's not initialized.
        if pa_hash.is_none() {
            *pa_hash = Some(PreauthHashState::default());
        }
        // Otherwise, update the hash!
        *pa_hash = pa_hash.take().unwrap().next(&raw).into();
        Ok(())
    }

    /// Finalizes the preauth hash, if it's not already finalized, and returns the value.
    #[maybe_async]
    pub async fn finalize_preauth_hash(&self) -> crate::Result<PreauthHashValue> {
        // TODO: Move into preauth hash structure.

        let mut pa_hash = self.preauth_hash.lock().await?;
        if let Some(PreauthHashState::Finished(hash)) = &*pa_hash {
            return Ok(hash.clone());
        }
        *pa_hash = pa_hash
            .take()
            .ok_or(crate::Error::InvalidState(
                "Preauth hash not initialized!".to_string(),
            ))?
            .finish()
            .into();

        match &*pa_hash {
            Some(PreauthHashState::Finished(hash)) => Ok(hash.clone()),
            _ => panic!("Preauth hash not finished!"),
        }
    }

    /// Gets an OutgoingMessage ready for sending, performs crypto operations, and returns the
    /// final bytes to be sent.
    #[maybe_async]
    pub async fn transform_outgoing(
        &self,
        msg: OutgoingMessage,
    ) -> crate::Result<NetBiosTcpMessage> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let set_session_id = msg.message.header.session_id;

        // 1. Sign
        let mut data = {
            let mut data = Vec::new();
            msg.message.write(&mut Cursor::new(&mut data))?;

            // 0. Update preauth hash as needed.
            self.step_preauth_hash(&data).await?;
            if should_sign {
                debug_assert!(
                    !should_encrypt,
                    "Should not sign and encrypt at the same time!"
                );
                let mut header_copy = msg.message.header.clone();

                let signer = {
                    self.get_session(set_session_id)
                        .await?
                        .lock()
                        .await?
                        .signer()
                        .cloned()
                };
                if let Some(mut signer) = signer {
                    signer.sign_message(&mut header_copy, &mut data)?;
                };
            };
            data
        };

        // 2. Compress
        data = {
            if msg.compress && data.len() > 1024 {
                let rconfig = self.config.read().await?;
                if let Some(compress) = &rconfig.compress {
                    let compressed = compress.0.compress(&data)?;
                    data.clear();
                    let mut cursor = Cursor::new(&mut data);
                    Message::Compressed(compressed).write(&mut cursor)?;
                };
            }
            data
        };

        // 3. Encrypt
        let data = {
            if msg.encrypt {
                let session = self.get_session(set_session_id).await?;
                let encryptor = { session.lock().await?.encryptor().cloned() };
                if let Some(mut encryptor) = encryptor {
                    debug_assert!(should_encrypt && !should_sign);
                    let encrypted = encryptor.encrypt_message(data, set_session_id)?;
                    let mut cursor = Cursor::new(Vec::new());
                    Message::Encrypted(encrypted).write(&mut cursor)?;
                    cursor.into_inner()
                } else {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: true,
                        phase: TranformPhase::EncryptDecrypt,
                        session_id: Some(set_session_id),
                        why: "Message is encrypted, but no encryptor is set up!",
                    }));
                }
            } else {
                data
            }
        };

        Ok(NetBiosTcpMessage::from_content_bytes(data))
    }

    /// Given a NetBiosTcpMessage, decrypts (if necessary), decompresses (if necessary) and returns the plain SMB2 message.
    #[maybe_async]
    pub async fn transform_incoming(
        &self,
        netbios: NetBiosTcpMessage,
    ) -> crate::Result<IncomingMessage> {
        let message = match netbios.parse_content()? {
            NetBiosMessageContent::SMB2Message(message) => Some(message),
            _ => None,
        }
        .ok_or(crate::Error::TranformFailed(TransformError {
            outgoing: false,
            phase: TranformPhase::EncodeDecode,
            session_id: None,
            why: "Message is not an SMB2 message!",
        }))?;

        let mut form = MessageForm::default();

        // 3. Decrpt
        let (message, raw) = if let Message::Encrypted(encrypted_message) = &message {
            let session = self
                .get_session(encrypted_message.header.session_id)
                .await?;
            let decryptor = { session.lock().await?.decryptor().cloned() };
            form.encrypted = true;
            match decryptor {
                Some(mut decryptor) => decryptor.decrypt_message(&encrypted_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TranformPhase::EncryptDecrypt,
                        session_id: Some(encrypted_message.header.session_id),
                        why: "Message is encrypted, but no decryptor is set up!",
                    }))
                }
            }
        } else {
            (message, netbios.content)
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Message::Encrypted(_)));
        let (message, raw) = if let Message::Compressed(compressed_message) = &message {
            let rconfig = self.config.read().await?;
            form.compressed = true;
            match &rconfig.compress {
                Some(compress) => compress.1.decompress(compressed_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TranformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                    }))
                }
            }
        } else {
            (message, raw)
        };

        let mut message = match message {
            Message::Plain(message) => message,
            _ => panic!("Unexpected message type"),
        };

        // 1. Verify signature (if required, according to the spec)
        if !form.encrypted
            && message.header.message_id != u64::MAX
            && message.header.status != Status::Pending
            && message.header.flags.signed()
        {
            let session_id = message.header.session_id;
            let session = self.get_session(session_id).await?;
            let verifier = { session.lock().await?.signer().cloned() };
            if let Some(mut verifier) = verifier {
                form.signed = true;
                verifier.verify_signature(&mut message.header, &raw)?;
            } else {
                return Err(crate::Error::TranformFailed(TransformError {
                    outgoing: false,
                    phase: TranformPhase::SignVerify,
                    session_id: Some(session_id),
                    why: "Message is signed, but no verifier is set up!",
                }));
            }
        }

        self.step_preauth_hash(&raw).await?;

        Ok(IncomingMessage { message, raw, form })
    }
}

#[derive(Debug)]
pub struct TransformError {
    outgoing: bool,
    phase: TranformPhase,
    session_id: Option<u64>,
    why: &'static str,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.outgoing {
            write!(
                f,
                "Failed to transform outgoing message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        } else {
            write!(
                f,
                "Failed to transform incoming message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        }
    }
}

#[derive(Debug)]
pub enum TranformPhase {
    EncodeDecode,
    SignVerify,
    CompressDecompress,
    EncryptDecrypt,
}
