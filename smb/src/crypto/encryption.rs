#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockEncrypt, BlockSizeUser};
#[cfg(feature = "encrypt_aes128ccm")]
use aes::Aes128;
#[cfg(feature = "encrypt_aes256ccm")]
use aes::Aes256;
#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
use ccm::{
    aead::AeadMutInPlace,
    consts::{U11, U16},
    Ccm, KeyInit, KeySizeUser,
};
use std::fmt::Debug;

use crate::packets::smb2::*;

use super::CryptoError;

pub struct EncryptionResult {
    pub signature: u128,
}

pub trait EncryptingAlgo: Debug + Send {
    /// Algo-specific encryption function.
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
    ) -> Result<EncryptionResult, CryptoError>;

    /// Algo-specific decryption function.
    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
        signature: u128,
    ) -> Result<(), CryptoError>;

    /// Returns the size of the nonce required by the encryption algorithm.
    fn nonce_size(&self) -> usize;

    /// Returns the nonce to be used for encryption/decryption (trimmed to the required size),
    /// as the rest of the nonce is expected to be zero.
    fn trim_nonce<'a>(&self, nonce: &'a EncryptionNonce) -> &'a [u8] {
        // Sanity: the rest of the nonce is expected to be zero.
        debug_assert!(nonce[self.nonce_size()..].iter().all(|&x| x == 0));
        &nonce[..self.nonce_size()]
    }

    /// Clone the algo into a boxed trait object.
    ///
    /// This method is added to allow cloning the trait object, and allow cloning it's users,
    /// to enable multi-threaded access to the same encryption algorithm:
    /// Some of the algorithms are only mutable, and can't be shared between threads.
    fn clone_box(&self) -> Box<dyn EncryptingAlgo>;
}

pub const ENCRYPTING_ALGOS: &[EncryptionCipher] = &[
    #[cfg(feature = "encrypt_aes128ccm")]
    EncryptionCipher::Aes128Ccm,
    #[cfg(feature = "encrypt_aes256ccm")]
    EncryptionCipher::Aes256Ccm,
];

pub fn make_encrypting_algo(
    encrypting_algorithm: EncryptionCipher,
    encrypting_key: &[u8],
) -> Result<Box<dyn EncryptingAlgo>, CryptoError> {
    if !ENCRYPTING_ALGOS.contains(&encrypting_algorithm) {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    match encrypting_algorithm {
        #[cfg(feature = "encrypt_aes128ccm")]
        EncryptionCipher::Aes128Ccm => Ok(CcmEncryptor::<Aes128>::build(encrypting_key.into())?),
        #[cfg(feature = "encrypt_aes256ccm")]
        EncryptionCipher::Aes256Ccm => Ok(CcmEncryptor::<Aes256>::build(encrypting_key.into())?),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
#[derive(Clone)]
pub struct CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    cipher: Ccm<C, U16, U11>,
}

#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
impl<C> CcmEncryptor<C>
where
    C: BlockCipher
        + BlockSizeUser<BlockSize = U16>
        + BlockEncrypt
        + KeyInit
        + Send
        + Clone
        + 'static,
{
    fn build(
        encrypting_key: &GenericArray<u8, <C as KeySizeUser>::KeySize>,
    ) -> Result<Box<dyn EncryptingAlgo>, CryptoError> {
        Ok(Box::new(Self {
            cipher: Ccm::<C, U16, U11>::new_from_slice(encrypting_key)?,
        }))
    }
}

#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
impl<C> EncryptingAlgo for CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + Send + Clone + 'static,
{
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
    ) -> Result<EncryptionResult, CryptoError> {
        let nonce = GenericArray::from_slice(self.trim_nonce(nonce));
        let signature = self
            .cipher
            .encrypt_in_place_detached(nonce, header_data, payload)?;

        Ok(EncryptionResult {
            signature: u128::from_le_bytes(signature.into()),
        })
    }

    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
        signature: u128,
    ) -> Result<(), CryptoError> {
        let nonce = GenericArray::from_slice(self.trim_nonce(nonce));
        self.cipher.decrypt_in_place_detached(
            nonce,
            header_data,
            payload,
            &signature.to_le_bytes().into(),
        )?;

        Ok(())
    }

    fn nonce_size(&self) -> usize {
        11
    }

    fn clone_box(&self) -> Box<dyn EncryptingAlgo> {
        Box::new(self.clone())
    }
}

#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
impl<C> Debug for CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ccm128Encrypter")
    }
}
