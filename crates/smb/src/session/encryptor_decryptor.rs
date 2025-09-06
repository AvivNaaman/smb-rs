//! SMB Message encryption/decryption implementation.

use binrw::prelude::*;
use rand::RngCore;
use rand::rngs::OsRng;
use std::io::Cursor;

use crate::{
    crypto,
    packets::smb2::{Response, encrypted::*},
};

#[derive(Debug)]
pub struct MessageEncryptor {
    algo: Box<dyn crypto::EncryptingAlgo>,
}

impl MessageEncryptor {
    pub fn new(algo: Box<dyn crypto::EncryptingAlgo>) -> MessageEncryptor {
        MessageEncryptor { algo }
    }

    /// Encrypts message in-place.
    pub fn encrypt_message(
        &mut self,
        mut message: Vec<u8>,
        session_id: u64,
    ) -> crate::Result<EncryptedMessage> {
        debug_assert!(session_id != 0);

        // Serialize message:
        let mut header = EncryptedHeader {
            signature: 0,
            nonce: self.gen_nonce(),
            original_message_size: message.len().try_into()?,
            session_id,
        };

        let result = self
            .algo
            .encrypt(&mut message, &header.aead_bytes(), &header.nonce)?;

        header.signature = result.signature;

        log::debug!("Encrypted message with signature: {:?}", header.signature);

        Ok(EncryptedMessage {
            header,
            encrypted_message: message,
        })
    }

    fn gen_nonce(&self) -> [u8; 16] {
        let mut nonce = [0; 16];
        // Generate self.algo.nonce_size() random bytes:
        OsRng.fill_bytes(&mut nonce[..self.algo.nonce_size()]);
        nonce
    }
}

impl Clone for MessageEncryptor {
    fn clone(&self) -> Self {
        MessageEncryptor {
            algo: self.algo.clone_box(),
        }
    }
}

#[derive(Debug)]
pub struct MessageDecryptor {
    algo: Box<dyn crypto::EncryptingAlgo>,
}

impl MessageDecryptor {
    pub fn new(algo: Box<dyn crypto::EncryptingAlgo>) -> MessageDecryptor {
        MessageDecryptor { algo }
    }

    pub fn decrypt_message(
        &mut self,
        msg_in: EncryptedMessage,
    ) -> crate::Result<(Response, Vec<u8>)> {
        // decrypt in-place
        let mut buffer = msg_in.encrypted_message;
        let aead_bytes = msg_in.header.aead_bytes();
        let nonce = msg_in.header.nonce;
        let signature = msg_in.header.signature;
        self.algo
            .decrypt(&mut buffer, &aead_bytes, &nonce, signature)?;

        // deserialize
        let result = Response::read(&mut Cursor::new(&buffer))?;

        log::debug!("Decrypted with signature {}", msg_in.header.signature);
        Ok((result, buffer))
    }
}

impl Clone for MessageDecryptor {
    fn clone(&self) -> Self {
        MessageDecryptor {
            algo: self.algo.clone_box(),
        }
    }
}
