//! SMB Message signing implementation.

use binrw::prelude::*;
use std::io::Cursor;

use crate::{Error, crypto};
use smb_msg::Header;

/// A struct for writing and verifying SMB message signatures.
///
/// This struct is NOT thread-safe, use clones for concurrent access.
#[derive(Debug)]
pub struct MessageSigner {
    signing_algo: Box<dyn crypto::SigningAlgo>,
}

impl MessageSigner {
    pub fn new(signing_algo: Box<dyn crypto::SigningAlgo>) -> MessageSigner {
        MessageSigner { signing_algo }
    }

    /// Verifies the signature of a message.
    pub fn verify_signature(&mut self, header: &mut Header, raw_data: &[u8]) -> crate::Result<()> {
        let calculated_signature = self.calculate_signature(header, raw_data)?;
        if calculated_signature != header.signature {
            return Err(Error::SignatureVerificationFailed);
        }
        Ok(())
    }

    /// Signs a message.
    pub fn sign_message(&mut self, header: &mut Header, raw_data: &mut [u8]) -> crate::Result<()> {
        debug_assert!(raw_data.len() >= Header::STRUCT_SIZE);

        header.signature = self.calculate_signature(header, raw_data)?;
        // Update raw data to include the signature.
        let mut header_writer = Cursor::new(&mut raw_data[0..Header::STRUCT_SIZE]);
        header.write(&mut header_writer)?;
        Ok(())
    }

    fn calculate_signature(&mut self, header: &mut Header, raw_data: &[u8]) -> crate::Result<u128> {
        // Write header with signature set to 0.
        let signture_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; Header::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signture_backup;

        // Start signing session with the header.
        self.signing_algo.start(header);
        self.signing_algo.update(&header_bytes.into_inner());

        // And write rest of the raw message.
        let message_body = &raw_data[Header::STRUCT_SIZE..];
        self.signing_algo.update(message_body);

        Ok(self.signing_algo.finalize())
    }
}

impl Clone for MessageSigner {
    fn clone(&self) -> Self {
        MessageSigner {
            signing_algo: self.signing_algo.clone_box(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::make_signing_algo;

    use super::*;

    const TEST_SIGNING_KEY: [u8; 16] = [
        0xAC, 0x36, 0xE9, 0x54, 0x3C, 0xD8, 0x88, 0xF0, 0xA8, 0x41, 0x23, 0xE4, 0x6B, 0xB2, 0xA0,
        0xD7,
    ];

    #[test]
    #[cfg(feature = "sign_gmac")]
    fn test_calc_signature() {
        // Some random session logoff request for testing.

        use smb_msg::SigningAlgorithmId;
        let raw_data = vec![
            0xfeu8, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x1, 0x0,
            0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53, 0x20, 0xc, 0x21, 0x0, 0x0, 0x0, 0x0, 0x76,
            0x23, 0x4b, 0x3c, 0x81, 0x2f, 0x51, 0xab, 0x8a, 0x5c, 0xf9, 0xfa, 0x43, 0xd4, 0xeb,
            0x28, 0x4, 0x0, 0x0, 0x0,
        ];
        let mut header = Header::read_le(&mut Cursor::new(
            &raw_data.as_slice()[..=Header::STRUCT_SIZE],
        ))
        .unwrap();

        let mut signer = MessageSigner::new(
            make_signing_algo(SigningAlgorithmId::AesGmac, &TEST_SIGNING_KEY).unwrap(),
        );
        let signature = signer.calculate_signature(&mut header, &raw_data).unwrap();
        assert_eq!(signature, 0x28ebd443faf95c8aab512f813c4b2376);
    }
}
