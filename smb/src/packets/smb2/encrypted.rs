//! Encrypted messages

use std::io::Cursor;

use binrw::prelude::*;
const SIGNATURE_SIZE: usize = 16;

/// The nonce used for encryption.
/// Depending on the encryption algorithm, the nonce may be trimmed to a smaller size when used,
/// or padded with zeroes to match the required size. When transmitted, the full 16 bytes are used.
pub type EncryptionNonce = [u8; 16];

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little, magic(b"\xfdSMB"))]
pub struct EncryptedHeader {
    pub signature: u128,
    pub nonce: EncryptionNonce,
    pub original_message_size: u32,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = 1)] // MUST be set to 1.
    #[br(assert(_flags == 1))]
    _flags: u16,
    pub session_id: u64,
}

impl EncryptedHeader {
    const MAGIC_SIZE: usize = 4;

    /// The bytes to use as the additional data for the AEAD out of this header.
    /// Make sure to call it after all fields (except signature) are finalized.
    ///
    /// Returns (according to MS-SMB2) the bytes of the header, excluding the magic and the signature.
    pub fn aead_bytes(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(vec![]);
        self.write(&mut cursor).unwrap();
        cursor.into_inner()[Self::MAGIC_SIZE + SIGNATURE_SIZE..].to_vec()
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct EncryptedMessage {
    pub header: EncryptedHeader,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub encrypted_message: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_parse_encrypted_header() {
        let header = [
            0xfdu8, 0x53, 0x4d, 0x42, 0x92, 0x2e, 0xe8, 0xf2, 0xa0, 0x6e, 0x7a, 0xd4, 0x70, 0x22,
            0xd7, 0x1d, 0xb, 0x2, 0x6b, 0x11, 0xa, 0x57, 0x67, 0x55, 0x6d, 0xa0, 0x23, 0x73, 0x1,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x55, 0x0,
            0x0, 0x24, 0x0, 0x30, 0x0, 0x0,
        ];
        assert_eq!(
            EncryptedHeader::read(&mut Cursor::new(header)).unwrap(),
            EncryptedHeader {
                signature: u128::from_le_bytes([
                    0x92, 0x2e, 0xe8, 0xf2, 0xa0, 0x6e, 0x7a, 0xd4, 0x70, 0x22, 0xd7, 0x1d, 0xb,
                    0x2, 0x6b, 0x11,
                ]),
                nonce: [
                    0xa, 0x57, 0x67, 0x55, 0x6d, 0xa0, 0x23, 0x73, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0,
                ],
                original_message_size: 104,
                session_id: 0x300024000055
            }
        )
    }

    #[test]
    fn test_write_encrypted_header() {
        let header = EncryptedHeader {
            signature: u128::from_le_bytes([
                0x2a, 0x45, 0x6c, 0x5d, 0xd0, 0xc3, 0x2d, 0xd4, 0x47, 0x85, 0x21, 0xf7, 0xf6, 0xa8,
                0x87, 0x5b,
            ]),
            nonce: [
                0xbe, 0xe6, 0xbf, 0xe5, 0xa1, 0xe6, 0x7b, 0xb1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0,
            ],
            original_message_size: 248,
            session_id: 0x0000300024000055,
        };
        let mut buffer = Vec::new();
        header.write(&mut Cursor::new(&mut buffer)).unwrap();
        assert_eq!(
            buffer,
            [
                0xfd, 0x53, 0x4d, 0x42, 0x2a, 0x45, 0x6c, 0x5d, 0xd0, 0xc3, 0x2d, 0xd4, 0x47, 0x85,
                0x21, 0xf7, 0xf6, 0xa8, 0x87, 0x5b, 0xbe, 0xe6, 0xbf, 0xe5, 0xa1, 0xe6, 0x7b, 0xb1,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                0x55, 0x0, 0x0, 0x24, 0x0, 0x30, 0x0, 0x0
            ]
        );
    }
}
