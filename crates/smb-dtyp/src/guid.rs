use std::{fmt::Display, io::Cursor, str::FromStr};

use binrw::prelude::*;
use rand::{Rng, rngs::OsRng};

/// Represents a standard, 16-byte GUID.
///
/// Supports [`std::mem::size_of`].
#[derive(BinRead, BinWrite, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct Guid(u32, u16, u16, [u8; 8]);

impl Guid {
    /// The size of a GUID, in Bytes
    pub const GUID_SIZE: usize = 16;
    const _VALIDATE_SIZE_OF: [u8; Self::GUID_SIZE] = [0; size_of::<Self>()];

    pub const ZERO: Guid = Guid(0, 0, 0, [0; 8]);

    /// Generates a new random GUID.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        Self::try_from(&bytes).unwrap()
    }

    /// The maximum possible GUID value (all bits set to 1).
    pub const MAX: Guid = Guid(u32::MAX, u16::MAX, u16::MAX, [u8::MAX; 8]);

    pub const fn parse_uuid(s: &str) -> Result<Guid, &'static str> {
        use super::util::parse_byte;
        let b = s.as_bytes();
        let so = if b[0] == b'{' && b[b.len() - 1] == b'}' {
            if s.len() != 38 {
                return Err("Invalid UUID format");
            }
            1
        } else {
            if s.len() != 36 {
                return Err("Invalid UUID format");
            }
            0
        };
        if b[so + 8] != b'-' || b[so + 13] != b'-' || b[so + 18] != b'-' || b[so + 23] != b'-' {
            return Err("Invalid UUID format");
        }

        /// A macro to perform the same as `parse_bytes(b, i)?`,
        /// which is impossible in a const context.
        macro_rules! parse_byte {
            ($b:expr, $i:expr) => {
                match parse_byte($b, $i) {
                    Ok(val) => val,
                    Err(e) => return Err(e),
                }
            };
        }

        Ok(Guid(
            u32::from_be_bytes([
                parse_byte!(b, so),
                parse_byte!(b, so + 2),
                parse_byte!(b, so + 4),
                parse_byte!(b, so + 6),
            ]),
            u16::from_be_bytes([parse_byte!(b, so + 9), parse_byte!(b, so + 11)]),
            u16::from_be_bytes([parse_byte!(b, so + 14), parse_byte!(b, so + 16)]),
            [
                parse_byte!(b, so + 19),
                parse_byte!(b, so + 21),
                parse_byte!(b, so + 24),
                parse_byte!(b, so + 26),
                parse_byte!(b, so + 28),
                parse_byte!(b, so + 30),
                parse_byte!(b, so + 32),
                parse_byte!(b, so + 34),
            ],
        ))
    }
}

/// A macro to create a `Guid` from a string literal at compile time.
///
/// Prefer the [`make_guid!`] alias.
///
/// ```
/// use smb_dtyp::make_guid;
/// let guid = make_guid!("065eadf1-6daf-1543-b04f-10e69084c9ae");
/// assert_eq!(guid.to_string(), "065eadf1-6daf-1543-b04f-10e69084c9ae");
/// ```
#[macro_export]
macro_rules! guid {
    ($s:literal) => {{
        match $crate::Guid::parse_uuid($s) {
            Ok(guid) => guid,
            Err(_) => panic!("Invalid GUID format"),
        }
    }};
}

/// Alias for [`guid!`] following a verb–noun naming convention, used by `smb-fscc` for filesystem-info GUIDs.
/// Prefer `make_guid!` when constructing GUIDs in SMB filesystem contexts.
pub use guid as make_guid;

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        Self::try_from(&value).unwrap()
    }
}

impl TryFrom<&[u8; 16]> for Guid {
    type Error = binrw::Error;

    fn try_from(value: &[u8; 16]) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value);
        Guid::read(&mut cursor)
    }
}

impl From<Guid> for [u8; 16] {
    fn from(val: Guid) -> Self {
        let mut cursor = Cursor::new(Vec::new());
        val.write(&mut cursor).unwrap();
        cursor.into_inner().try_into().unwrap()
    }
}

impl FromStr for Guid {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Guid::parse_uuid(s)
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print first fields in little endian, and the rest in big endian:
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:12x}",
            self.0,
            self.1,
            self.2,
            self.3[0],
            self.3[1],
            self.3[2..]
                .iter()
                .fold(0u64, |acc, &x| (acc << 8) + x as u64)
        )
    }
}

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GUID_STR: &str = "065eadf1-6daf-1543-b04f-10e69084c9ae";
    const PARSED_GUID_VALUE: Guid = Guid(
        0x065eadf1,
        0x6daf,
        0x1543,
        [0xb0, 0x4f, 0x10, 0xe6, 0x90, 0x84, 0xc9, 0xae],
    );
    const TEST_GUID_BYTES: [u8; 16] = [
        0xf1u8, 0xad, 0x5e, 0x06, 0xaf, 0x6d, 0x43, 0x15, 0xb0, 0x4f, 0x10, 0xe6, 0x90, 0x84, 0xc9,
        0xae,
    ];

    #[test]
    pub fn test_guid_parse_runtime() {
        let guid = TEST_GUID_STR.parse::<Guid>().unwrap();
        assert_eq!(guid, PARSED_GUID_VALUE);
        assert_eq!(guid.to_string(), TEST_GUID_STR);
    }

    #[test]
    pub fn test_const_guid() {
        assert_eq!(
            make_guid!("065eadf1-6daf-1543-b04f-10e69084c9ae"),
            PARSED_GUID_VALUE
        );
        assert_eq!(
            make_guid!("{065eadf1-6daf-1543-b04f-10e69084c9ae}"),
            PARSED_GUID_VALUE
        );
    }

    #[test]
    pub fn test_guid_parse_bytes() {
        assert_eq!(Guid::try_from(&TEST_GUID_BYTES).unwrap(), PARSED_GUID_VALUE);
    }

    #[test]
    pub fn test_guid_write_bytes() {
        let mut cursor = Cursor::new(Vec::new());
        PARSED_GUID_VALUE.write(&mut cursor).unwrap();
        assert_eq!(cursor.into_inner(), TEST_GUID_BYTES);
    }
}
