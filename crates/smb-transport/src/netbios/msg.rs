use std::str::FromStr;

use binrw::{
    meta::{ReadEndian, WriteEndian},
    prelude::*,
};

/// NetBIOS session service packet header.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(big)]
pub struct NBSSPacketHeader {
    pub ptype: NBSSPacketType,
    // We force the size to be small, since no need to support
    // a large packet size.
    #[br(assert(flags == 0x00))]
    pub flags: u8,
    pub length: u16,
}

impl NBSSPacketHeader {
    /// Returns the size of the header network structure in bytes.
    pub const SIZE: usize = 4;
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum NBSSPacketType {
    SessionMessage = 0x00,
    SessionRequest = 0x81,
    PositiveSessionResponse = 0x82,
    NegativeSessionResponse = 0x83,
    SessionRetargetResponse = 0x84,
    SessionKeepAlive = 0x85,
}

/// NetBIOS session service packet trailer.
///
/// This does not include the session message parsing, since it is
/// a user-data only packet - mostly to avoid useless parsing & copying of data.
#[binrw::binrw]
#[derive(Debug)]
#[br(import(ptype: NBSSPacketType))]
#[brw(big)]
pub enum NBSSTrailer {
    #[br(pre_assert(ptype == NBSSPacketType::SessionRequest))]
    SessionRequest(NBSessionRequest),
    #[br(pre_assert(ptype == NBSSPacketType::PositiveSessionResponse))]
    PositiveSessionResponse(()),
    #[br(pre_assert(ptype == NBSSPacketType::NegativeSessionResponse))]
    NegativeSessionResponse(NBNegativeSessionResponse),
    #[br(pre_assert(ptype == NBSSPacketType::SessionRetargetResponse))]
    SessionRetargetResponse(NBSSSessionRetargetResponse),
    #[br(pre_assert(ptype == NBSSPacketType::SessionKeepAlive))]
    SessionKeepAlive(()),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(big)]
pub struct NBSessionRequest {
    pub called_name: NetBiosName,
    pub calling_name: NetBiosName,
}

/// Represents a NetBIOS name.
#[derive(Debug, PartialEq, Eq)]
pub struct NetBiosName {
    name: String,
    suffix: u8,
}

impl NetBiosName {
    /// The difference between byte to converted nibble value.
    const SUB_TO_GET_NIBBLE: u8 = b'A';
    /// NetBIOS names are exactly 16 bytes long, including the suffix.
    const TOTAL_NAME_BYTES: usize = 15;

    pub fn new(mut name: String, suffix: u8) -> Self {
        // Pad to length
        name.truncate(Self::TOTAL_NAME_BYTES);
        name.push_str(&" ".repeat(Self::TOTAL_NAME_BYTES - name.len()));

        NetBiosName { name, suffix }
    }
}

impl std::fmt::Display for NetBiosName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}<{:02X}>",
            self.name.trim_end_matches(' '),
            self.suffix
        )
    }
}

impl BinRead for NetBiosName {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let number_of_bytes = u8::read_options(reader, endian, ())?;

        let number_of_chars = number_of_bytes as usize / 2;
        if number_of_chars != Self::TOTAL_NAME_BYTES + 1 {
            return Err(binrw::Error::AssertFail {
                pos: reader.stream_position().unwrap(),
                message: format!(
                    "NetBiosName length is not {} bytes",
                    Self::TOTAL_NAME_BYTES + 1
                ),
            });
        }

        // First-level decoding
        let mut name = String::with_capacity(number_of_chars);
        let mut suffix = 0u8;
        for indx in 0..number_of_chars {
            let lower_byte = u8::read_options(reader, endian, ())?;
            let upper_byte = u8::read_options(reader, endian, ())?;

            let lower_nibble = lower_byte - Self::SUB_TO_GET_NIBBLE;
            let upper_nibble = upper_byte - Self::SUB_TO_GET_NIBBLE;

            let char = (lower_nibble << 4) | upper_nibble;

            if indx == number_of_chars - 1 {
                // Last byte is the suffix
                suffix = char;
            } else {
                name.push(char as char);
            }
        }
        // Next byte should be 0x00
        let null_byte = u8::read_options(reader, endian, ())?;
        if null_byte != 0x00 {
            return Err(binrw::Error::AssertFail {
                pos: reader.stream_position().unwrap(),
                message: "Expected null byte at the end of NetBiosName".to_string(),
            });
        }
        Ok(NetBiosName { name, suffix })
    }
}

impl ReadEndian for NetBiosName {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::None;
}

impl BinWrite for NetBiosName {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        let number_of_bytes = self.name.len() * 2 + 1 + 1; // +1 for suffix and +1 for null byte
        let length_to_write = number_of_bytes as u8;
        u8::write_options(&length_to_write, writer, endian, ())?;

        let name_and_suffix = self
            .name
            .chars()
            .chain(std::iter::once(self.suffix as char));

        // First-level encoding
        for c in name_and_suffix {
            if c as u8 > 0x7F {
                return Err(binrw::Error::AssertFail {
                    pos: writer.stream_position().unwrap(),
                    message: "NetBiosName contains non-ASCII characters".to_string(),
                });
            }

            let upper_nibble = (c as u8) >> 4;
            let lower_nibble = (c as u8) & 0x0F;

            let first_char = upper_nibble + Self::SUB_TO_GET_NIBBLE;
            let second_char = lower_nibble + Self::SUB_TO_GET_NIBBLE;

            u8::write_options(&first_char, writer, endian, ())?;
            u8::write_options(&second_char, writer, endian, ())?;
        }
        // Write null byte at the end
        u8::write_options(&0x00u8, writer, endian, ())?;
        Ok(())
    }
}

impl WriteEndian for NetBiosName {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::None;
}

impl FromStr for NetBiosName {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse NETBIOS<SUFFIX> format
        let mut parts = s.split('<');
        let name = parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing name"))?
            .to_string();
        if name.is_empty() || name.len() > Self::TOTAL_NAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid name length",
            ));
        }

        let suffix_str = parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing suffix"))?
            .trim_end_matches('>')
            .to_string();
        if suffix_str.is_empty() || suffix_str.len() > 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid suffix length",
            ));
        }
        let suffix = u8::from_str_radix(&suffix_str, 16);
        if suffix.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid suffix value",
            ));
        }
        let suffix = suffix.unwrap();
        Ok(NetBiosName::new(name, suffix))
    }
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NBNegativeSessionResponse {
    pub error_code: NBSSNegativeSessionResponseErrorCode,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big, repr(u8))]
pub enum NBSSNegativeSessionResponseErrorCode {
    NotListeningOnCalledName = 0x80,
    NotListeningForCallingName = 0x81,
    CalledNameNotPresent = 0x82,
    InsufficientResources = 0x83,
    UnspecifiedError = 0x8F,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NBSSSessionRetargetResponse {
    pub ip: u32,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use smb_tests::test_binrw;

    use super::*;

    test_binrw! {
        NetBiosName: NetBiosName::from_str("*SMBSERVER<20>").unwrap()
            => "20434b4644454e454346444546464346474546464343414341434143414341434100"
    }

    test_binrw! {
        struct NBSessionRequest {
            called_name: NetBiosName::new("*SMBSERVER".to_string(), 0x20),
            calling_name: NetBiosName::new("MACBOOKPRO-AF8A".to_string(), 0x0),
        } => "20434b4644454e45434644454646434647454646434341434143414341434143410020454e
        45424544454345504550454c464146434550434e4542454744494542414100"
    }

    test_binrw! {
        struct NBSSPacketHeader {
            ptype: NBSSPacketType::PositiveSessionResponse,
            flags: 0x00,
            length: 0x0000,
        } => "82000000"
    }
}
