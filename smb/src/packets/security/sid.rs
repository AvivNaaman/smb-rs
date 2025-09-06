//! MS-DTYP 2.4.2.2

use std::str::FromStr;

use binrw::prelude::*;

use smb_dtyp::binrw_util::prelude::*;

/// SID (Security identifier)
///
/// [MS-DTYP 2.4.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25>)
///
/// This SID implementation supports binary read/write, and from/to string operations.
/// ```
/// use smb_dtyp::security::SID;
/// use std::str::FromStr;
/// const SID_STRING: &str = "S-1-5-21-782712087-4182988437-2163400469-1002";
/// let sid = SID::from_str(SID_STRING).unwrap();
/// let sid_string = sid.to_string();
/// assert_eq!(sid_string, SID_STRING);
/// ```
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct SID {
    #[bw(calc = 1)]
    #[br(assert(revision == 1))]
    revision: u8,
    #[bw(try_calc = sub_authority.len().try_into())]
    sub_authority_count: u8,
    #[brw(big)] // WE LOVE MICROSOFT!
    #[br(parse_with = read_u48)]
    #[bw(write_with = write_u48)]
    pub identifier_authority: u64,
    #[br(count = sub_authority_count)]
    pub sub_authority: Vec<u32>,
}
impl SID {
    /// SID common string prefix
    const PREFIX: &'static str = "S-1-";

    /// Administrators group SID
    pub const S_ADMINISTRATORS: &'static str = "S-1-5-32-544";
    /// Local System user SID
    pub const S_LOCAL_SYSTEM: &'static str = "S-1-5-18";
    /// Everyone group SID
    pub const S_EVERYONE: &'static str = "S-1-1-0";
}

impl FromStr for SID {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 1. starts with S-1-:
        if !s.starts_with(Self::PREFIX) {
            return Err("SID must start with S-1-");
        }
        let mut s = s[Self::PREFIX.len()..].split('-');
        // 2. authority is a number, possibly in hex.
        let identifier_authority = match s.next() {
            Some("0x") => {
                // hex is only for sub-authorities > 32 bits!
                let p = u64::from_str_radix(
                    s.next().ok_or("Identifier authority format is incorrect")?,
                    16,
                )
                .map_err(|_| "Identifier authority format is incorrect")?;
                if p >> 32 == 0 {
                    p
                } else {
                    return Err("Identifier authority format is incorrect");
                }
            }
            Some(x) => x
                .parse()
                .map_err(|_| "Identifier authority format is incorrect")?,
            None => return Err("SID format is incorrect - missing authority"),
        };
        // 3. sub-authorities are numbers.
        let sub_authority = s
            .map(|x| x.parse().map_err(|_| "Sub-authority format is incorrect"))
            .collect::<Result<_, _>>()?;
        Ok(SID {
            identifier_authority,
            sub_authority,
        })
    }
}

impl std::fmt::Display for SID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // MS-DTYP 2.4.2.1: SID String Format
        write!(f, "S-1-")?;
        if self.identifier_authority >> 32 == 0 {
            write!(f, "{}", self.identifier_authority)?;
        } else {
            write!(f, "0x{:x}", self.identifier_authority)?;
        }
        for sub_authority in &self.sub_authority {
            write!(f, "-{sub_authority}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID_STRING: &str = "S-1-5-21-782712087-4182988437-2163400469-1002";

    #[test]
    fn test_sid_to_from_string() {
        let sid_value: SID = SID {
            identifier_authority: 5,
            sub_authority: vec![21, 782712087, 4182988437, 2163400469, 1002],
        };
        assert_eq!(SID_STRING.parse::<SID>().unwrap(), sid_value);
        assert_eq!(sid_value.to_string(), SID_STRING);
    }
    #[test]
    fn test_sid_to_from_bin() {
        let sid_value = [
            0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e,
            0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xea, 0x3, 0x0, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(&sid_value);
        assert_eq!(
            SID::read_le(&mut cursor).unwrap(),
            SID_STRING.parse().unwrap()
        );
    }
}
