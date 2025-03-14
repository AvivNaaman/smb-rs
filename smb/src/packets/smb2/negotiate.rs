use binrw::io::{SeekFrom, TakeSeekExt};
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use rand::rngs::OsRng;
use rand::Rng;

use crate::Error;

use super::super::binrw_util::prelude::*;
use super::super::guid::Guid;

#[binrw::binrw]
#[derive(Debug)]
pub struct NegotiateRequest {
    #[bw(calc = 0x24)]
    #[br(assert(_structure_size == 0x24))]
    _structure_size: u16,
    #[bw(try_calc(u16::try_from(dialects.len())))]
    dialect_count: u16,
    pub security_mode: NegotiateSecurityMode,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub capabilities: GlobalCapabilities,
    pub client_guid: Guid,
    // TODO: The 3 fields below are possibly a union in older versions of SMB.
    #[bw(calc = PosMarker::default())]
    negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    negotiate_context_count: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
    // Only on SMB 3.1.1 we have negotiate contexts.
    // Align to 8 bytes.
    #[brw(if(dialects.contains(&Dialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

#[bitfield]
#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NegotiateSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B14,
}

#[bitfield]
#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct GlobalCapabilities {
    pub dfs: bool,
    pub leasing: bool,
    pub large_mtu: bool,
    pub multi_channel: bool,

    pub persistent_handles: bool,
    pub directory_leasing: bool,
    pub encryption: bool,
    pub notifications: bool,

    #[skip]
    __: B24,
}

impl NegotiateRequest {
    pub fn new(
        client_netname: String,
        client_guid: Guid,
        supported_dialects: Vec<Dialect>,
        signing_algorithms: Vec<SigningAlgorithmId>,
        encrypting_algorithms: Vec<EncryptionCipher>,
        compression_algorithms: Vec<CompressionAlgorithm>,
    ) -> NegotiateRequest {
        let mut caps = GlobalCapabilities::new();
        let mut security_mode = NegotiateSecurityMode::new();
        if signing_algorithms.len() > 0 {
            caps.set_encryption(true);
        }

        let ctx_list = if supported_dialects.contains(&Dialect::Smb0311) {
            let mut ctx_list = vec![
                NegotiateContext {
                    context_type: NegotiateContextType::PreauthIntegrityCapabilities,
                    data: NegotiateContextValue::PreauthIntegrityCapabilities(
                        PreauthIntegrityCapabilities {
                            hash_algorithms: vec![HashAlgorithm::Sha512],
                            salt: (0..32).map(|_| OsRng.gen()).collect(),
                        },
                    ),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::NetnameNegotiateContextId,
                    data: NegotiateContextValue::NetnameNegotiateContextId(
                        NetnameNegotiateContextId {
                            netname: client_netname.into(),
                        },
                    ),
                },
            ];
            if encrypting_algorithms.len() > 0 {
                ctx_list.push(NegotiateContext {
                    context_type: NegotiateContextType::EncryptionCapabilities,
                    data: NegotiateContextValue::EncryptionCapabilities(EncryptionCapabilities {
                        ciphers: encrypting_algorithms,
                    }),
                });
            }
            if compression_algorithms.len() > 0 {
                ctx_list.push(NegotiateContext {
                    context_type: NegotiateContextType::CompressionCapabilities,
                    data: NegotiateContextValue::CompressionCapabilities(CompressionCaps {
                        flags: CompressionCapsFlags::new().with_chained(true),
                        compression_algorithms,
                    }),
                });
            }
            if signing_algorithms.len() > 0 {
                ctx_list.push(NegotiateContext {
                    context_type: NegotiateContextType::SigningCapabilities,
                    data: NegotiateContextValue::SigningCapabilities(SigningCapabilities {
                        signing_algorithms,
                    }),
                });
                security_mode.set_signing_enabled(true);
            }
            Some(ctx_list)
        } else {
            None
        };
        NegotiateRequest {
            security_mode: security_mode,
            capabilities: caps
                .with_dfs(true)
                .with_leasing(true)
                .with_large_mtu(true)
                .with_multi_channel(true)
                .with_persistent_handles(true)
                .with_directory_leasing(true),
            client_guid,
            dialects: supported_dialects,
            negotiate_context_list: ctx_list,
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NegotiateResponse {
    #[br(assert(_structure_size == 0x41))]
    #[bw(calc = 0x41)]
    _structure_size: u16,
    pub security_mode: NegotiateSecurityMode,
    pub dialect_revision: NegotiateDialect,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(assert(if dialect_revision == NegotiateDialect::Smb0311 { negotiate_context_count > 0 } else { negotiate_context_count == 0 }))]
    negotiate_context_count: u16,
    pub server_guid: Guid,
    pub capabilities: GlobalCapabilities,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: FileTime,
    pub server_start_time: FileTime,
    #[bw(calc = PosMarker::default())]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(try_calc(u16::try_from(buffer.len())))]
    security_buffer_length: u16,
    #[bw(calc = PosMarker::default())]
    negotiate_context_offset: PosMarker<u32>,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,

    #[brw(if(matches!(dialect_revision, NegotiateDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

impl NegotiateResponse {
    pub fn get_ctx_signing_algo(&self) -> Option<SigningAlgorithmId> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::SigningCapabilities => match &context.data {
                        NegotiateContextValue::SigningCapabilities(caps) => {
                            caps.signing_algorithms.first().copied()
                        }
                        _ => None,
                    },
                    _ => None,
                })
        })
    }

    pub fn get_ctx_integrity_algo(&self) -> Option<HashAlgorithm> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::PreauthIntegrityCapabilities => match &context.data {
                        NegotiateContextValue::PreauthIntegrityCapabilities(caps) => {
                            caps.hash_algorithms.first().copied()
                        }
                        _ => None,
                    },
                    _ => None,
                })
        })
    }

    pub fn get_ctx_compression(&self) -> Option<&CompressionCaps> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::CompressionCapabilities => match &context.data {
                        NegotiateContextValue::CompressionCapabilities(caps) => Some(caps),
                        _ => None,
                    },
                    _ => None,
                })
        })
    }

    pub fn get_ctx_encrypt_cipher(&self) -> Option<EncryptionCipher> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::EncryptionCapabilities => match &context.data {
                        NegotiateContextValue::EncryptionCapabilities(caps) => {
                            caps.ciphers.first().copied()
                        }
                        _ => None,
                    },
                    _ => None,
                })
        })
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[brw(repr(u16))]
pub enum Dialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311,
}

impl Dialect {
    pub const MAX: Dialect = Dialect::Smb0311;
    pub const MIN: Dialect = Dialect::Smb0202;
    pub const ALL: [Dialect; 5] = [
        Dialect::Smb0202,
        Dialect::Smb021,
        Dialect::Smb030,
        Dialect::Smb0302,
        Dialect::Smb0311,
    ];
}

/// Dialects that may be used in the SMB Negotiate Request.
/// The same as [Dialect] but with a wildcard for SMB 2.0.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum NegotiateDialect {
    Smb0202 = Dialect::Smb0202 as isize,
    Smb021 = Dialect::Smb021 as isize,
    Smb030 = Dialect::Smb030 as isize,
    Smb0302 = Dialect::Smb0302 as isize,
    Smb0311 = Dialect::Smb0311 as isize,
    Smb02Wildcard = 0x02FF,
}

impl TryFrom<NegotiateDialect> for Dialect {
    type Error = Error;

    fn try_from(value: NegotiateDialect) -> Result<Self, Self::Error> {
        match value {
            NegotiateDialect::Smb0202 => Ok(Dialect::Smb0202),
            NegotiateDialect::Smb021 => Ok(Dialect::Smb021),
            NegotiateDialect::Smb030 => Ok(Dialect::Smb030),
            NegotiateDialect::Smb0302 => Ok(Dialect::Smb0302),
            NegotiateDialect::Smb0311 => Ok(Dialect::Smb0311),
            _ => Err(Error::UnsupportedDialect(value)),
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NegotiateContext {
    // The entire context is 8-byte aligned.
    #[brw(align_before = 8)]
    pub context_type: NegotiateContextType,
    #[bw(calc = PosMarker::default())]
    data_length: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    #[br(args(&context_type))]
    #[br(map_stream = |s| s.take_seek(data_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&data_length))]
    pub data: NegotiateContextValue,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum NegotiateContextType {
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigningCapabilities = 0x0008,
    ContextTypeReserved = 0x0100,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[br(import(context_type: &NegotiateContextType))]
pub enum NegotiateContextValue {
    #[br(pre_assert(context_type == &NegotiateContextType::PreauthIntegrityCapabilities))]
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::EncryptionCapabilities))]
    EncryptionCapabilities(EncryptionCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::CompressionCapabilities))]
    CompressionCapabilities(CompressionCaps),
    #[br(pre_assert(context_type == &NegotiateContextType::NetnameNegotiateContextId))]
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    #[br(pre_assert(context_type == &NegotiateContextType::TransportCapabilities))]
    TransportCapabilities(TransportCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::RdmaTransformCapabilities))]
    RdmaTransformCapabilities(RdmaTransformCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::SigningCapabilities))]
    SigningCapabilities(SigningCapabilities),
}

impl Into<NegotiateContext> for NegotiateContextValue {
    fn into(self) -> NegotiateContext {
        NegotiateContext {
            context_type: self.get_matching_type(),
            data: self,
        }
    }
}

impl NegotiateContextValue {
    pub fn get_matching_type(&self) -> NegotiateContextType {
        match self {
            NegotiateContextValue::PreauthIntegrityCapabilities(_) => {
                NegotiateContextType::PreauthIntegrityCapabilities
            }
            NegotiateContextValue::EncryptionCapabilities(_) => {
                NegotiateContextType::EncryptionCapabilities
            }
            NegotiateContextValue::CompressionCapabilities(_) => {
                NegotiateContextType::CompressionCapabilities
            }
            NegotiateContextValue::NetnameNegotiateContextId(_) => {
                NegotiateContextType::NetnameNegotiateContextId
            }
            NegotiateContextValue::TransportCapabilities(_) => {
                NegotiateContextType::TransportCapabilities
            }
            NegotiateContextValue::RdmaTransformCapabilities(_) => {
                NegotiateContextType::RdmaTransformCapabilities
            }
            NegotiateContextValue::SigningCapabilities(_) => {
                NegotiateContextType::SigningCapabilities
            }
        }
    }
}

// u16 enum hash algorithms binrw 0x01 is sha512.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum HashAlgorithm {
    Sha512 = 0x01,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct PreauthIntegrityCapabilities {
    #[bw(try_calc(u16::try_from(hash_algorithms.len())))]
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    pub hash_algorithms: Vec<HashAlgorithm>,
    #[br(count = salt_length)]
    pub salt: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionCapabilities {
    #[bw(try_calc(u16::try_from(ciphers.len())))]
    cipher_count: u16,
    #[br(count = cipher_count)]
    ciphers: Vec<EncryptionCipher>,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum EncryptionCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompressionCaps {
    #[bw(try_calc(u16::try_from(compression_algorithms.len())))]
    compression_algorithm_count: u16,
    #[bw(calc = 0)]
    _padding: u16,
    pub flags: CompressionCapsFlags,
    #[br(count = compression_algorithm_count)]
    pub compression_algorithms: Vec<CompressionAlgorithm>,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum CompressionAlgorithm {
    None = 0x0000,
    LZNT1 = 0x0001,
    LZ77 = 0x0002,
    LZ77Huffman = 0x0003,
    PatternV1 = 0x0004,
    LZ4 = 0x0005,
}

impl CompressionAlgorithm {
    /// Relevant for processing compressed messages.
    pub fn original_size_required(&self) -> bool {
        matches!(
            self,
            CompressionAlgorithm::LZNT1
                | CompressionAlgorithm::LZ77
                | CompressionAlgorithm::LZ77Huffman
                | CompressionAlgorithm::LZ4
        )
    }
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            CompressionAlgorithm::None => "None",
            CompressionAlgorithm::LZNT1 => "LZNT1",
            CompressionAlgorithm::LZ77 => "LZ77",
            CompressionAlgorithm::LZ77Huffman => "LZ77+Huffman",
            CompressionAlgorithm::PatternV1 => "PatternV1",
            CompressionAlgorithm::LZ4 => "LZ4",
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u16)
    }
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct CompressionCapsFlags {
    pub chained: bool,
    #[skip]
    __: B31,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
pub struct NetnameNegotiateContextId {
    #[br(parse_with = binrw::helpers::until_eof)]
    netname: SizedWideString,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TransportCapabilities {
    pub accept_transport_layer_security: bool,
    #[skip]
    __: B31,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct RdmaTransformCapabilities {
    #[bw(try_calc(u16::try_from(transforms.len())))]
    transform_count: u16,

    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u32,

    #[br(count = transform_count)]
    pub transforms: Vec<u16>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SigningCapabilities {
    #[bw(try_calc(u16::try_from(signing_algorithms.len())))]
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    pub signing_algorithms: Vec<SigningAlgorithmId>,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum SigningAlgorithmId {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::packets::smb2::*;

    #[test]
    pub fn test_negotiate_res_parse() {
        let data = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff,
            0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x0, 0x1,
            0x0, 0x11, 0x3, 0x5, 0x0, 0xb9, 0x21, 0xf8, 0xe0, 0x15, 0x7, 0xaa, 0x41, 0xbe, 0x38,
            0x67, 0xfe, 0xbf, 0x5e, 0x2e, 0x11, 0x2f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0,
            0x80, 0x0, 0x0, 0x0, 0x80, 0x0, 0xa8, 0x76, 0xd8, 0x78, 0xc5, 0x69, 0xdb, 0x1, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x0, 0x2a, 0x0, 0xb0, 0x0, 0x0, 0x0, 0x60,
            0x28, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x1e, 0x30, 0x1c, 0xa0, 0x1a,
            0x30, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0x1e, 0x6, 0xa,
            0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
            0x0, 0x26, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x20, 0x0, 0x1, 0x0, 0xd5, 0x67, 0x1b,
            0x24, 0xa1, 0xe9, 0xcc, 0xc8, 0x93, 0xf5, 0x55, 0x5a, 0x31, 0x3, 0x43, 0x5a, 0x85,
            0x2b, 0xc3, 0xcb, 0x1a, 0xd3, 0x2d, 0xc5, 0x1f, 0x92, 0x80, 0x6e, 0xf3, 0xfb, 0x4d,
            0xd4, 0x0, 0x0, 0x2, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x7, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2,
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x4, 0x0,
        ];

        let response = match decode_content(&data).content {
            Content::NegotiateResponse(response) => response,
            _ => panic!("Expected NegotiateResponse"),
        };

        assert_eq!(
            response,
            NegotiateResponse {
                security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
                dialect_revision: NegotiateDialect::Smb0311,
                server_guid: Guid::from([
                    0xb9, 0x21, 0xf8, 0xe0, 0x15, 0x7, 0xaa, 0x41, 0xbe, 0x38, 0x67, 0xfe, 0xbf,
                    0x5e, 0x2e, 0x11
                ]),
                capabilities: GlobalCapabilities::new()
                    .with_dfs(true)
                    .with_leasing(true)
                    .with_large_mtu(true)
                    .with_multi_channel(true)
                    .with_directory_leasing(true),
                max_transact_size: 8388608,
                max_read_size: 8388608,
                max_write_size: 8388608,
                system_time: datetime!(2025-01-18 16:24:39.448746400).into(),
                server_start_time: FileTime::default(),
                buffer: [
                    0x60, 0x28, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x1e, 0x30, 0x1c,
                    0xa0, 0x1a, 0x30, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2,
                    0x2, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa
                ]
                .to_vec(),
                negotiate_context_list: Some(vec![
                    NegotiateContextValue::PreauthIntegrityCapabilities(
                        PreauthIntegrityCapabilities {
                            hash_algorithms: vec![HashAlgorithm::Sha512],
                            salt: [
                                0xd5, 0x67, 0x1b, 0x24, 0xa1, 0xe9, 0xcc, 0xc8, 0x93, 0xf5, 0x55,
                                0x5a, 0x31, 0x3, 0x43, 0x5a, 0x85, 0x2b, 0xc3, 0xcb, 0x1a, 0xd3,
                                0x2d, 0xc5, 0x1f, 0x92, 0x80, 0x6e, 0xf3, 0xfb, 0x4d, 0xd4
                            ]
                            .to_vec()
                        }
                    )
                    .into(),
                    NegotiateContextValue::EncryptionCapabilities(EncryptionCapabilities {
                        ciphers: vec![EncryptionCipher::Aes128Gcm]
                    })
                    .into(),
                    NegotiateContextValue::SigningCapabilities(SigningCapabilities {
                        signing_algorithms: vec![SigningAlgorithmId::AesGmac]
                    })
                    .into(),
                    NegotiateContextValue::RdmaTransformCapabilities(RdmaTransformCapabilities {
                        transforms: vec![0x0001, 0x0002]
                    })
                    .into(),
                    NegotiateContextValue::CompressionCapabilities(CompressionCaps {
                        flags: CompressionCapsFlags::new().with_chained(true),
                        compression_algorithms: vec![
                            CompressionAlgorithm::LZ77,
                            CompressionAlgorithm::PatternV1
                        ]
                    })
                    .into(),
                ])
            }
        )
    }
}
