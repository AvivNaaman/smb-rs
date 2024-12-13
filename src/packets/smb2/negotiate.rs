use binrw::prelude::*;
use binrw::io::SeekFrom;

use crate::pos_marker::PosMarker;


#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SMBNegotiateRequest {
    #[bw(calc = 0x24)]
    #[br(assert(structure_size == 0x24))]
    structure_size: u16,
    #[bw(try_calc(u16::try_from(dialects.len())))]
    dialect_count: u16,
    pub security_mode: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    pub capabilities: u32,
    pub client_guid: u128,
    // TODO: The 3 fields below are possibly a union in older versions of SMB.
    pub negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    negotiate_context_count: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    #[br(count = dialect_count)]
    pub dialects: Vec<SMBDialect>,
    // Only on SMB 3.1.1 we have negotiate contexts.
    // Align to 8 bytes.
    #[brw(if(dialects.contains(&SMBDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<SMBNegotiateContext>>
}

impl SMBNegotiateRequest {
    pub fn build(client_guid: u128) -> SMBNegotiateRequest {
        SMBNegotiateRequest {
            security_mode: 0x1,
            capabilities: 0x7f,
            client_guid: client_guid,
            dialects: vec![
                SMBDialect::Smb0202,
                SMBDialect::Smb021,
                SMBDialect::Smb030,
                SMBDialect::Smb0302,
                SMBDialect::Smb0311
            ],
            negotiate_context_list: Some(vec![
                SMBNegotiateContext {
                    context_type: SMBNegotiateContextType::PreauthIntegrityCapabilities,
                    data_length: 38,
                    reserved: 0,
                    data: SMBNegotiateContextValue::PreauthIntegrityCapabilities(
                        PreauthIntegrityCapabilities {
                            hash_algorithm_count: 1,
                            hash_algorithms: vec![HashAlgorithm::Sha512],
                            salt: (0..32).map(|_| rand::random::<u8>()).collect()
                        }
                    )
                },
                SMBNegotiateContext {
                    context_type: SMBNegotiateContextType::EncryptionCapabilities,
                    data_length: 10,
                    reserved: 0,
                    data: SMBNegotiateContextValue::EncryptionCapabilities(
                        EncryptionCapabilities {
                            cipher_count: 4,
                            ciphers: vec![
                                EncryptionCapabilitiesCipher::Aes128Ccm,
                                EncryptionCapabilitiesCipher::Aes128Gcm,
                                EncryptionCapabilitiesCipher::Aes256Ccm,
                                EncryptionCapabilitiesCipher::Aes256Gcm
                            ]
                        }
                    )
                },
                SMBNegotiateContext {
                    context_type: SMBNegotiateContextType::CompressionCapabilities,
                    data_length: 10,
                    reserved: 0,
                    data: SMBNegotiateContextValue::CompressionCapabilities(
                        CompressionCapabilities {
                            compression_algorithm_count: 1,
                            padding: 0,
                            flags: 0,
                            compression_algorithms: vec![0]
                        }
                    )
                },
                SMBNegotiateContext {
                    context_type: SMBNegotiateContextType::SigningCapabilities,
                    data_length: 6,
                    reserved: 0,
                    data: SMBNegotiateContextValue::SigningCapabilities(
                        SigningCapabilities {
                            signing_algorithm_count: 2,
                            signing_algorithms: vec![
                                SigningAlgorithmId::AesGmac,
                                SigningAlgorithmId::AesCmac
                            ]
                        }
                    )
                },
                SMBNegotiateContext {
                    context_type: SMBNegotiateContextType::NetnameNegotiateContextId,
                    data_length: 12,
                    reserved: 0,
                    data: SMBNegotiateContextValue::NetnameNegotiateContextId(
                        NetnameNegotiateContextId {
                            netname: binrw::NullWideString::from("AVIVVM")
                        }
                    )
                }
            ]),
            negotiate_context_offset: PosMarker::default()
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SMBNegotiateResponse {
    #[br(assert(structure_size == 0x41))]
    #[bw(calc = 0x41)]
    structure_size: u16,
    security_mode: u16,
    dialect_revision: SMBNegotiateResponseDialect,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    negotiate_context_count: u16, // TODO: if dialect contains 0x0311
    server_guid: u128,
    capabilities: u32,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: u64,
    server_start_time: u64,
    security_buffer_offset: PosMarker<u16>,
    #[bw(try_calc(u16::try_from(buffer.len())))]
    security_buffer_length: u16,
    negotiate_context_offset: PosMarker<u32>,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&security_buffer_offset))]
    buffer: Vec<u8>,

    #[brw(if(matches!(dialect_revision, SMBNegotiateResponseDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&negotiate_context_offset))]
    negotiate_context_list: Option<Vec<SMBNegotiateContext>>
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), little)]
pub enum SMBDialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), little)]
pub enum SMBNegotiateResponseDialect {
    Smb0202 = SMBDialect::Smb0202 as isize,
    Smb021 = SMBDialect::Smb021 as isize,
    Smb030 = SMBDialect::Smb030 as isize,
    Smb0302 = SMBDialect::Smb0302 as isize,
    Smb0311 = SMBDialect::Smb0311 as isize,
    Smb02Wildcard = 0x02FF,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub struct SMBNegotiateContext {
    // The entire context is 8-byte aligned.
    #[brw(align_before = 8)]
    context_type: SMBNegotiateContextType,
    data_length: u16,
    reserved: u32,
    #[br(args(&context_type))]
    data: SMBNegotiateContextValue
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), little)]
pub enum SMBNegotiateContextType {
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigningCapabilities = 0x0008,
    ContextTypeReserved = 0x0100,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(import(context_type: &SMBNegotiateContextType))]
enum SMBNegotiateContextValue {
    #[br(pre_assert(context_type == &SMBNegotiateContextType::PreauthIntegrityCapabilities))]
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::EncryptionCapabilities))]
    EncryptionCapabilities(EncryptionCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::CompressionCapabilities))]
    CompressionCapabilities(CompressionCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::NetnameNegotiateContextId))]
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::TransportCapabilities))]
    TransportCapabilities(TransportCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::RdmaTransformCapabilities))]
    RdmaTransformCapabilities(RdmaTransformCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::SigningCapabilities))]
    SigningCapabilities(SigningCapabilities)
}

// u16 enum hash algorithms binrw 0x01 is sha512.
#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
pub enum HashAlgorithm {
    Sha512 = 0x01
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
struct PreauthIntegrityCapabilities {
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    hash_algorithms: Vec<HashAlgorithm>,
    #[br(count = salt_length)]
    salt: Vec<u8>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct EncryptionCapabilities {
    cipher_count: u16,
    #[br(count = cipher_count)]
    ciphers: Vec<EncryptionCapabilitiesCipher>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
pub enum EncryptionCapabilitiesCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct CompressionCapabilities {
    compression_algorithm_count: u16,
    padding: u16,
    flags: u32,
    #[br(count = compression_algorithm_count)]
    compression_algorithms: Vec<u16>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct NetnameNegotiateContextId {
    netname: binrw::NullWideString
}


#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct TransportCapabilities {
    flags: u32
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct RdmaTransformCapabilities {
    transform_count: u16,
    reserved1: u16,
    reserved2: u32,
    #[br(count = transform_count)]
    transforms: Vec<u16>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct SigningCapabilities {
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    signing_algorithms: Vec<SigningAlgorithmId>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
pub enum SigningAlgorithmId {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002
}
