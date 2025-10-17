use thiserror::Error;

/// Errors specific to the smb-fscc crate.
#[derive(Error, Debug)]
pub enum SmbFsccError {
    /// This error is returned when trying to convert a file information type enum into a specific information struct, but the enum variant does not match the expected struct.
    #[error("Unexpected information type. Expected {0}, got {1}")]
    UnexpectedInformationType(u8, u8),
}
