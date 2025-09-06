use thiserror::Error;

/// FSCC errors
#[derive(Error, Debug)]
pub enum SmbFsccError {
    #[error("Unexpected information type. Expected {0}, got {1}")]
    UnexpectedInformationType(u8, u8),
}
