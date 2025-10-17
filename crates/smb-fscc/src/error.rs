use thiserror::Error;

/// Errors specific to the smb-fscc crate.
#[derive(Error, Debug)]
pub enum SmbFsccError {
    /// Describes a failure to convert info class enum to varaint.
    ///
    /// For example, when trying to convert a [`QueryFileInfo`][`crate::QueryFileInfo`] to [`FileAccessInformation`][`crate::FileAccessInformation`],
    /// and the actual variant is different.
    #[error("Unexpected information type. Expected {0} ({1}), got {2}")]
    UnexpectedInformationType(&'static str, u8, u8),
}
