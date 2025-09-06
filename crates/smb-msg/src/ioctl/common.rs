use std::ops::{Deref, DerefMut};

/// A trait that helps calculating the size of the buffer for IOCTL requests.
// TODO: Make sure it is tested for all types of IOCTL requests.
pub trait IoctlRequestContent {
    /// Returns the size of the buffer for IOCTL requests -- the size of the ENCODED data, in bytes.
    fn get_bin_size(&self) -> u32;
}

impl IoctlRequestContent for () {
    fn get_bin_size(&self) -> u32 {
        0
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlBuffer {
    #[br(parse_with = binrw::helpers::until_eof)]
    buffer: Vec<u8>,
}

impl From<Vec<u8>> for IoctlBuffer {
    fn from(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }
}

impl From<&[u8]> for IoctlBuffer {
    fn from(buffer: &[u8]) -> Self {
        Self {
            buffer: buffer.to_vec(),
        }
    }
}

impl IoctlRequestContent for IoctlBuffer {
    fn get_bin_size(&self) -> u32 {
        self.len() as u32
    }
}

impl Deref for IoctlBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for IoctlBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}
