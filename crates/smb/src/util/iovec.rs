use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// A buffer in an IoVec, either owned or shared.
///
/// This implements Deref to `&[u8]` for easy access to the underlying data.
///
/// Note that DerefMut is also implemented, but will panic if called on a Shared buffer,
/// since shared buffers cannot be mutated by default!
#[derive(Debug, Clone)]
pub enum IoVecBuf {
    Owned(Vec<u8>),
    Shared(Arc<[u8]>),
}

impl Deref for IoVecBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            IoVecBuf::Owned(v) => v.as_slice(),
            IoVecBuf::Shared(v) => v.as_ref(),
        }
    }
}

impl DerefMut for IoVecBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            IoVecBuf::Owned(v) => v.as_mut_slice(),
            IoVecBuf::Shared(_) => {
                panic!("Cannot get mutable reference to shared IoVecBuf");
            }
        }
    }
}

impl From<Vec<u8>> for IoVecBuf {
    fn from(v: Vec<u8>) -> Self {
        IoVecBuf::Owned(v)
    }
}

impl From<Arc<[u8]>> for IoVecBuf {
    fn from(v: Arc<[u8]>) -> Self {
        IoVecBuf::Shared(v)
    }
}

/// A vector of buffers for zero-copy I/O operations.
#[derive(Debug, Clone, Default)]
pub struct IoVec(Vec<IoVecBuf>);

impl IoVec {
    /// Returns the total size of all buffers in the IoVec (in bytes).
    pub fn total_size(&self) -> usize {
        self.0.iter().map(|buf| buf.len()).sum()
    }

    /// Inserts a new owned buffer to the IoVec, and returns a mutable reference to it.
    pub fn insert_owned(&mut self, at: usize, buf: Vec<u8>) -> &mut Vec<u8> {
        let to_add = IoVecBuf::Owned(buf);
        self.0.insert(at, to_add);
        self.0
            .get_mut(at)
            .map(|b| match b {
                IoVecBuf::Owned(v) => v,
                _ => panic!("Just added an owned buffer, but it's not owned?"),
            })
            .unwrap()
    }

    /// Adds a new owned buffer to the end of the IoVec, and returns a mutable reference to it.
    pub fn add_owned(&mut self, buf: Vec<u8>) -> &mut Vec<u8> {
        self.insert_owned(self.0.len(), buf)
    }

    /// Inserts a new shared buffer to the IoVec, and returns a reference to it.
    pub fn insert_shared(&mut self, at: usize, buf: Arc<[u8]>) -> &Arc<[u8]> {
        let to_add = IoVecBuf::Shared(buf);
        self.0.insert(at, to_add);
        self.0
            .get_mut(at)
            .map(|b| match b {
                IoVecBuf::Shared(v) => v,
                _ => panic!("Just added a shared buffer, but it's not shared?"),
            })
            .unwrap()
    }

    /// Adds a new shared buffer to the end of the IoVec, and returns a reference to it.
    pub fn add_shared(&mut self, buf: Arc<[u8]>) -> &Arc<[u8]> {
        self.insert_shared(self.0.len(), buf)
    }

    /// Consolidates all buffers into a single owned buffer,
    /// and puts it in the IoVec, replacing all previous buffers.
    pub fn consolidate(&mut self) -> &mut Vec<u8> {
        let mut consolidated = Vec::with_capacity(self.total_size());
        for buf in self.0.iter() {
            consolidated.extend_from_slice(buf);
        }
        self.0.clear();
        self.add_owned(consolidated)
    }
}

impl From<Vec<IoVecBuf>> for IoVec {
    fn from(v: Vec<IoVecBuf>) -> Self {
        Self(v)
    }
}

impl From<IoVecBuf> for IoVec {
    fn from(v: IoVecBuf) -> Self {
        Self(vec![v])
    }
}

impl From<Vec<u8>> for IoVec {
    fn from(v: Vec<u8>) -> Self {
        Self(vec![IoVecBuf::Owned(v)])
    }
}

impl From<Vec<Vec<u8>>> for IoVec {
    fn from(v: Vec<Vec<u8>>) -> Self {
        Self(v.into_iter().map(IoVecBuf::Owned).collect())
    }
}

impl Deref for IoVec {
    type Target = [IoVecBuf];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IoVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
