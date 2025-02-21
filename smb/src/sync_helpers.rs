///! This is a helper module that allows easy access and usage of
/// Async/Multi-threaded features in the library, according to the
/// features enabled.
#[cfg(not(feature = "async"))]
pub use std::{
    cell::OnceCell,
    sync::{Mutex, RwLock},
};

#[cfg(feature = "multi_threaded")]
pub use std::{sync::mpsc, thread::JoinHandle};

#[cfg(feature = "async")]
pub use tokio::{
    sync::{mpsc, OnceCell},
    task::JoinHandle,
};
#[cfg(feature = "async")]
pub use tokio_util::sync::CancellationToken;

#[cfg(feature = "async")]
use std::sync::LockResult;

/// A wrapper for [tokio::sync::RwLock] that mocks the behavior of [std::sync::RwLock].
#[cfg(feature = "async")]
#[derive(Debug, Default)]
pub struct RwLock<T: ?Sized> {
    inner: tokio::sync::RwLock<T>,
}

#[cfg(feature = "async")]
impl<T> RwLock<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(value),
        }
    }

    #[inline]
    pub async fn read(&self) -> LockResult<tokio::sync::RwLockReadGuard<'_, T>> {
        Ok(self.inner.read().await)
    }

    #[inline]
    pub async fn write(&self) -> LockResult<tokio::sync::RwLockWriteGuard<'_, T>> {
        Ok(self.inner.write().await)
    }
}

// Same for mutex, with lock():
#[cfg(feature = "async")]
#[derive(Debug, Default)]
pub struct Mutex<T: ?Sized> {
    inner: tokio::sync::Mutex<T>,
}

#[cfg(feature = "async")]
impl<T> Mutex<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(value),
        }
    }

    #[inline]
    pub async fn lock(&self) -> LockResult<tokio::sync::MutexGuard<'_, T>> {
        Ok(self.inner.lock().await)
    }
}
