use crate::sync_helpers::*;
use maybe_async::*;

pub trait ReadAt {
    #[cfg(feature = "async")]
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + std::marker::Send;
    #[cfg(not(feature = "async"))]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> crate::Result<usize>;
}

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait WriteAt {
    #[cfg(feature = "async")]
    fn write_at(
        &self,
        buf: &[u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + std::marker::Send;
    #[cfg(not(feature = "async"))]
    fn write_at(&self, buf: &[u8], offset: u64) -> crate::Result<usize>;
}

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait GetLen {
    async fn get_len(&self) -> crate::Result<u64>;
}

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait SetLen {
    async fn set_len(&self, len: u64) -> crate::Result<()>;
}

mod impls {
    use super::*;

    #[cfg(not(feature = "async"))]
    use std::{
        fs::File,
        io::{Read, Seek, Write},
    };
    #[cfg(feature = "async")]
    use tokio::{
        fs::File,
        io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    };

    #[cfg(feature = "async")]
    pub trait ReadSeek: AsyncRead + AsyncSeek + Unpin {}
    #[cfg(not(feature = "async"))]
    pub trait ReadSeek: Read + Seek {}
    impl ReadSeek for File {}
    impl<F: ReadSeek + Send> ReadAt for Mutex<F> {
        #[maybe_async]
        async fn read_at(&self, buf: &mut [u8], offset: u64) -> crate::Result<usize> {
            let mut reader = self
                .lock()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            reader.seek(std::io::SeekFrom::Start(offset)).await?;
            Ok(reader.read(buf).await?)
        }
    }

    #[cfg(feature = "async")]
    pub trait WriteSeek: AsyncWrite + AsyncSeek + Unpin {}
    #[cfg(not(feature = "async"))]
    pub trait WriteSeek: Write + Seek {}
    impl WriteSeek for File {}
    impl<F: WriteSeek + Send> WriteAt for Mutex<F> {
        #[maybe_async]
        async fn write_at(&self, buf: &[u8], offset: u64) -> crate::Result<usize> {
            let mut writer = self
                .lock()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            writer.seek(std::io::SeekFrom::Start(offset)).await?;
            Ok(writer.write(buf).await?)
        }
    }

    impl GetLen for Mutex<File> {
        #[maybe_async]
        async fn get_len(&self) -> crate::Result<u64> {
            let file = self
                .lock()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(file.metadata().await?.len())
        }
    }

    impl SetLen for Mutex<File> {
        #[maybe_async]
        async fn set_len(&self, len: u64) -> crate::Result<()> {
            let file = self
                .lock()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(File::set_len(&file, len).await?)
        }
    }
}

pub use impls::*;

#[cfg(not(feature = "single_threaded"))]
mod copy {
    use super::*;

    use std::sync::{Arc, atomic::AtomicU64};

    #[derive(Debug)]
    struct CopyState {
        current_block: AtomicU64,

        last_block: u64,
        total_size: u64,

        max_chunk_size: u64,
        num_jobs: usize,
    }

    /// Generic block copy function.
    #[maybe_async]
    pub async fn block_copy<
        F: ReadAt + GetLen + Send + Sync + 'static,
        T: WriteAt + SetLen + Send + Sync + 'static,
    >(
        from: F,
        to: T,
        jobs: usize,
    ) -> crate::Result<()> {
        const MAX_JOBS: usize = 128;
        if jobs > MAX_JOBS {
            return Err(crate::Error::InvalidArgument(format!(
                "Number of jobs exceeds maximum allowed ({MAX_JOBS})"
            )));
        }

        const DEFAULT_JOBS: usize = 16;
        let jobs = if jobs == 0 {
            log::debug!("No jobs specified, using default: {DEFAULT_JOBS}",);
            DEFAULT_JOBS
        } else {
            jobs
        };

        const CHUNK_SIZE: u64 = 2u64.pow(16);

        let file_length = from.get_len().await?;
        to.set_len(file_length).await?;

        if file_length == 0 {
            log::debug!("Source file is empty, nothing to copy.");
            return Ok(());
        }

        let copy_state = CopyState {
            current_block: AtomicU64::new(0),
            last_block: file_length / CHUNK_SIZE,
            total_size: file_length,
            max_chunk_size: CHUNK_SIZE,
            num_jobs: jobs,
        };
        log::debug!("Starting parallel copy: {copy_state:?}",);
        start_parallel_copy(from, to, copy_state).await?;

        Ok(())
    }

    #[cfg(feature = "async")]
    async fn start_parallel_copy<
        F: ReadAt + GetLen + Send + Sync + 'static,
        T: WriteAt + SetLen + Send + Sync + 'static,
    >(
        from: F,
        to: T,
        state: CopyState,
    ) -> crate::Result<()> {
        use tokio::task::JoinSet;

        to.set_len(from.get_len().await?).await?;

        let to = Arc::new(to);
        let from = Arc::new(from);
        let state = Arc::new(state);

        let mut handles = JoinSet::new();
        for task_id in 0..state.num_jobs {
            let from = from.clone();
            let to = to.clone();
            let state = state.clone();
            handles.spawn(async move { block_copy_task(from, to, state, task_id).await });
        }

        handles.join_all().await;
        Ok(())
    }

    #[cfg(feature = "multi_threaded")]
    fn start_parallel_copy<
        F: ReadAt + GetLen + Send + Sync + 'static,
        T: WriteAt + SetLen + Send + Sync + 'static,
    >(
        from: F,
        to: T,
        state: CopyState,
    ) -> crate::Result<()> {
        let from = Arc::new(from);
        let to = Arc::new(to);
        let state = Arc::new(state);

        let mut handles = Vec::new();
        for task_id in 0..state.num_jobs {
            let from = from.clone();
            let to = to.clone();
            let state = state.clone();
            let handle =
                std::thread::spawn(move || block_copy_task(from.clone(), to, state, task_id));
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap()?;
        }

        Ok(())
    }

    #[maybe_async]
    async fn block_copy_task<
        F: ReadAt + GetLen + Send + Sync,
        T: WriteAt + SetLen + Send + Sync,
    >(
        from: Arc<F>,
        to: Arc<T>,
        state: Arc<CopyState>,
        task_id: usize,
    ) -> crate::Result<()> {
        log::debug!("Starting copy task {task_id}",);

        let mut curr_chunk = vec![0u8; state.max_chunk_size as usize];

        loop {
            let current_block = state
                .current_block
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if current_block > state.last_block {
                break;
            }
            let chunk_size = if current_block == state.last_block {
                let last_block_leftover = state.total_size % state.max_chunk_size;
                if last_block_leftover == 0 {
                    break;
                }
                last_block_leftover
            } else {
                state.max_chunk_size
            } as usize;

            let offset = current_block * state.max_chunk_size;
            let bytes_read = from.read_at(&mut curr_chunk[..chunk_size], offset).await?;
            if bytes_read < chunk_size {
                log::warn!(
                    "Task {task_id}: Read less bytes than expected. File might be corrupt. Expected: {chunk_size}, Read: {bytes_read}"
                );
            }
            let valid_chunk_end = bytes_read;
            to.write_at(&curr_chunk[..valid_chunk_end], offset).await?;
        }
        log::debug!("Copy task {task_id} completed",);
        Ok(())
    }
}

#[cfg(feature = "single_threaded")]
mod copy {
    use super::*;

    /// Generic block copy function.
    pub fn block_copy<F: ReadAt + GetLen, T: WriteAt + SetLen>(
        from: F,
        to: T,
        _jobs: usize,
    ) -> crate::Result<()> {
        let file_length = from.get_len()?;
        to.set_len(file_length)?;

        if file_length == 0 {
            log::debug!("Source file is empty, nothing to copy.");
            return Ok(());
        }

        let mut curr_chunk = vec![0u8; 2u64.pow(16) as usize];
        let mut offset = 0;

        while offset < file_length {
            let chunk_size = if offset + curr_chunk.len() as u64 > file_length {
                (file_length - offset) as usize
            } else {
                curr_chunk.len()
            };
            let bytes_read = from.read_at(&mut curr_chunk[..chunk_size], offset)?;
            if bytes_read < chunk_size {
                log::warn!(
                    "Read less bytes than expected. File might be corrupt. Expected: {chunk_size}, Read: {bytes_read}"
                );
            }
            to.write_at(&curr_chunk[..bytes_read], offset)?;
            offset += bytes_read as u64;
        }
        Ok(())
    }
}

pub use copy::*;
