#[cfg(not(feature = "single_threaded"))]
pub mod multi_worker;
#[cfg(feature = "single_threaded")]
pub mod single_worker;
pub mod worker_trait;
#[cfg(not(feature = "single_threaded"))]
pub use multi_worker::*;
#[cfg(feature = "single_threaded")]
pub use single_worker::*;
pub use worker_trait::*;

#[cfg(feature = "single_threaded")]
pub type WorkerImpl = SingleWorker;
#[cfg(not(feature = "single_threaded"))]
pub type WorkerImpl = AsyncWorker;
