#[cfg(feature = "rdma")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaConfig {
    pub rdma_type: RdmaType,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RdmaType {
    IWarp,
    RoCE,
    InfiniBand,
}
