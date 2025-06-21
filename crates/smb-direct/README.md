# SMB Direct Transport for SMB

This crate provides the support for SMB Direct (SMB over RDMA) transport in the `smb` crate.

Currently, it depends on the `async-rdma` crate for RDMA operations, which initializes libibverbs to perform RDMA communication,
and is therefore, only supported on Linux systems.

This crate is currently NOT being published to crates.io, and is only available as a path dependency,
due to modifications made to the `async-rdma` crate.