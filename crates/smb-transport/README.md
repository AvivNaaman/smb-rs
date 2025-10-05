# SMB Transport

This crate contains various smb transport implementations:
- **TCP** - Standard TCP transport, used by default.
- **NetBIOS** - NetBIOS over TCP transport, used for connecting to older SMB servers.
- **QUIC** - SMB over QUIC transport, requires the `quic` feature.
- **RDMA** - SMB over RDMA transport, requires the `rdma` feature.

> This crate is a part of the `smb-rs` project
