# SMB RPC

This crate contains MS-RPC implementation, that is used by SMB for some operations.
Specifically, RPC is used for the NetrShareEnumAll operation, which is used to enumerate shares on the server,
but a richer implementation for Ndr64 is found in this crate, to support possible future use cases.

For now, RPC structures and functions are manually implemented - not derived from an IDL file.

> This crate is a part of the `smb-rs` project
