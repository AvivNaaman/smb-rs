# SMB Messages

This crate contains SMB-specific messages and structures,
that are used by the SMB protocol.

Mostly, it contains SMB messages (like SMB2 Headers, SMB2 Requests & Responses, etc.).
It also contains additional structures that are used by SMB specifically
(for example, DFS referrals), but common structures (such as GUID) are found in the `smb-types` crate.

> This crate is a part of the `smb-rs` project
