# smb-rs: The SMB2 Client in Rust

[![Build](https://github.com/AvivNaaman/smb-rs/actions/workflows/build.yml/badge.svg)](https://github.com/AvivNaaman/smb-rs/actions/workflows/build.yml)
[![Crates.io](https://img.shields.io/crates/v/smb)](https://crates.io/crates/smb)
[![docs.rs](https://img.shields.io/docsrs/smb/latest?link=https%3A%2F%2Fdocs.rs%2Fsmb%2Flatest%2Fsmb%2Findex.html)](https://docs.rs/smb/latest/smb/index.html)

This project is the first rust implementation of [SMB2 & 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) client -- the protocol that powers Windows file sharing and remote services. The project is designed to be used as a crate, but also includes a CLI tool for basic operations.

While most current implementations are mostly bindings to C libraries (such as libsmb2, samba, or windows' own libraries), this project is a full implementation in Rust, with no dependencies on C libraries!

## Getting started
Running the project is as simple as:
```sh
cargo run -- --help
```
Check out the `info` and the `copy` sub-commands for more information.

For advanced usage, and crate usage, see the [Advanced Usage](#advanced-usage) section.
## Features
### General
- ✅ SMB 2.X & 3.X support.
- ✅ Async (`tokio`), Multi-threaded, or Single-threaded client.
- ✅ Compression & Encryption support.
- ✅ Transport using SMB over TCP (445), over NetBIOS (139), and over QUIC (443).
- ✅ NTLM & Kerberos authentication (using the [`sspi`](https://crates.io/crates/sspi) crate).
- ✅ Cross-platform (Windows, Linux, MacOS).

You are welcome to see the project's roadmap in the [GitHub Project](https://github.com/users/AvivNaaman/projects/2).

### Feature Flags
| Type            | Algorithm           |     | Feature Name           |
| --------------- | ------------------- | --- | ---------------------- |
| Authentication  | Kerberos            | ✅   | `kerberos`             |
| Transport       | QUIC                | ✅   | `quic`                 |
| **Signing**     | *                   |     | `sign`                 |
| Signing         | HMAC_SHA256         | ✅   | `sign_hmac`            |
| Signing         | AES-128-GCM         | ✅   | `sign_gmac`            |
| Signing         | AES-128-CCM         | ✅   | `sign_cmac`            |
| **Encryption**  | *                   |     | `encrypt`              |
| Encryption      | AES-128-CCM         | ✅   | `encrypt_aes128ccm`    |
| Encryption      | AES-128-GCM         | ✅   | `encrypt_aes128gcm`    |
| Encryption      | AES-256-CCM         | ✅   | `encrypt_aes256ccm`    |
| Encryption      | AES-256-GCM         | ✅   | `encrypt_aes256gcm`    |
| **Compression** | *                   |     | `compress`             |
| Compression     | LZ4                 | ✅   | `compress_lz4`         |
| Compression     | Pattern_V1          | 🟡   | `compress_pattern_v1`* |
| Compression     | LZNT1/LZ77/+Huffman | ❌   | -                      |

> [!NOTE] 
> Some of SMB's suported compression algorithms are missing, since no proper crates are available for them.

## Advanced Usage
### Using the crate
Check out the `Client` struct, exported from the `smb` crate, to initiate a connection to an SMB server:
```rust
let unc_path = smb::UncPath::from_str(r"\\server\share\\file.txt")?;
let smb = smb::Client::new(smb::ClientConfig::default());
smb.share_connect(&unc_path, "username", "password".to_string()).await?;
```

Opening a file for reading:
```rust
let mut file: smb::File = smb.create_file(&unc_path, 
    &FileCreateArgs::make_open_existing(
        FileAccessMask::new().with_generic_read(true),
)).await.try_into()?;

// .. do some things with the file

file.close().await?; // don't forget to close it!
```

>[!tip]
> Check out `smb-cli`'s commands implementation for more examples of how to use the crate.

### Switch Threading model
The project supports async, multi-threaded, and single-threaded backends. The `async` backend is the default one, but you can enable the other backends by using the following features:
- `async`: Enables the async backend (default)
- `single_threaded`: Enables the single-threaded backend. *Must disable default features.*
- `multi_threaded`: Enables the multi-threaded backend. *Must disable default features.*

For example, to run the CLI using multi-threaded backend, you can run:
```sh
cargo run --no-default-feature --features "multi_threaded,sign,encrypt,compress" -- --help
```
If you're using the crate, you can enable the features in your `Cargo.toml` file:
```toml
[dependencies]
smb = { version = "0.1", features = ["multi_threaded", "sign", "..."], no-default-features = true }
```

## Development
To set up a development environment, you may use any supported rust version.

It is highly recommended to use rust nightly, and install pre-commit hooks (using `pip install pre-commit && pre-commit install`)