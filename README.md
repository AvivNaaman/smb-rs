# Pure Rust SMB Client
This project is the first full-rust implementation of a SMB client.

## Features
✅ SMB 3.1.1 dialect support.
✅ Async/Multi-threaded/Single-threaded backends.
✅ File & Directory read/write/information (basic) operations. 
✅ CLI tool for basic operations.
✅ Windows, Linux & MacOS support.

You are welcome to see the project's roadmap in the [GitHub Project](https://github.com/users/AvivNaaman/projects/2).

## Building the Project
The project supports async, multi-threaded, and single-threaded backends. The `async` backend is the default one, but you can enable the other backends by using the following features:
- `single_threaded`: Enables the single-threaded backend.
- `multi_threaded`: Enables the multi-threaded backend.

## Basic CLI Usage
The smb-cli crate implements a simple CLI for the SMB client.
- It supports copying a file from a remote SMB server to a local machine.
    ```sh
    ./smb_cli -u LocalAdmin -p 123456 copy "\\\\172.16.204.149\MyShare\ntoskrnl.exe" ./test.exe
    ```
- And querying information about a file or a directory:
    ```sh
    ./smb_cli -u LocalAdmin -p 123456 info "\\\\172.16.204.149\MyShare\ntoskrnl.exe"  # file
    ./smb_cli -u LocalAdmin -p 123456 info "\\\\172.16.204.149\MyShare"  # directory
    ```
- View additional options:
    ```sh
    ./smb_cli --help
    ```