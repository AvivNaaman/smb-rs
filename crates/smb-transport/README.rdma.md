# About RDMA & SMB
Currently, the crate supports SMB over RDMA on Linux systems only, due to the reliance on the `async-rdma` crate, which is Linux-specific (via the usage of `libibverbs`).

## Building with RDMA support
To enable RDMA support, you need to build the crate with the `rdma` feature.
- `async-rdma` requires the installation of some libraries:
    `sudo apt install -y libibverbs1 ibverbs-utils librdmacm1 libibumad3 ibverbs-providers rdma-core libibverbs-dev iproute2 perftest build-essential net-tools git librdmacm-dev rdmacm-utils cmake libprotobuf-dev protobuf-compiler clang curl`
- When building your project, you might encounter issues with binding generation. This is usually due to old dependencies. 

## Setting up Linux RDMA server for testing
The best way to quickly setup a Linux RDMA server is to use the `ksmbd` kernel module. Below are the steps to set it up:
1. Install `ksmbd-tools` using your package manager.
2. Add software RDMA NIC. For example, if your main NIC is `ens18`, run:
   ```sh
   rdma link add rxe_ens18 type rxe netdev ens18
   ```
   Ensure the interface is up using `rdma link show` - make sure the state is `ACTIVE`.
3. Make sure to start `ksmbd` service, add user, share, and reload the configuration.