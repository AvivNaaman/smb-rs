# About RDMA & SMB
Currently, the crate supports SMB over RDMA on Linux systems only, due to the reliance on the `async-rdma` crate, which is Linux-specific (via the usage of `libibverbs`).

## Building with RDMA support
To enable RDMA support, you need to build the crate with the `rdma` feature.
- `async-rdma` requires the installation of some libraries:
    `sudo apt install -y libibverbs1 ibverbs-utils librdmacm1 libibumad3 ibverbs-providers rdma-core libibverbs-dev iproute2 perftest build-essential net-tools git librdmacm-dev rdmacm-utils cmake libprotobuf-dev protobuf-compiler clang curl`
- When building your project, you might encounter issues with binding generation. This is usually due to old dependencies. 

## Setting up Linux RDMA server for testing
For testing purposes, you can set up a Linux RDMA server using the following steps:
1. Install [ksmbd](https://github.com/namjaejeon/ksmbd) and [ksmbd-tools](https://github.com/namjaejeon/ksmbd-tools). Don't load just yet!
    - 
2. Install RDMA libraries:
    `sudo apt install -y rdma-core libibverbs1 rdmacm-utils`
3. Load RDMA drivers and start the RDMA service:
    - Load RDMA drivers: 
    ```sh
    modprobe rdma_rxe
    modprobe ib_uverbs
    modprobe rdma_cm
    ```
    - Initialize Soft-RoCE for a certain network interface (replace `ens18` with your interface):
    ```sh
    sudo rdma link add rxe_ens18 type rxe netdev ens18
    ```
    - Make sure the RDMA interface is up:
    ```sh
    rdma link show
    ```
4. Start KSMBD
    - Start the ksmbd service:
    ```sh
    sudo modprobe ksmbd
    sudo ksmbd.mountd
    sudo ksmbd.control --debug all
    sudo ksmbd.control --reload
    ```