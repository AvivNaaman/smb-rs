FROM rustlang/rust:nightly

RUN apt update && \
    apt install -y \
    build-essential \
    cmake \
    git \
    clang \
    lld \
    iputils-ping \
    tcpdump \
    neovim \
    net-tools \
    # RDMA
    libibverbs1 ibverbs-utils librdmacm1 libibumad3 ibverbs-providers rdma-core libibverbs-dev iproute2 perftest librdmacm-dev rdmacm-utils libprotobuf-dev protobuf-compiler clang curl

ENV RUST_BACKTRACE=1 RUST_LOG=DEBUG
