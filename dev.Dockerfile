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
    net-tools 

ENV RUST_BACKTRACE=1 RUST_LOG=DEBUG
