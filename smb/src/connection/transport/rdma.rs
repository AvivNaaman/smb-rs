#![cfg(feature = "rdma")]

use std::net::{Ipv4Addr, SocketAddrV4};

use async_rdma::{Rdma, RdmaBuilder};

use crate::connection::transport::{SmbTransport, SmbTransportRead};

pub struct RdmaTransport {
    rdma: Rdma,
}

impl RdmaTransport {
    pub async fn new() -> crate::Result<Self> {
        let rdma = RdmaBuilder::default()
            .connect(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 445))
            .await?;
        // rdma.send(lm)
        Ok(Self { rdma })
    }
}
