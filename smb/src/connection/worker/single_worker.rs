use std::{cell::RefCell, sync::Arc};

use crate::{
    connection::{netbios_client::NetBiosClient, transformer::Transformer},
    msg_handler::{IncomingMessage, OutgoingMessage, SendMessageResult},
};

use super::Worker;

/// Single-threaded worker.
#[derive(Debug)]
pub struct SingleWorker {
    // for trait compatibility, we need to use RefCell here,
    // since we can't have mutable references to the same object in multiple threads,
    // which is useful in the async worker.
    netbios_client: RefCell<NetBiosClient>,
    transformer: Transformer,
}

impl Worker for SingleWorker {
    fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        if !netbios_client.is_connected() {
            Err(crate::Error::NotConnected)
        } else {
            Ok(Arc::new(Self {
                netbios_client: RefCell::new(netbios_client),
                transformer: Transformer::default(),
            }))
        }
    }

    fn stop(&self) -> crate::Result<()> {
        self.netbios_client.borrow_mut().disconnect();
        Ok(())
    }

    fn send(self: &Self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let msg_id = msg.message.header.message_id;
        let finalize_preauth_hash = msg.finalize_preauth_hash;

        let t = self.transformer.transform_outgoing(msg)?;
        self.netbios_client.borrow_mut().send_raw(t)?;

        let hash = match finalize_preauth_hash {
            true => Some(self.transformer.finalize_preauth_hash()?),
            false => None,
        };

        Ok(SendMessageResult::new(msg_id, hash))
    }

    fn receive(self: &Self, msg_id: u64) -> crate::Result<IncomingMessage> {
        let msg = self.netbios_client.borrow_mut().recieve_bytes()?;
        let im = self.transformer.transform_incoming(msg)?;
        // Make sure this is our message.
        // In async clients, this is no issue, but here, we can't deal with unordered/unexpected message IDs.
        if im.message.header.message_id != msg_id {
            return Err(crate::Error::UnexpectedMessageId(
                im.message.header.message_id,
                msg_id,
            ));
        }
        Ok(im)
    }

    fn transformer(&self) -> &Transformer {
        &self.transformer
    }
}
