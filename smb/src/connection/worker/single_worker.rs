use std::{
    cell::{OnceCell, RefCell},
    sync::Arc,
    time::Duration,
};

use crate::{
    connection::{transformer::Transformer, transport::SmbTransport},
    msg_handler::{IncomingMessage, OutgoingMessage, ReceiveOptions, SendMessageResult},
};

use super::Worker;

/// Single-threaded worker.
pub struct SingleWorker {
    // for trait compatibility, we need to use RefCell here,
    // since we can't have mutable references to the same object in multiple threads,
    // which is useful in the async worker.
    transport: RefCell<OnceCell<Box<dyn SmbTransport>>>,
    transformer: Transformer,
    timeout: RefCell<Option<Duration>>,
}

impl Worker for SingleWorker {
    fn start(transport: Box<dyn SmbTransport>, timeout: Duration) -> crate::Result<Arc<Self>> {
        transport.set_read_timeout(timeout)?;
        Ok(Arc::new(Self {
            transport: RefCell::new(OnceCell::from(transport)),
            transformer: Transformer::default(),
            timeout: RefCell::new(Some(timeout)),
        }))
    }

    fn stop(&self) -> crate::Result<()> {
        self.transport
            .borrow_mut()
            .take()
            .ok_or(crate::Error::NotConnected)?;
        Ok(())
    }

    fn send(&self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let msg_id = msg.message.header.message_id;
        let finalize_preauth_hash = msg.finalize_preauth_hash;

        let msg_to_send = self.transformer.transform_outgoing(msg)?;

        let mut t = self.transport.borrow_mut();
        t.get_mut()
            .ok_or(crate::Error::NotConnected)?
            .send(msg_to_send.as_ref())?;

        let hash = match finalize_preauth_hash {
            true => self.transformer.finalize_preauth_hash()?,
            false => None,
        };

        Ok(SendMessageResult::new(msg_id, hash))
    }

    fn receive_next(&self, options: &ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        // Receive next message
        let mut self_mut = self.transport.borrow_mut();
        let transport = self_mut.get_mut().ok_or(crate::Error::NotConnected)?;
        let msg = transport.receive().map_err(|e| match e {
            crate::Error::IoError(ioe) => {
                if ioe.kind() == std::io::ErrorKind::WouldBlock {
                    crate::Error::OperationTimeout(
                        "Receive next message".into(),
                        self.timeout.borrow().unwrap_or(Duration::ZERO),
                    )
                } else {
                    crate::Error::IoError(ioe)
                }
            }
            _ => e,
        })?;
        // Transform the message
        let im = self.transformer.transform_incoming(msg)?;
        // Make sure this is our message.
        // In async clients, this is no issue, but here, we can't deal with unordered/unexpected message IDs.
        if im.message.header.message_id != options.msg_id {
            return Err(crate::Error::UnexpectedMessageId(
                im.message.header.message_id,
                options.msg_id,
            ));
        }
        Ok(im)
    }

    fn transformer(&self) -> &Transformer {
        &self.transformer
    }

    fn set_timeout(&self, timeout: Duration) -> crate::Result<()> {
        self.transport
            .borrow()
            .get()
            .ok_or(crate::Error::NotConnected)?
            .set_read_timeout(timeout)?;
        self.timeout.replace(Some(timeout));
        Ok(())
    }
}

impl std::fmt::Debug for SingleWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleWorker")
            .field("timeout", &self.timeout)
            .finish()
    }
}
