use std::{cell::OnceCell, error::Error};

use crate::{
    msg_handler::{SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        create::CreateDisposition,
        fscc::FileAccessMask,
        message::SMBMessageContent,
        tree_connect::{SMB2TreeConnectRequest, SMB2TreeDisconnectRequest},
    },
    smb_resource::SMBResource,
    smb_session::SMBSessionMessageHandler,
};

type Upstream = SMBHandlerReference<SMBSessionMessageHandler>;

#[derive(Debug)]
struct TreeConnectInfo {
    tree_id: u32,
}

pub struct SMBTree {
    handler: SMBHandlerReference<SMBTreeMessageHandler>,
    name: String,
}

impl SMBTree {
    pub fn new(name: String, upstream: Upstream) -> SMBTree {
        SMBTree {
            handler: SMBTreeMessageHandler::new(upstream),
            name,
        }
    }

    pub fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.handler.borrow().connect_info().is_some() {
            return Err("Tree connection already established!".into());
        }
        // send and receive tree request & response.
        let response = self
            .handler
            .send_recv(SMBMessageContent::SMBTreeConnectRequest(
                SMB2TreeConnectRequest::new(&self.name),
            ))?;

        let _response_content = match response.message.content {
            SMBMessageContent::SMBTreeConnectResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();
        log::info!(
            "Connected to tree {} (@{})",
            self.name,
            response.message.header.tree_id
        );
        self.handler
            .borrow_mut()
            .connect_info
            .set(TreeConnectInfo {
                tree_id: response.message.header.tree_id,
            })
            .unwrap();
        Ok(())
    }

    /// Connects to a resource (file, directory, etc.) on the remote server by it's name.
    pub fn create(
        &mut self,
        file_name: String,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> Result<SMBResource, Box<dyn Error>> {
        Ok(SMBResource::create(
            file_name,
            self.handler.clone(),
            disposition,
            desired_access,
        )?)
    }

    fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.handler.borrow_mut().connect_info.get().is_none() {
            // No tree connection to disconnect from.
            return Ok(());
        };

        // send and receive tree disconnect request & response.
        let _response = self
            .handler
            .send_recv(SMBMessageContent::SMBTreeDisconnectRequest(
                SMB2TreeDisconnectRequest::default(),
            ))?;

        log::info!("Disconnected from tree {}", self.name);
        self.handler.borrow_mut().connect_info.take();
        Ok(())
    }
}

impl Drop for SMBTree {
    fn drop(&mut self) {
        self.disconnect()
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.name, e);
                Err(e)
            })
            .ok();
    }
}

pub struct SMBTreeMessageHandler {
    upstream: Upstream,
    connect_info: OnceCell<TreeConnectInfo>,
}

impl SMBTreeMessageHandler {
    pub fn new(upstream: Upstream) -> SMBHandlerReference<SMBTreeMessageHandler> {
        SMBHandlerReference::new(SMBTreeMessageHandler {
            upstream,
            connect_info: OnceCell::new(),
        })
    }

    fn connect_info(&self) -> Option<&TreeConnectInfo> {
        self.connect_info.get()
    }
}

impl SMBMessageHandler for SMBTreeMessageHandler {
    fn hsendo(
        &mut self,
        mut msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        msg.message.header.tree_id = match self.connect_info.get() {
            Some(info) => info.tree_id,
            None => 0,
        };
        self.upstream.borrow_mut().hsendo(msg)
    }

    fn hrecvo(
        &mut self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().hrecvo(options)
    }
}
