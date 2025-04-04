use std::sync::Arc;

use maybe_async::*;

use crate::connection::connection_info::ConnectionInfo;
use crate::packets::fscc::FileAttributes;
use crate::packets::smb2::{CreateOptions, ShareType};
use crate::sync_helpers::*;

use crate::{
    msg_handler::{HandlerReference, MessageHandler},
    packets::{
        fscc::FileAccessMask,
        smb2::{
            create::CreateDisposition,
            plain::Content,
            tree_connect::{TreeConnectRequest, TreeDisconnectRequest},
        },
    },
    resource::Resource,
    session::SessionMessageHandler,
    Error,
};

type Upstream = HandlerReference<SessionMessageHandler>;

#[derive(Debug)]
pub struct TreeConnectInfo {
    tree_id: u32,
    share_type: ShareType,
}

/// A tree represents a share on the server.
/// It is used to create resources (files, directories, pipes, printers) on the server.
pub struct Tree {
    handler: HandlerReference<TreeMessageHandler>,
    conn_info: Arc<ConnectionInfo>,
}

impl Tree {
    #[maybe_async]
    pub async fn connect(
        name: &str,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Tree> {
        // send and receive tree request & response.
        let response = upstream
            .send_recv(Content::TreeConnectRequest(TreeConnectRequest::new(name)))
            .await?;

        let content = response.message.content.to_treeconnectresponse()?;

        // Make sure the share flags from the server are valid to the dialect.
        if ((!u32::from_le_bytes(conn_info.dialect.get_tree_connect_caps_mask().into_bytes()))
            & u32::from_le_bytes(content.capabilities.into_bytes()))
            != 0
        {
            return Err(Error::InvalidMessage(format!(
                "Invalid share flags received from server for tree '{}': {:?}",
                name, content.share_flags
            )));
        }

        // Same for share flags
        if ((!u32::from_le_bytes(conn_info.dialect.get_share_flags_mask().into_bytes()))
            & u32::from_le_bytes(content.share_flags.into_bytes()))
            != 0
        {
            return Err(Error::InvalidMessage(format!(
                "Invalid capabilities received from server for tree '{}': {:?}",
                name, content.capabilities
            )));
        }

        let tree_id = response
            .message
            .header
            .tree_id
            .ok_or(Error::InvalidMessage(
                "Tree ID is not set in the response".to_string(),
            ))?;

        log::info!("Connected to tree {} (#{})", name, tree_id);

        let tree_connect_info = TreeConnectInfo {
            tree_id: tree_id,
            share_type: content.share_type,
        };

        let t = Tree {
            handler: TreeMessageHandler::new(upstream, name.to_string(), tree_connect_info),
            conn_info: conn_info.clone(),
        };

        Ok(t)
    }

    /// Creates a resource (file, directory, pipe, or printer) on the remote server by it's name.
    /// See [Tree::create_file] and [Tree::create_directory] for an easier API.
    /// # Arguments
    /// * `file_name` - The name of the resource to create. This should NOT contain the share name, or begin with a backslash.
    /// * `disposition` - The disposition of the resource. This determines how the resource is created or opened. See [CreateDisposition] for more information.
    /// * `desired_access` - The access mask for the resource. This determines what operations are allowed on the resource. See [FileAccessMask] for more information.
    /// * `attributes` - The attributes of the resource. This determines how the resource is created. See [FileAttributes] for more information.
    /// * `options` - The options for the resource. This determines how the resource is created. See [CreateOptions] for more information.
    /// # Returns
    /// * A [Resource] object representing the created resource. This can be a file, directory, pipe, or printer.
    #[maybe_async]
    pub async fn create(
        &self,
        file_name: &str,
        disposition: CreateDisposition,
        options: CreateOptions,
        desired_access: FileAccessMask,
        attributes: FileAttributes,
    ) -> crate::Result<Resource> {
        let info = self
            .handler
            .connect_info
            .get()
            .ok_or(Error::InvalidState("Tree is closed".to_string()))?;

        Ok(Resource::create(
            file_name,
            &self.handler,
            disposition,
            attributes,
            options,
            desired_access,
            &self.conn_info,
            info.share_type,
        )
        .await?)
    }

    /// A wrapper around [Tree::create] that creates a file on the remote server.
    /// See [Tree::create] for more information.
    #[maybe_async]
    pub async fn create_file(
        &self,
        file_name: &str,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(
            file_name,
            disposition,
            CreateOptions::new(),
            desired_access,
            FileAttributes::new(),
        )
        .await
    }

    /// A wrapper around [Tree::create] that creates a directory on the remote server.
    /// See [Tree::create] for more information.
    #[maybe_async]
    pub async fn create_directory(
        &self,
        dir_name: &str,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(
            dir_name,
            disposition,
            CreateOptions::new().with_directory_file(true),
            desired_access.with_generic_read(true),
            FileAttributes::new().with_directory(true),
        )
        .await
    }

    /// A wrapper around [Tree:create] that opens an existing file or directory on the remote server.
    /// See [Tree::create] for more information.
    #[maybe_async]
    pub async fn open_existing(
        &self,
        file_name: &str,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(
            file_name,
            CreateDisposition::Open,
            Default::default(),
            desired_access.with_generic_read(true),
            Default::default(),
        )
        .await
    }
}

pub struct TreeMessageHandler {
    upstream: Upstream,
    connect_info: OnceCell<TreeConnectInfo>,
    tree_name: String,
}

impl TreeMessageHandler {
    pub fn new(
        upstream: &Upstream,
        tree_name: String,
        info: TreeConnectInfo,
    ) -> HandlerReference<TreeMessageHandler> {
        HandlerReference::new(TreeMessageHandler {
            upstream: upstream.clone(),
            connect_info: OnceCell::from(info),
            tree_name,
        })
    }

    #[maybe_async]
    async fn disconnect(&mut self) -> crate::Result<()> {
        let info = self.connect_info.get();

        if !info.is_some() {
            return Err(Error::InvalidState(
                "Tree connection already disconnected!".into(),
            ));
        }

        log::debug!("Disconnecting from tree {}", self.tree_name);

        // send and receive tree disconnect request & response.
        let _response = self
            .send_recv(Content::TreeDisconnectRequest(
                TreeDisconnectRequest::default(),
            ))
            .await?;

        self.connect_info.take();
        log::info!("Disconnected from tree {}", self.tree_name);

        Ok(())
    }

    #[cfg(feature = "async")]
    #[inline]
    pub async fn disconnect_async(&mut self) {
        self.disconnect()
            .await
            .or_else(|e| {
                log::error!("Failed to disconnect from tree: {}", e);
                Err(e)
            })
            .ok();
    }
}

impl MessageHandler for TreeMessageHandler {
    #[maybe_async]
    async fn sendo(
        &self,
        mut msg: crate::msg_handler::OutgoingMessage,
    ) -> crate::Result<crate::msg_handler::SendMessageResult> {
        msg.message.header.tree_id = match self.connect_info.get() {
            Some(info) => info.tree_id,
            None => 0,
        }
        .into();
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(feature = "sync")]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        self.disconnect()
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.tree_name, e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.disconnect_async().await;
            })
        })
    }
}
