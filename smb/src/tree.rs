use std::sync::Arc;

use maybe_async::*;

use crate::connection::connection_info::ConnectionInfo;
use crate::packets::fscc::FileAttributes;
use crate::packets::smb2::{CreateOptions, ShareFlags, ShareType};
use crate::resource::FileCreateArgs;
use crate::sync_helpers::*;

use crate::{
    Error,
    msg_handler::{HandlerReference, MessageHandler},
    packets::{
        fscc::FileAccessMask,
        smb2::{
            create::CreateDisposition,
            tree_connect::{TreeConnectRequest, TreeDisconnectRequest},
        },
    },
    resource::Resource,
    session::SessionMessageHandler,
};
mod dfs_tree;
pub use dfs_tree::*;

type Upstream = HandlerReference<SessionMessageHandler>;

#[derive(Debug, Clone)]
pub struct TreeConnectInfo {
    tree_id: u32,
    share_type: ShareType,
}

/// A tree represents a share on the server.
/// It is used to create resources (files, directories, pipes, printers) on the server.
pub struct Tree {
    handler: HandlerReference<TreeMessageHandler>,
    conn_info: Arc<ConnectionInfo>,
    dfs: bool,
}

impl Tree {
    #[maybe_async]
    pub(crate) async fn connect(
        name: &str,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
        dfs: bool,
    ) -> crate::Result<Tree> {
        // send and receive tree request & response.
        let response = upstream
            .send_recv(TreeConnectRequest::new(name).into())
            .await?;

        let content = response.message.content.to_treeconnect()?;

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

        // If encryption is required, make sure it is available.
        if content.share_flags.encrypt_data() && conn_info.config.encryption_mode.is_disabled() {
            return Err(Error::InvalidMessage(
                "Server requires encryption, but client does not support it".to_string(),
            ));
        }

        let tree_id = response
            .message
            .header
            .tree_id
            .ok_or(Error::InvalidMessage(
                "Tree ID is not set in the response".to_string(),
            ))?;

        log::info!("Connected to tree {name} (#{tree_id})");

        let tree_connect_info = TreeConnectInfo {
            tree_id,
            share_type: content.share_type,
        };

        let t = Tree {
            handler: TreeMessageHandler::new(
                upstream,
                name.to_string(),
                tree_connect_info,
                content.share_flags,
            ),
            conn_info: conn_info.clone(),
            dfs,
        };

        Ok(t)
    }

    /// Creates a resource (file, directory, pipe, or printer) on the remote server by it's name.
    /// See [Tree::create_file] and [Tree::create_directory] for an easier API.
    /// # Arguments
    /// * `file_name` - The name of the resource to create. This should NOT contain the share name, or begin with a backslash.
    /// * `args` - The arguments for the create operation. This includes the desired access, file attributes, and create options.
    ///     See [`FileCreateArgs`] for more information.
    /// # Returns
    /// * A [Resource] object representing the created resource. This can be a file, directory, pipe, or printer.
    /// # Notes
    /// This function automatically handles the following:
    /// * *DFS operations*: If the share has been opened as a DFS referral share, the create operation will modify the file name to include the DFS path.
    ///     That is, assuming it is NOT prefixed with "\\". This is rquired for a proper DFS referral file open. ("DFS normalization", MS-SMB2 2.2.13 + 3.3.5.9)
    #[maybe_async]
    pub async fn create(&self, file_name: &str, args: &FileCreateArgs) -> crate::Result<Resource> {
        let info = self
            .handler
            .connect_info
            .get()
            .ok_or(Error::InvalidState("Tree is closed".to_string()))?;

        Resource::create(
            file_name,
            &self.handler,
            args,
            &self.conn_info,
            info.share_type,
            self.dfs,
        )
        .await
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
            &FileCreateArgs {
                disposition,
                options: CreateOptions::new(),
                desired_access,
                attributes: FileAttributes::new(),
            },
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
            &FileCreateArgs {
                disposition,
                options: CreateOptions::new().with_directory_file(true),
                desired_access,
                attributes: FileAttributes::new().with_directory(true),
            },
        )
        .await
    }

    /// A wrapper around [Tree:create] that opens an existing file or directory on the remote server.
    /// See [Tree::create] for more information.
    #[maybe_async]
    pub async fn open_existing(
        &self,
        file_name: &str,
        access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(file_name, &FileCreateArgs::make_open_existing(access))
            .await
    }

    pub fn is_dfs_root(&self) -> bool {
        self.handler.share_flags.dfs_root() && self.handler.share_flags.dfs()
    }

    pub fn as_dfs_tree(&self) -> crate::Result<DfsRootTreeRef<'_>> {
        if !self.is_dfs_root() {
            return Err(Error::InvalidState("Tree is not a DFS tree".to_string()));
        }
        Ok(DfsRootTreeRef::new(self))
    }
}

pub struct TreeMessageHandler {
    upstream: Upstream,
    connect_info: OnceCell<TreeConnectInfo>,
    tree_name: String,

    share_flags: ShareFlags,
    dropping: bool,
}

impl TreeMessageHandler {
    pub fn new(
        upstream: &Upstream,
        tree_name: String,
        info: TreeConnectInfo,
        share_flags: ShareFlags,
    ) -> HandlerReference<TreeMessageHandler> {
        HandlerReference::new(TreeMessageHandler {
            upstream: upstream.clone(),
            connect_info: OnceCell::from(info),
            tree_name,
            share_flags,
            dropping: false,
        })
    }

    #[maybe_async]
    async fn disconnect(&mut self) -> crate::Result<()> {
        let info = self.connect_info.get();

        if info.is_none() {
            return Err(Error::InvalidState(
                "Tree connection already disconnected!".into(),
            ));
        }

        log::debug!("Disconnecting from tree {}", self.tree_name);

        // send and receive tree disconnect request & response.
        let _response = self
            .send_recv(TreeDisconnectRequest::default().into())
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
            .map_err(|e| {
                log::error!("Failed to disconnect from tree: {e}");
                e
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
        if self.share_flags.encrypt_data() {
            msg.encrypt = true;
        }
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        let msg = self.upstream.recvo(options).await?;

        // Make sure encryption is enforced if the share requires it.
        if !msg.form.encrypted && self.share_flags.encrypt_data() {
            return Err(Error::InvalidMessage(
                "Received unencrypted message on encrypted share".to_string(),
            ));
        }

        Ok(msg)
    }
}

#[cfg(not(feature = "async"))]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        self.disconnect()
            .map_err(|e| {
                log::error!("Failed to disconnect from tree {}: {e}", self.tree_name);
                e
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        if self.dropping {
            return;
        }

        let connect_info = match self.connect_info.get() {
            Some(info) => info.clone(),
            None => return,
        };

        let mut tree_name = String::new();
        std::mem::swap(&mut self.tree_name, &mut tree_name);

        let mut handler = TreeMessageHandler {
            connect_info: OnceCell::from(connect_info),
            tree_name,
            upstream: self.upstream.clone(),
            share_flags: self.share_flags,
            dropping: true,
        };

        tokio::task::spawn(async move {
            handler.disconnect_async().await;
        });
    }
}
