use std::sync::Arc;

use maybe_async::*;
use time::PrimitiveDateTime;

use crate::{
    connection::connection_info::ConnectionInfo,
    msg_handler::{HandlerReference, MessageHandler},
    packets::{fscc::*, smb2::*},
    tree::TreeMessageHandler,
    Error,
};

pub mod directory;
pub mod file;

pub use directory::*;
pub use file::*;

type Upstream = HandlerReference<TreeMessageHandler>;

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
}

impl Resource {
    #[maybe_async]
    pub async fn create(
        name: &str,
        upstream: &Upstream,
        create_disposition: CreateDisposition,
        desired_access: FileAccessMask,
        conn_info: &Arc<ConnectionInfo>,
        share_type: ShareType,
    ) -> crate::Result<Resource> {
        let share_access = if share_type == ShareType::Disk {
            ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true)
        } else {
            ShareAccessFlags::new()
        };

        if share_type == ShareType::Print && create_disposition != CreateDisposition::Create {
            return Err(Error::InvalidArgument(
                "Printer can only accept CreateDisposition::Create.".to_string(),
            ));
        }

        let response = upstream
            .send_recv(Content::CreateRequest(CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                desired_access,
                file_attributes: FileAttributes::new(),
                share_access,
                create_disposition,
                create_options: CreateOptions::new(),
                name: name.into(),
                contexts: vec![
                    QueryMaximalAccessRequest::default().into(),
                    QueryOnDiskIdReq.into(),
                ],
            }))
            .await?;

        let content = response.message.content.to_createresponse()?;
        log::info!("Created file '{}', ({:?})", name, content.file_id);

        let is_dir = content.file_attributes.directory();

        // Get maximal access
        let access = match CreateContextRespData::first_mxac(&content.create_contexts) {
            Some(response) => response.maximal_access,
            _ => return Err(Error::InvalidMessage("No maximal access context".into())),
        };

        // Common information is held in the handle object.
        let handle = ResourceHandle {
            name: name.to_string(),
            handler: ResourceMessageHandle::new(upstream),
            file_id: content.file_id,
            created: content.creation_time.date_time(),
            modified: content.last_write_time.date_time(),
            conn_info: conn_info.clone(),
        };

        // Construct specific resource and return it.

        if is_dir {
            Ok(Resource::Directory(Directory::new(handle, access.into())))
        } else {
            Ok(Resource::File(File::new(
                handle,
                access,
                content.endof_file,
                share_type,
            )))
        }
    }

    pub fn as_file(&self) -> Option<&File> {
        match self {
            Resource::File(f) => Some(f),
            _ => None,
        }
    }

    pub fn as_dir(&self) -> Option<&Directory> {
        match self {
            Resource::Directory(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_file(&self) -> bool {
        self.as_file().is_some()
    }

    pub fn is_dir(&self) -> bool {
        self.as_dir().is_some()
    }

    pub fn unwrap_file(self) -> File {
        match self {
            Resource::File(f) => f,
            _ => panic!("Not a file"),
        }
    }

    pub fn unwrap_dir(self) -> Directory {
        match self {
            Resource::Directory(d) => d,
            _ => panic!("Not a directory"),
        }
    }
}

/// Holds the common information for an opened SMB resource.
pub struct ResourceHandle {
    name: String,
    handler: HandlerReference<ResourceMessageHandle>,

    file_id: FileId,
    created: PrimitiveDateTime,
    modified: PrimitiveDateTime,

    conn_info: Arc<ConnectionInfo>,
}

impl ResourceHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn created(&self) -> PrimitiveDateTime {
        self.created
    }

    pub fn modified(&self) -> PrimitiveDateTime {
        self.modified
    }

    /// Close the handle.
    #[maybe_async]
    async fn close(&mut self) -> crate::Result<()> {
        if !self.is_valid() {
            return Err(Error::InvalidState("Handle is not valid".into()));
        }

        log::debug!("Closing handle for {} ({:?})", self.name, self.file_id);
        let _response = self
            .handler
            .send_recv(Content::CloseRequest(CloseRequest {
                file_id: self.file_id,
            }))
            .await?;

        self.file_id = FileId::EMPTY;
        log::info!("Closed file {}.", self.name);

        Ok(())
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.file_id != FileId::EMPTY
    }

    #[maybe_async]
    #[inline]
    pub async fn send_receive(
        &self,
        msg: Content,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.handler.send_recv(msg).await
    }

    #[cfg(feature = "async")]
    pub async fn close_async(&mut self) {
        self.close()
            .await
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

struct ResourceMessageHandle {
    upstream: Upstream,
}

impl ResourceMessageHandle {
    pub fn new(upstream: &Upstream) -> HandlerReference<ResourceMessageHandle> {
        HandlerReference::new(ResourceMessageHandle {
            upstream: upstream.clone(),
        })
    }
}

impl MessageHandler for ResourceMessageHandle {
    #[maybe_async]
    #[inline]
    async fn sendo(
        &self,
        msg: crate::msg_handler::OutgoingMessage,
    ) -> crate::Result<crate::msg_handler::SendMessageResult> {
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    #[inline]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(feature = "sync")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        self.close()
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.close_async().await;
            })
        })
    }
}
