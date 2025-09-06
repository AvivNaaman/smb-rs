use std::sync::{Arc, atomic::AtomicBool};

use maybe_async::*;
use smb_dtyp::SecurityDescriptor;
use smb_fscc::*;
use smb_msg::*;
use time::PrimitiveDateTime;

use crate::{
    Error,
    connection::connection_info::ConnectionInfo,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
    },
    tree::TreeMessageHandler,
};

pub mod directory;
pub mod file;
pub mod file_util;
pub mod pipe;

pub use directory::*;
pub use file::*;
pub use file_util::*;
pub use pipe::*;

type Upstream = HandlerReference<TreeMessageHandler>;

#[derive(Default)]
pub struct FileCreateArgs {
    pub disposition: CreateDisposition,
    pub attributes: FileAttributes,
    pub options: CreateOptions,
    pub desired_access: FileAccessMask,
}

impl FileCreateArgs {
    pub fn make_open_existing(access: FileAccessMask) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Open,
            attributes: FileAttributes::new(),
            options: CreateOptions::new(),
            desired_access: access,
        }
    }

    /// Returns arguments for creating a new file,
    /// with the default access set to Generic All.
    pub fn make_create_new(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Create,
            attributes,
            options,
            desired_access: FileAccessMask::new().with_generic_all(true),
        }
    }

    /// Returns arguments for creating a new file,
    /// with the default access set to Generic All.
    /// overwrites existing file, if it exists.
    pub fn make_overwrite(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::OverwriteIf,
            attributes,
            options,
            desired_access: FileAccessMask::new().with_generic_all(true),
        }
    }

    /// Returns arguments for opening a duplex pipe (rw).
    pub fn make_pipe() -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Open,
            attributes: Default::default(),
            options: Default::default(),
            desired_access: FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true),
        }
    }
}

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
    Pipe(Pipe),
}

impl Resource {
    #[maybe_async]
    pub(crate) async fn create(
        name: &str,
        upstream: &Upstream,
        create_args: &FileCreateArgs,
        conn_info: &Arc<ConnectionInfo>,
        share_type: ShareType,
        is_dfs: bool,
    ) -> crate::Result<Resource> {
        let share_access = if share_type == ShareType::Disk {
            ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true)
        } else {
            ShareAccessFlags::new()
        };

        if share_type == ShareType::Print && create_args.disposition != CreateDisposition::Create {
            return Err(Error::InvalidArgument(
                "Printer can only accept CreateDisposition::Create.".to_string(),
            ));
        }

        if name.starts_with("\\") {
            return Err(Error::InvalidArgument(
                "Resource name cannot start with a backslash.".to_string(),
            ));
        }

        let mut msg = OutgoingMessage::new(
            CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                desired_access: create_args.desired_access,
                file_attributes: create_args.attributes,
                share_access,
                create_disposition: create_args.disposition,
                create_options: create_args.options,
                name: name.into(),
                contexts: vec![
                    QueryMaximalAccessRequest::default().into(),
                    QueryOnDiskIdReq.into(),
                ],
            }
            .into(),
        );
        // Make sure to set DFS if required.
        msg.message.header.flags.set_dfs_operation(is_dfs);

        let response = upstream
            .sendo_recvo(msg, ReceiveOptions::new().with_allow_async(true))
            .await?;

        let response = response.message.content.to_create()?;
        log::debug!("Created file '{}', ({:?})", name, response.file_id);

        let is_dir = response.file_attributes.directory();

        // Get maximal access
        let access = match CreateContextRespData::first_mxac(&response.create_contexts) {
            Some(response) => response.maximal_access,
            _ => {
                log::debug!(
                    "No maximal access context found for file '{name}', using default (full access)."
                );
                FileAccessMask::from_bytes(u32::MAX.to_be_bytes())
            }
        };

        // Common information is held in the handle object.
        let handle = ResourceHandle {
            name: name.to_string(),
            handler: ResourceMessageHandle::new(upstream),
            open: AtomicBool::new(true),
            _file_id: response.file_id,
            created: response.creation_time.date_time(),
            modified: response.last_write_time.date_time(),
            access,
            share_type,
            conn_info: conn_info.clone(),
        };

        // Construct specific resource and return it.

        let resource = if is_dir {
            Resource::Directory(Directory::new(handle))
        } else {
            match share_type {
                ShareType::Disk => Resource::File(File::new(handle, response.endof_file)),
                ShareType::Pipe => Resource::Pipe(Pipe::new(handle)),
                ShareType::Print => unimplemented!("Printer resources are not yet implemented"),
            }
        };
        Ok(resource)
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

impl TryInto<File> for Resource {
    type Error = crate::Error;

    fn try_into(self) -> Result<File, Self::Error> {
        match self {
            Resource::File(f) => Ok(f),
            _ => Err(Error::InvalidArgument("Not a file".into())),
        }
    }
}

impl TryInto<Directory> for Resource {
    type Error = crate::Error;

    fn try_into(self) -> Result<Directory, Self::Error> {
        match self {
            Resource::Directory(d) => Ok(d),
            _ => Err(Error::InvalidArgument("Not a directory".into())),
        }
    }
}

/// Holds the common information for an opened SMB resource.
pub struct ResourceHandle {
    name: String,
    handler: HandlerReference<ResourceMessageHandle>,

    // Whether the resource is open or not.
    // TODO: Consider using RwLock here on FileId instead of AtomicBool+FileId.
    open: AtomicBool,

    // Avoid accessing directly; use the `file_id()` getter,
    // that makes sure the resource is still open.
    _file_id: FileId,
    created: PrimitiveDateTime,
    modified: PrimitiveDateTime,
    share_type: ShareType,

    access: FileAccessMask,

    conn_info: Arc<ConnectionInfo>,
}

impl ResourceHandle {
    /// Returns the name of the resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the creation time of the resource.
    pub fn created(&self) -> PrimitiveDateTime {
        self.created
    }

    /// Returns the last modified time of the resource.
    pub fn modified(&self) -> PrimitiveDateTime {
        self.modified
    }

    /// Returns the current share type of the resource. See [ShareType] for more details.
    pub fn share_type(&self) -> ShareType {
        self.share_type
    }

    /// Returns the handle of the resource.
    // This is implemented to be "inhrited" by Deref impl of resources impls, to avoid boilerplate code.
    pub fn handle(&self) -> &ResourceHandle {
        self
    }

    /// (Internal)
    ///
    /// Returns the file ID of the resource, ensuring the resource is still open.
    fn file_id(&self) -> crate::Result<FileId> {
        // The current design here allows the race condition over a close after this validation occurs.
        // therefore, this atomic load can be relaxed, and actual atomic compare and exchange are used
        // to avoid double close somehow.
        if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is closed".into()));
        }
        Ok(self._file_id)
    }

    /// (Internal)
    ///
    /// Sends a Query Information Request and parses the response.
    #[maybe_async]
    async fn query_common(&self, req: QueryInfoRequest) -> crate::Result<QueryInfoData> {
        let info_type = req.info_type;
        Ok(self
            .send_receive(req.into())
            .await?
            .message
            .content
            .to_queryinfo()?
            .parse(info_type)?)
    }

    /// (Internal)
    ///
    /// Sends a Set Information Request and parses the response.
    #[maybe_async]
    async fn set_info_common<T>(
        &self,
        data: T,
        cls: SetInfoClass,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()>
    where
        T: Into<SetInfoData>,
    {
        let data = data.into().to_req(cls, self.file_id()?, additional_info);
        let response = self.send_receive(data.into()).await?;
        response.message.content.to_setinfo()?;
        Ok(())
    }

    /// Queries the file for information.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    /// # Notes
    /// * use [`ResourceHandle::query_full_ea_info`] to query extended attributes information.
    #[maybe_async]
    pub async fn query_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileInfoValue,
    {
        let flags = QueryInfoFlags::new()
            .with_restart_scan(true)
            .with_return_single_entry(true);

        self.query_info_with_options::<T>(flags, 1024).await
    }

    /// Queries the file for extended attributes information.
    /// # Arguments
    /// * `names` - A list of extended attribute names to query.
    /// # Returns
    /// A `Result` containing the requested information, of type [QueryFileFullEaInformation].
    /// See [`ResourceHandle::query_info`] for more information.
    #[maybe_async]
    pub async fn query_full_ea_info(
        &self,
        names: Vec<&str>,
    ) -> crate::Result<QueryFileFullEaInformation> {
        let result = self
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.file_id()?,
                data: GetInfoRequestData::EaInfo(GetEaInfoList {
                    values: names
                        .iter()
                        .map(|&s| FileGetEaInformationInner { ea_name: s.into() }.into())
                        .collect(),
                }),
            })
            .await?
            .as_file()?
            .parse(QueryFileInfoClass::FullEaInformation)?
            .try_into()?;
        Ok(result)
    }

    /// Queries the file for information with additional arguments.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Arguments
    /// * `flags` - The [QueryInfoFlags] for the query request.
    /// * `output_buffer_length` - The maximum output buffer to use.
    /// # Returns
    /// A `Result` containing the requested information.
    /// # Notes
    /// * use [ResourceHandle::query_full_ea_info] to query extended attributes information.
    #[maybe_async]
    pub async fn query_info_with_options<T: QueryFileInfoValue>(
        &self,
        flags: QueryInfoFlags,
        output_buffer_length: usize,
    ) -> crate::Result<T> {
        let result: T = self
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(T::CLASS_ID),
                output_buffer_length: output_buffer_length as u32,
                additional_info: AdditionalInfo::new(),
                flags,
                file_id: self.file_id()?,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .as_file()?
            .parse(T::CLASS_ID)?
            .try_into()?;
        Ok(result)
    }

    /// Queries the file for it's security descriptor.
    /// # Arguments
    /// * `additional_info` - The information to request on the security descriptor.
    /// # Returns
    /// A `Result` containing the requested information, of type [SecurityDescriptor].
    #[maybe_async]
    pub async fn query_security_info(
        &self,
        additional_info: AdditionalInfo,
    ) -> crate::Result<SecurityDescriptor> {
        Ok(self
            .query_common(QueryInfoRequest {
                info_type: InfoType::Security,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_info,
                flags: QueryInfoFlags::new(),
                file_id: self.file_id()?,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .unwrap_security())
    }

    /// Sends an FSCTL message for the current resource (file).
    /// # Type Parameters
    /// * `T` - The type of the request to send. Must implement the [`FsctlRequest`] trait.
    /// # Arguments
    /// * `request` - The request to send, which has an associated FSCTL code and data.
    /// # Returns
    /// A `Result` containing the requested information, as bound to [`FsctlRequest::Response`].
    #[maybe_async]
    pub async fn fsctl<T: FsctlRequest>(&self, request: T) -> crate::Result<T::Response> {
        const DEFAULT_RESPONSE_OUT_SIZE: u32 = 1024;
        self.fsctl_with_options(request, DEFAULT_RESPONSE_OUT_SIZE)
            .await
    }

    /// Sends an FSCTL message for the current resource (file) with additional options.
    /// # Type Parameters
    /// * `T` - The type of the request to send. Must implement the [`FsctlRequest`] trait.
    /// # Arguments
    /// * `request` - The request to send, which has an associated FSCTL code and data.
    /// * `max_input_response` - The maximum input response size.
    /// * `max_output_response` - The maximum output response size.
    /// # Returns
    /// A `Result` containing the requested information, as bound to [`FsctlRequest::Response`].
    #[maybe_async]
    pub async fn fsctl_with_options<T: FsctlRequest>(
        &self,
        request: T,
        max_output_response: u32,
    ) -> crate::Result<T::Response> {
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let ioctl_result = self
            ._ioctl(
                T::FSCTL_CODE as u32,
                request.into(),
                NO_INPUT_IN_RESPONSE,
                max_output_response,
                IoctlRequestFlags::new().with_is_fsctl(true),
            )
            .await?
            .parse_fsctl::<T::Response>()?;
        Ok(ioctl_result)
    }

    /// Sends an IOCTL message for the current resource (file).
    /// # Arguments
    /// * `ctl_code` - The control code for the IOCTL request.
    /// * `request` - The request data to send.
    /// * `max_output_response` - The maximum output response size.
    /// # Returns
    /// A `Result` containing the response data as a vector of bytes.
    #[maybe_async]
    pub async fn ioctl(
        &self,
        ctl_code: u32,
        request: Vec<u8>,
        max_output_response: u32,
    ) -> crate::Result<Vec<u8>> {
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let response = self
            ._ioctl(
                ctl_code,
                IoctlReqData::Ioctl(request.into()),
                NO_INPUT_IN_RESPONSE,
                max_output_response,
                IoctlRequestFlags::new(),
            )
            .await?;
        Ok(response.out_buffer)
    }

    /// (Internal)
    #[maybe_async]
    async fn _ioctl(
        &self,
        ctl_code: u32,
        req_data: IoctlReqData,
        max_in: u32,
        max_out: u32,
        flags: IoctlRequestFlags,
    ) -> crate::Result<IoctlResponse> {
        let result = self
            .handler
            .send_recvo(
                RequestContent::Ioctl(IoctlRequest {
                    ctl_code,
                    file_id: self.file_id()?,
                    max_input_response: max_in,
                    max_output_response: max_out,
                    flags,
                    buffer: req_data,
                }),
                ReceiveOptions::new().with_allow_async(true),
            )
            .await?
            .message
            .content
            .to_ioctl()?;
        Ok(result)
    }

    /// Queries the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileSystemInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    #[maybe_async]
    pub async fn query_fs_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }
        let query_result: T = self
            .query_common(QueryInfoRequest {
                info_type: InfoType::FileSystem,
                info_class: QueryInfoClass::FileSystem(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.file_id()?,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .unwrap_filesystem()
            .parse(T::CLASS_ID)?
            .try_into()?;
        Ok(query_result)
    }

    /// Sets the file information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileInfoValue] trait.
    #[maybe_async]
    pub async fn set_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileInfoValue,
    {
        self.set_info_common(
            RawSetInfoData::from(info.into()),
            T::CLASS_ID.into(),
            Default::default(),
        )
        .await
    }

    /// Sets the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileSystemInfoValue] trait.
    #[maybe_async]
    pub async fn set_filesystem_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }

        self.set_info_common(
            RawSetInfoData::from(info.into()),
            T::CLASS_ID.into(),
            Default::default(),
        )
        .await
    }

    /// Sets the file system information for the current file.
    /// # Arguments
    /// * `info` - The information to set - a [SecurityDescriptor].
    /// * `additional_info` - The information that is set on the security descriptor.
    #[maybe_async]
    pub async fn set_security_info(
        &self,
        info: SecurityDescriptor,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()> {
        self.set_info_common(
            info,
            SetInfoClass::Security(Default::default()),
            additional_info,
        )
        .await
    }

    /// (Internal)
    ///
    /// Sends a close request to the server for the given file ID.
    /// This should be called properly after taking out the file id (handle) from the resource instance,
    /// to avoid Use-after-free errors.
    #[maybe_async]
    async fn send_close(
        file_id: FileId,
        handler: &HandlerReference<ResourceMessageHandle>,
    ) -> crate::Result<()> {
        log::trace!("Send close to file with ID: {file_id:?}");
        let response = handler.send_recv(CloseRequest { file_id }.into()).await?;
        log::debug!("Close response received for file ID: {file_id:?}, {response:?}");
        Ok(())
    }

    /// Closes the resource.
    /// The resource may not be used after calling this method.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    #[maybe_async]
    pub async fn close(&self) -> crate::Result<()> {
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is already closed".into()));
        }

        log::debug!("Closing handle for {} ({:?})", self.name, self._file_id);
        Self::send_close(self._file_id, &self.handler).await?;

        log::debug!("Closed file {}.", self.name);

        Ok(())
    }

    #[maybe_async]
    #[inline]
    async fn send_receive(
        &self,
        msg: RequestContent,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.handler.send_recv(msg).await
    }

    #[maybe_async]
    async fn send_recvo(
        &self,
        msg: RequestContent,
        options: ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        self.handler
            .sendo_recvo(OutgoingMessage::new(msg), options)
            .await
    }

    /// Returns whether current resource is opened from the same tree as the other resource.
    /// This is useful to check if two resources are opened from the same share instance.
    ///
    /// # Note
    /// * Even if a resource is positioned in the same tree, if the tree was accessed using different
    ///   share connections, this will return false!
    pub fn same_tree(&self, other: &Self) -> bool {
        Arc::ptr_eq(
            &self.handler.upstream.handler,
            &other.handler.upstream.handler,
        )
    }
}

struct ResourceMessageHandle {
    upstream: Upstream,
}

impl ResourceMessageHandle {
    fn new(upstream: &Upstream) -> HandlerReference<ResourceMessageHandle> {
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
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(not(feature = "async"))]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        let file_id = self.file_id();
        if file_id.is_err() {
            return;
        }

        log::warn!(
            "ResourceHandle for '{}' ({}) is being dropped without closing it properly. This may lead to resource leaks.",
            self.name,
            self._file_id
        );
    }
}

#[cfg(feature = "async")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // already closed, no problem
            return;
        }

        let file_id = self._file_id;
        let handler = self.handler.clone();
        log::debug!("Spawning task to close file with ID: {file_id:?}");
        tokio::task::spawn(async move {
            if file_id != FileId::EMPTY {
                if let Err(e) = Self::send_close(file_id, &handler).await {
                    log::error!("Error closing file: {e}");
                }
            }
        });
    }
}
