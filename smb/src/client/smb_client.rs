use crate::{
    Connection, Error, FileCreateArgs, Resource, Session, Tree,
    packets::{
        dfsc::{ReferralEntry, ReferralEntryValue},
        rpc::interface::{ShareInfo1, SrvSvc},
        smb2::Status,
    },
    resource::Pipe,
    sync_helpers::*,
};
use maybe_async::maybe_async;
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};

use super::{config::ClientConfig, unc_path::UncPath};

/// This struct represents a high-level SMB client, and it is highly encouraged to use it
/// for interacting with SMB servers, instead of manually creating connections.
///
/// ## General usage
/// When connecting to a new share, even if it's on the same server,
/// you must always connect to the share using [`Client::share_connect`].
///
/// ## Drop behavior
/// When the client drops, the held connections are not forcibly closed, but rather
/// kept alive until all their references are dropped.
/// For example, if a file is opened from the client, and the client is dropped,
/// the connection, session and tree of the opened file, will still be alive, but you will not be able
/// to use the client to interact with them.
///
/// To force a closure of all connections and their managed resources,
/// use the [`Client::close`] method.
///
/// ## Example
///
/// ```no_run
/// use smb::{Client, ClientConfig, UncPath, FileCreateArgs, FileAccessMask};
/// use std::str::FromStr;
/// # #[cfg(not(feature = "async"))] fn main() {}
/// #[cfg(feature = "async")]
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // instantiate the client
///     let client = Client::new(ClientConfig::default());
///     
///     // Connect to a share
///     let target_path = UncPath::from_str(r"\\server\share").unwrap();
///     client.share_connect(&target_path, "username", "password".to_string()).await?;
///     
///     // And open a file on the server
///     let file_to_open = target_path.with_path("file.txt".to_string());
///     let file_open_args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));
///     let file = client.create_file(&file_to_open, &file_open_args).await?;
///     // now, you can do a bunch of operations against `file`, and close it at the end.
///     Ok(())
/// }
/// ```
pub struct Client {
    config: ClientConfig,
    /// Server Name => [`ClientConnectionInfo`]
    connections: Mutex<HashMap<String, ClientConnectionInfo>>,
}

/// (Internal)
///
/// Holds information for a connection, held by the client.
/// This is most useful to avoid creating multiple connections to the same server,
struct ClientConnectionInfo {
    connection: Arc<Connection>,
    share_connects: HashMap<UncPath, ClientConectedTree>,
}

struct ClientConectedTree {
    session: Arc<Session>,
    tree: Arc<Tree>,
    credentials: Option<(String, String)>,
}

impl Client {
    /// Creates a new `Client` instance with the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Shuts down the client, and all its managed connections.
    ///
    /// Any resource held by the client will not be accessible after calling this method,
    /// directly or indirectly.
    ///
    /// See [Drop behavior][Client#drop-behavior] for more information.
    #[maybe_async]
    pub async fn close(&self) -> crate::Result<()> {
        let mut connections = self.connections.lock().await?;
        for (_unc, conn) in connections.iter() {
            conn.connection.close().await?;
        }
        connections.clear();

        Ok(())
    }

    /// Lists all shares on the specified server.
    #[maybe_async]
    pub async fn list_shares(&self, server: &str) -> crate::Result<Vec<ShareInfo1>> {
        let srvsvc_pipe_name: &str = "srvsvc";
        let srvsvc_pipe = self.open_pipe(server, srvsvc_pipe_name).await?;
        let mut srvsvc_pipe: SrvSvc<_> = srvsvc_pipe.bind().await?;
        let shares = srvsvc_pipe.netr_share_enum(server).await?;

        Ok(shares)
    }

    /// Connects to a share on the specified server.
    ///
    /// This method is the equivalent for executing a `net use` command on a local windows machine.
    ///
    /// Once the connection completes, the client will be able to access resource under the specified share,
    /// without needing to re-authenticate.
    ///
    /// If the share is already connected, this method will do nothing, and will log a warning indicating the double-connection attempt.
    ///
    /// ## Arguments
    /// * `target` - The UNC path of the share to connect to. The method refers to the server and share components in this path.
    /// * `user_name` - The username to use for authentication.
    /// * `password` - The password to use for authentication.
    ///
    /// ## Returns
    /// The connected share - a [`Tree`] instance.
    ///
    /// ## Notes
    /// This is the best high-level method that performs share connection, but it might not suit advanced use cases.
    ///
    /// You can replace calls to this method by performing the connection, session and share setup manually, just like it does,
    /// using the [`Client::connect`] method:
    /// ```no_run
    /// # use smb::{Client, ClientConfig, UncPath, FileCreateArgs, FileAccessMask};
    /// # use std::str::FromStr;
    /// # #[cfg(not(feature = "async"))] fn main() {}
    /// # #[cfg(feature = "async")]
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // instantiate the client
    /// # let client = Client::new(ClientConfig::default());
    /// // Connect to a share
    /// let target_path = UncPath::from_str(r"\\server\share").unwrap();
    /// let connection = client.share_connect(&target_path, "username", "password".to_string()).await?;
    /// #   Ok(()) }
    #[maybe_async]
    pub async fn share_connect(
        &self,
        target: &UncPath,
        user_name: &str,
        password: String,
    ) -> crate::Result<()> {
        if target.share.is_none() {
            return Err(crate::Error::InvalidArgument(
                "UNC path does not contain a share name.".to_string(),
            ));
        }

        let target = target.clone().with_no_path();
        {
            let existing_tree = self.get_tree(&target).await;
            if existing_tree.is_ok() {
                log::warn!(
                    "Share {} is already connected, ignoring duplicate connection attempt.",
                    target
                );
                return Ok(());
            }
        }

        self.connect(&target.server).await?;

        let mut connections = self.connections.lock().await?;
        let connection = connections.get_mut(&target.server).ok_or_else(|| {
            Error::NotFound(format!("No connection found for server: {}", target.server))
        })?;
        let session = connection
            .connection
            .authenticate(user_name, password.clone())
            .await?;
        log::debug!(
            "Successfully authenticated to {} as {}",
            target.server,
            user_name
        );
        let tree = session.tree_connect(&target.to_string()).await?;

        let credentials = if tree.is_dfs_root()? {
            Some((user_name.to_string(), password.clone()))
        } else {
            None
        };

        let connect_share_info = ClientConectedTree {
            session: Arc::new(session),
            tree: Arc::new(tree),
            credentials,
        };
        connection
            .share_connects
            .insert(target.clone(), connect_share_info);

        log::debug!(
            "Successfully connected to share: {}",
            target.share.as_ref().unwrap()
        );

        Ok(())
    }

    #[maybe_async]
    async fn _get_credentials(&self, target: &UncPath) -> crate::Result<(String, String)> {
        let target: UncPath = target.clone().with_no_path();
        let connections = self.connections.lock().await?;
        let connection = connections.get(&target.server).ok_or_else(|| {
            Error::NotFound(format!("No connection found for server: {}", target.server))
        })?;
        if !connection.share_connects.contains_key(&target) {
            return Err(Error::NotFound(format!(
                "No share connection found for path: {target}",
            )));
        }
        return Ok(connection
            .share_connects
            .get(&target)
            .ok_or_else(|| {
                Error::NotFound(format!("No connected share found for path: {target}",))
            })?
            .credentials
            .as_ref()
            .ok_or_else(|| Error::NotFound(format!("No credentials found for path: {target}",)))?
            .clone());
    }

    #[maybe_async]
    async fn _create_file(&self, path: &UncPath, args: &FileCreateArgs) -> crate::Result<Resource> {
        let tree = self.get_tree(path).await?;
        let resource = tree
            .create(path.path.as_deref().unwrap_or(""), args)
            .await?;
        Ok(resource)
    }

    /// Makes a connection to the specified server.
    /// If a matching connection already exists, returns it.
    ///
    /// _Note:_ You should usually connect the client through the [`Client::share_connect`] method.
    /// Using this method, for example, will require you to hold a reference to trees, or otherwise
    /// they will disconnect (as opposed to the `share_connect` method, which assures keeping the tree alive!)
    ///
    /// ## Arguments
    /// * `server` - The target server to make the connection for.
    ///
    /// ## Returns
    /// The connected connection, if succeeded. Error if failed to make the connection,
    /// or failed to connect the remote.
    #[maybe_async]
    pub async fn connect(&self, server: &str) -> crate::Result<Arc<Connection>> {
        let conn = {
            let mut connections = self.connections.lock().await?;
            if let Some(conn) = connections.get(server) {
                log::trace!("Re-using existing connection to {server}",);
                return Ok(conn.connection.clone());
            }

            log::debug!("Creating new connection to {server}",);

            let conn = Connection::build(server, self.config.connection.clone())?;
            let conn = Arc::new(conn);

            connections.insert(
                server.to_owned(),
                ClientConnectionInfo {
                    connection: conn.clone(),
                    share_connects: Default::default(),
                },
            );
            conn
        };

        conn.connect().await?;
        log::debug!("Successfully connected to {server}",);

        Ok(conn)
    }

    /// Returns the underlying [`Connection`] for the specified server,
    /// after a successful call to [`Client::connect`] or [`Client::share_connect`].
    #[maybe_async]
    pub async fn get_connection(&self, server: &str) -> crate::Result<Arc<Connection>> {
        let connections = self.connections.lock().await?;
        if let Some(conn) = connections.get(server) {
            return Ok(conn.connection.clone());
        }
        Err(Error::NotFound(format!(
            "No connection found for server: {server}",
        )))
    }

    #[maybe_async]
    pub async fn get_session(&self, path: &UncPath) -> crate::Result<Arc<Session>> {
        let path = path.clone().with_no_path();
        let connections = self.connections.lock().await?;
        let connection = connections.get(&path.server).ok_or_else(|| {
            Error::NotFound(format!("No connection found for server: {}", path.server))
        })?;
        if let Some(share_connect) = connection.share_connects.get(&path) {
            return Ok(share_connect.session.clone());
        }
        Err(Error::NotFound(format!(
            "No session found for path: {path}",
        )))
    }

    /// Returns the underlying [`Tree`] for the specified UNC path,
    /// after a successful call to [`Client::share_connect`].
    #[maybe_async]
    pub async fn get_tree(&self, path: &UncPath) -> crate::Result<Arc<Tree>> {
        let path = path.clone().with_no_path();
        let connections = self.connections.lock().await?;
        let connection = connections.get(&path.server).ok_or_else(|| {
            Error::NotFound(format!("No connection found for server: {}", path.server))
        })?;
        if let Some(share_connect) = connection.share_connects.get(&path) {
            return Ok(share_connect.tree.clone());
        }
        Err(Error::NotFound(format!("No tree found for path: {path}",)))
    }

    /// Creates (or opens) a file on the specified path, using the specified args.
    ///
    /// See [`FileCreateArgs`] for detailed information regarding the file open options.
    ///
    /// The function also handles DFS resolution if it is enabled in the client configuration.
    ///
    /// ## Arguments
    /// * `path` - The UNC path of the file to create or open.
    /// * `args` - The arguments to use when creating or opening the file.
    ///
    /// ## Returns
    /// A result containing the created or opened file resource, or an error.
    #[maybe_async]
    pub async fn create_file(
        &self,
        path: &UncPath,
        args: &FileCreateArgs,
    ) -> crate::Result<Resource> {
        let file_result = self._create_file(path, args).await;

        let resource = match file_result {
            Ok(file) => Ok(file),
            Err(Error::ReceivedErrorMessage(Status::U32_PATH_NOT_COVERED, _)) => {
                if self.config.dfs {
                    DfsResolver::new(self).resolve_to_dfs_file(path, args).await
                } else {
                    Err(Error::UnsupportedOperation(
                        "DFS is not enabled, but the server returned path not covered (dfs must be enabled in config to resolve the path!).".to_string(),
                    ))
                }
            }
            x => x,
        }?;

        Ok(resource)
    }

    /// Similar [`Client::share_connect`], but connects to the SMB pipes share (IPC$).
    ///
    /// After calling this method, the [`Client::open_pipe`] method can be used to open named pipes.
    #[maybe_async]
    pub async fn ipc_connect(
        &self,
        server: &str,
        user_name: &str,
        password: String,
    ) -> crate::Result<()> {
        let ipc_share = UncPath::ipc_share(server.to_string());
        self.share_connect(&ipc_share, user_name, password).await
    }

    /// Opens a named pipe on the specified server.
    /// Use this when intending to communicate with a service using a named pipe, for convenience.
    ///
    /// ## Arguments
    /// * `server` - The name of the server hosting the pipe.
    /// * `pipe_name` - The name of the pipe to open.
    ///
    /// ## Returns
    /// A result containing the opened [`Pipe`] resource, or an error.
    ///
    /// ## Notes
    /// before calling this method, you MUST call the [`Client::ipc_connect`] method,
    /// that connects to the IPC$ share on the server, which then allows for communication with the named pipe.
    #[maybe_async]
    pub async fn open_pipe(&self, server: &str, pipe_name: &str) -> crate::Result<Pipe> {
        let path = UncPath::ipc_share(server.to_string()).with_path(pipe_name.to_string());
        let pipe = self
            ._create_file(&path, &FileCreateArgs::make_pipe())
            .await?;
        match pipe {
            Resource::Pipe(file) => {
                log::info!("Successfully opened pipe: {pipe_name}",);
                Ok(file)
            }
            _ => crate::Result::Err(Error::InvalidMessage(
                "Expected a pipe resource, but got something else.".to_string(),
            )),
        }
    }
}

impl Default for Client {
    /// Starts the client with default configuration.
    fn default() -> Self {
        Client::new(ClientConfig::default())
    }
}

/// Internal helper struct for implementing DFS referral resolution simply and easily.
struct DfsResolver<'a> {
    client: &'a Client,
}

impl<'a> DfsResolver<'a> {
    fn new(client: &'a Client) -> Self {
        DfsResolver { client }
    }

    /// Resolves the DFS referral for the given UNC path and re-creates a file on the resolved path.
    #[maybe_async]
    async fn resolve_to_dfs_file(
        &self,
        dfs_path: &UncPath,
        args: &FileCreateArgs,
    ) -> crate::Result<Resource> {
        let dfs_ref_paths = self.get_dfs_refs(dfs_path).await?;

        // Re-use the same credentials for the DFS referral.
        let dfs_creds = self.client._get_credentials(dfs_path).await?;

        // Open the next DFS referral. Try each referral path, since some may be down.
        for ref_unc_path in dfs_ref_paths.iter() {
            // Try opening the share. Log failure, and try next ref.
            if let Err(e) = self
                .client
                .share_connect(ref_unc_path, dfs_creds.0.as_str(), dfs_creds.1.clone())
                .await
            {
                log::error!("Failed to open DFS referral: {e}",);
                continue;
            };

            let resource = self
                .client
                ._create_file(ref_unc_path, args)
                .await
                .map_err(|e| {
                    log::error!("Failed to create file on DFS referral: {e}",);
                    e
                })?;
            log::info!("Successfully created file on DFS referral: {ref_unc_path}",);
            return Ok(resource);
        }
        Err(Error::DfsReferralConnectionFail(dfs_path.clone()))
    }

    /// Returns a list of DFS referral paths for the given input UNC path.
    #[maybe_async]
    async fn get_dfs_refs(&self, unc: &UncPath) -> crate::Result<Vec<UncPath>> {
        log::debug!("Resolving DFS referral for {unc}");
        let dfs_path_string = unc.to_string();

        let dfs_refs = {
            let dfs_root = &self.client.get_tree(unc).await?;
            dfs_root
                .as_dfs_tree()?
                .dfs_get_referrals(&dfs_path_string)
                .await?
        };
        if !dfs_refs.referral_header_flags.storage_servers() {
            return Err(Error::InvalidMessage(
                "DFS referral does not contain storage servers".to_string(),
            ));
        }

        let mut paths = vec![];
        // Resolve the DFS referral entries.
        for (indx, curr_referral) in dfs_refs.referral_entries.iter().enumerate() {
            let is_first = indx == 0;
            paths.push(self.ref_entry_to_dfs_target(
                curr_referral,
                dfs_refs.path_consumed as usize,
                &dfs_path_string,
                is_first,
            )?);
        }
        Ok(paths)
    }

    /// Given a [`ReferralEntry`] result from a DFS referral query, returns a ready UNC path for the DFS target.
    fn ref_entry_to_dfs_target(
        &self,
        entry: &ReferralEntry,
        path_consumed: usize,
        dfs_path_string: &str,
        is_first: bool,
    ) -> crate::Result<UncPath> {
        match &entry.value {
            ReferralEntryValue::V4(v4) => {
                // First? verify flags.
                if v4.referral_entry_flags == 0 && is_first {
                    return Err(Error::InvalidMessage(
                        "First DFS Referral is not primary one, invalid message!".to_string(),
                    ));
                }
                // The path consumed is a wstring index.
                let index_end_of_match = path_consumed / std::mem::size_of::<u16>();

                if index_end_of_match > dfs_path_string.len() {
                    return Err(Error::InvalidMessage(
                        "DFS path consumed is out of bounds".to_string(),
                    ));
                }

                let suffix = if index_end_of_match < dfs_path_string.len() {
                    dfs_path_string
                        .char_indices()
                        .nth(index_end_of_match)
                        .ok_or_else(|| {
                            Error::InvalidMessage("DFS path consumed is out of bounds".to_string())
                        })?
                        .0
                } else {
                    // Empty -- exact cover.
                    dfs_path_string.len()
                };

                let unc_str_dest = "\\".to_string()
                    + &v4.refs.network_address.to_string()
                    + &dfs_path_string[suffix..];
                let unc_path = UncPath::from_str(&unc_str_dest)?;
                log::debug!("Resolved DFS referral to {unc_path}",);
                Ok(unc_path)
            }
            _ => Err(Error::UnsupportedOperation(
                "Unsupported DFS referral entry type".to_string(),
            )),
        }
    }
}
