use std::{collections::HashMap, str::FromStr};

use maybe_async::maybe_async;

use crate::{
    packets::{
        dfsc::{ReferralEntry, ReferralEntryValue},
        rpc::interface::{ShareInfo1, SrvSvc},
        smb2::Status,
    },
    resource::Pipe,
    Connection, Error, FileCreateArgs, Resource, Session, Tree,
};

use super::{config::ClientConfig, unc_path::UncPath};

/// A High-level SMB client interface.
pub struct Client {
    config: ClientConfig,

    connections: HashMap<UncPath, OpenedConnectionInfo>,
}

struct OpenedConnectionInfo {
    _conn: Connection,
    _session: Session,
    tree: Tree,
    creds: Option<(String, String)>,
}

impl Client {
    /// Creates a new `Client` instance with the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config,
            connections: HashMap::new(),
        }
    }

    #[maybe_async]
    pub async fn close(&mut self) -> crate::Result<()> {
        self.connections.clear();
        Ok(())
    }

    /// Connects to the IPC$ share on the specified server using the provided username and password.
    #[maybe_async]
    pub async fn ipc_connect(
        &mut self,
        server: &str,
        user_name: &str,
        password: String,
    ) -> crate::Result<()> {
        let ipc_share = UncPath::ipc_share(server.to_string());
        self.share_connect(&ipc_share, user_name, password).await
    }

    #[maybe_async]
    pub async fn list_shares(&mut self, server: &str) -> crate::Result<Vec<ShareInfo1>> {
        let srvsvc_pipe_name: &str = "srvsvc";
        let srvsvc_pipe = self.open_pipe(server, srvsvc_pipe_name).await?;
        let mut srvsvc_pipe: SrvSvc<_> = srvsvc_pipe.bind().await?;
        let shares = srvsvc_pipe.netr_share_enum(server).await?;

        Ok(shares)
    }

    #[maybe_async]
    pub async fn share_connect(
        &mut self,
        unc: &UncPath,
        user_name: &str,
        password: String,
    ) -> crate::Result<()> {
        if unc.share.is_none() {
            return Err(crate::Error::InvalidArgument(
                "UNC path does not contain a share name.".to_string(),
            ));
        }

        let share_unc = unc.clone().with_no_path();

        if self.connections.contains_key(&share_unc) {
            log::warn!("Connection already exists for this UNC path. Reusing it.");
        }

        let mut conn = Connection::build(share_unc.server.clone(), self.config.connection.clone())?;
        conn.connect().await?;
        let session = conn.authenticate(user_name, password.clone()).await?;
        let tree = session.tree_connect(&share_unc.to_string()).await?;

        let mut opened_conn_info = OpenedConnectionInfo {
            _conn: conn,
            _session: session,
            tree,
            creds: None,
        };

        if self.config.dfs {
            opened_conn_info.creds = Some((user_name.to_string(), password));
        }

        log::debug!("Connected to share {} with user {}", share_unc, user_name);
        self.connections.insert(share_unc, opened_conn_info);

        Ok(())
    }

    fn get_opened_conn_for_path(&self, unc: &UncPath) -> crate::Result<&OpenedConnectionInfo> {
        if let Some(cst) = self.connections.get(&unc.clone().with_no_path()) {
            Ok(cst)
        } else {
            Err(crate::Error::InvalidArgument(format!(
                "No connection found for {}. Use `share_connect` to create one.",
                unc
            )))
        }
    }

    #[maybe_async]
    async fn _create_file_internal(
        &self,
        path: &UncPath,
        args: &FileCreateArgs,
    ) -> crate::Result<Resource> {
        let conn_info = self.get_opened_conn_for_path(path)?;
        conn_info
            .tree
            .create(path.path.as_deref().unwrap_or(""), args)
            .await
    }

    #[maybe_async]
    pub async fn create_file(
        &mut self,
        path: &UncPath,
        args: &FileCreateArgs,
    ) -> crate::Result<Resource> {
        let file_result = self._create_file_internal(path, args).await;

        let resource = match file_result {
            Ok(file) => Ok(file),
            Err(Error::ReceivedErrorMessage(Status::U32_PATH_NOT_COVERED, _)) => {
                if self.config.dfs {
                    DfsResolver::new(self).create_dfs_file(path, args).await
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

    #[maybe_async]
    pub async fn open_pipe(&mut self, server: &str, pipe_name: &str) -> crate::Result<Pipe> {
        let path = UncPath::ipc_share(server.to_string()).with_path(pipe_name.to_string());
        let pipe = self
            ._create_file_internal(&path, &FileCreateArgs::make_pipe())
            .await?;
        match pipe {
            Resource::Pipe(file) => {
                log::info!("Successfully opened pipe: {}", pipe_name);
                Ok(file)
            }
            _ => crate::Result::Err(Error::InvalidMessage(
                "Expected a pipe resource, but got something else.".to_string(),
            )),
        }
    }
}

struct DfsResolver<'a>(&'a mut Client);

impl<'a> DfsResolver<'a> {
    fn new(client: &'a mut Client) -> Self {
        DfsResolver(client)
    }

    /// Resolves the DFS referral for the given UNC path and re-creates a file on the resolved path.
    #[maybe_async]
    async fn create_dfs_file(
        &mut self,
        dfs_path: &UncPath,
        args: &FileCreateArgs,
    ) -> crate::Result<Resource> {
        let dfs_ref_paths = self.get_dfs_refs(dfs_path).await?;

        // Re-use the same credentials for the DFS referral.
        let dfs_creds = self
            .0
            .get_opened_conn_for_path(dfs_path)?
            .creds
            .clone()
            .ok_or_else(|| {
                Error::InvalidState(
                    "DFS referral requires credentials, but none were found.".to_string(),
                )
            })?;

        // Open the next DFS referral. Try each referral path, since some may be down.
        for ref_unc_path in dfs_ref_paths.iter() {
            // Try opening the share. Log failure, and try next ref.
            if let Err(e) = self
                .0
                .share_connect(ref_unc_path, dfs_creds.0.as_str(), dfs_creds.1.clone())
                .await
            {
                log::error!("Failed to open DFS referral: {}", e);
                continue;
            };

            let resource = self
                .0
                ._create_file_internal(ref_unc_path, args)
                .await
                .map_err(|e| {
                    log::error!("Failed to create file on DFS referral: {}", e);
                    e
                })?;
            log::info!(
                "Successfully created file on DFS referral: {}",
                ref_unc_path
            );
            return Ok(resource);
        }
        Err(Error::DfsReferralConnectionFail(dfs_path.clone()))
    }

    #[maybe_async]
    async fn get_dfs_refs(&self, unc: &UncPath) -> crate::Result<Vec<UncPath>> {
        log::debug!("Resolving DFS referral for {}", unc);
        let dfs_path_string = unc.to_string();

        let dfs_root = self.0.get_opened_conn_for_path(unc)?.tree.as_dfs_tree()?;

        let dfs_refs = dfs_root.dfs_get_referrals(&dfs_path_string).await?;
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
                log::debug!("Resolved DFS referral to {}", unc_path);
                Ok(unc_path)
            }
            _ => Err(Error::UnsupportedOperation(
                "Unsupported DFS referral entry type".to_string(),
            )),
        }
    }
}
