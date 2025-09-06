use crate::ConnectionConfig;

/// Configuration for the SMB client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Whether to enable DFS (Distributed File System) resolution for the client.
    /// This includes resolving DFS referrals and accessing DFS namespaces.
    ///
    /// - If this is set to `false`, the client might return [`Status::PathNotCovered`][crate::packets::smb2::Status::PathNotCovered] errors
    ///   when trying to access DFS paths, instead of automatically resolving them.
    pub dfs: bool,

    /// Configuration related to the SMB connections made by the client.
    /// See [`ConnectionConfig`] for more details.
    pub connection: ConnectionConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            dfs: true,
            connection: ConnectionConfig::default(),
        }
    }
}
