use crate::{copy::CopyCmd, info::InfoCmd, security::SecurityCmd};
use clap::{Parser, Subcommand, ValueEnum};
use smb::Dialect;
use smb::{
    ClientConfig, ConnectionConfig,
    connection::{
        AuthMethodsConfig, EncryptionMode, QuicCertValidationOptions, QuicConfig, TransportConfig,
    },
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(short, long)]
    pub timeout: Option<u16>,

    #[arg(long)]
    pub negotiate_smb2_only: bool,
    /// Disables DFS referral resolution.
    #[arg(long)]
    pub no_dfs: bool,

    /// Disables NTLM authentication.
    #[arg(long)]
    pub no_ntlm: bool,
    /// Disables Kerberos authentication.
    #[arg(long)]
    pub no_kerberos: bool,

    /// Selects a transport protocol to use.
    #[arg(long)]
    pub use_transport: Option<CliUseTransport>,

    #[arg(short, long)]
    pub username: String,
    #[arg(short, long)]
    pub password: String,

    /// Disables message signing.
    /// This may should only be used when logging in with a guest user.
    #[arg(long)]
    pub disable_message_signing: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CliUseTransport {
    Default,
    Netbios,
    Quic,
}

impl Cli {
    pub fn make_smb_client_config(&self) -> ClientConfig {
        ClientConfig {
            dfs: !self.no_dfs,
            connection: ConnectionConfig {
                max_dialect: Some(Dialect::MAX),
                encryption_mode: EncryptionMode::Allowed,
                timeout: self
                    .timeout
                    .map(|t| std::time::Duration::from_secs(t.into())),
                smb2_only_negotiate: self.negotiate_smb2_only,
                transport: match self
                    .use_transport
                    .as_ref()
                    .unwrap_or(&CliUseTransport::Default)
                {
                    CliUseTransport::Quic => TransportConfig::Quic(QuicConfig {
                        local_address: None,
                        cert_validation: QuicCertValidationOptions::PlatformVerifier,
                    }),
                    CliUseTransport::Default => TransportConfig::Tcp,
                    CliUseTransport::Netbios => TransportConfig::NetBios,
                },
                port: self.port,
                auth_methods: AuthMethodsConfig {
                    ntlm: !self.no_ntlm,
                    kerberos: !self.no_kerberos,
                },
                allow_unsigned_guest_access: self.disable_message_signing,
                ..Default::default()
            },
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Copies files to/from a share.
    Copy(CopyCmd),
    /// Retrieves information about a share or a path.
    Info(InfoCmd),
    /// Configures object security
    Security(SecurityCmd),
}
