//! Connection configuration settings.

use std::time::Duration;

use crate::packets::{guid::Guid, smb2::Dialect};

/// Specifies the encryption mode for the connection.
/// Use this as part of the [ConnectionConfig] to specify the encryption mode for the connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionMode {
    /// Encryption is allowed but not required, it's up to the server to decide.
    #[default]
    Allowed,
    /// Encryption is required, and connection will fail if the server does not support it.
    Required,
    /// Encryption is disabled, server might fail the connection if it requires encryption.
    Disabled,
}

/// Specifies the transport protocol to be used for the connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// Use TCP transport protocol.
    #[default]
    Tcp,
    /// Use NetBIOS over TCP transport protocol.
    NetBios,
    /// Use SMB over QUIC transport protocol.
    /// Note that this is only suported in dialects 3.1.1 and above.
    Quic(QuicConfig),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicConfig {
    pub local_address: Option<String>,
    pub cert_validation: QuicCertValidationOptions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum QuicCertValidationOptions {
    /// Use the default platform verifier for the certificate.
    /// See [quinn::ClientConfig::with_platform_verifier].
    /// This is the default option.
    #[default]
    PlatformVerifier,
    /// Use a store with the provided root certificates.
    CustomRootCerts(Vec<String>),
}

impl EncryptionMode {
    /// Returns true if encryption is required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }

    /// Returns true if encryption is disabled.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Specifies the authentication methods (SSPs) to be used for the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMethodsConfig {
    /// Whether to try using NTLM authentication.
    /// This is enabled by default.
    pub ntlm: bool,

    /// Whether to try using Kerberos authentication.
    /// This is supported only if the `kerberos` feature is enabled,
    /// and if so, enabled by default.
    pub kerberos: bool,
}

impl Default for AuthMethodsConfig {
    fn default() -> Self {
        Self {
            ntlm: true,
            kerberos: cfg!(feature = "kerberos"),
        }
    }
}

/// Specifies the configuration for a connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Specifies the server port to connect to.
    /// If unset, defaults to the default port for the selected transport protocol.
    /// For Direct TCP, this is 445.
    /// For NetBIOS, this is 139.
    /// For SMB over QUIC, this is 443.
    pub port: Option<u16>,

    /// Specifies the timeout for the connection.
    /// If unset, defaults to [`ConnectionConfig::DEFAULT_TIMEOUT`].
    /// 0 means wait forever.
    /// Access the timeout using the [`ConnectionConfig::timeout()`] method.
    pub timeout: Option<Duration>,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub min_dialect: Option<Dialect>,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub max_dialect: Option<Dialect>,

    /// Sets the encryption mode for the connection.
    /// See [EncryptionMode] for more information.
    pub encryption_mode: EncryptionMode,

    /// Whether to enable compression, if supported by the server and specified connection dialects.
    ///
    /// Note: you must also have compression features enabled when building the crate, otherwise compression
    /// would not be available. *The compression feature is enabled by default.*
    pub compression_enabled: bool,

    /// Specifies the client host name to be used in the SMB2 negotiation & session setup.
    pub client_name: Option<String>,

    /// Specifies the GUID of the client to be used in the SMB2 negotiate request.
    /// If not set, a random GUID will be generated.
    pub client_guid: Option<Guid>,

    /// Specifies whether to disable support for Server-to-client notifications.
    /// If set to true, the client will NOT support notifications.
    pub disable_notifications: bool,

    /// Whether to avoid multi-protocol negotiation,
    /// and perform smb2-only negotiation. This results in a
    /// faster negotiation process, but may not be compatible
    /// with all servers properly.
    pub smb2_only_negotiate: bool,

    /// Specifies the transport protocol to be used for the connection.
    pub transport: TransportConfig,

    /// Configures valid authentication methods (SSPs) for the connection.
    /// See [`AuthMethodsConfig`] for more information.
    pub auth_methods: AuthMethodsConfig,
}

impl ConnectionConfig {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Validates common configuration settings.
    pub fn validate(&self) -> crate::Result<()> {
        // Make sure dialects min <= max.
        if let (Some(min), Some(max)) = (self.min_dialect, self.max_dialect) {
            if min > max {
                return Err(crate::Error::InvalidConfiguration(
                    "Minimum dialect is greater than maximum dialect".to_string(),
                ));
            }
        }
        // Make sure transport is supported by the dialects.
        if let Some(min) = self.min_dialect {
            if min < Dialect::Smb0311 && matches!(self.transport, TransportConfig::Quic(_)) {
                return Err(crate::Error::InvalidConfiguration(
                    "SMB over QUIC is not supported by the selected dialect".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT)
    }
}
