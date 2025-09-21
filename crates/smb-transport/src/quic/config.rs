use std::net::SocketAddr;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum QuicCertValidationOptions {
    /// Use the default platform verifier for the certificate.
    /// See `quinn::ClientConfig::with_platform_verifier`.
    /// This is the default option.
    #[default]
    PlatformVerifier,
    /// Use a store with the provided root certificates.
    CustomRootCerts(Vec<String>),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicConfig {
    pub local_address: Option<SocketAddr>,
    pub cert_validation: QuicCertValidationOptions,
}
