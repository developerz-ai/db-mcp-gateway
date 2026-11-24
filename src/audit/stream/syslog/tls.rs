//! Trust for the TLS syslog transport: the receiver's certificate must chain
//! to a CA from an operator-supplied PEM file. No system roots — an audit
//! export goes to a receiver the operator names, and pinning its CA keeps a
//! certificate from any public CA from being accepted for it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};

/// The rustls client configuration a TLS syslog sink connects with. Built
/// once (boot or reload) so a bad CA file fails there, not per row.
#[derive(Debug, Clone)]
pub struct SyslogTls(Arc<ClientConfig>);

#[derive(Debug, thiserror::Error)]
pub enum SyslogTlsError {
    #[error("syslog CA file {} could not be read", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("syslog CA file {} holds no PEM certificate", path.display())]
    NoCertificate { path: PathBuf },
    #[error("syslog CA file {} holds a certificate rustls rejects", path.display())]
    BadCertificate {
        path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error("syslog sink with `transport: tls` has no `ca_file`")]
    NoCaFile,
    #[error("TLS client configuration failed")]
    Config(#[source] rustls::Error),
}

impl SyslogTls {
    /// Trust exactly the certificates in the PEM file at `ca_file`. A
    /// synchronous read: it runs once at boot or on a reload, never per row.
    pub fn from_ca_file(ca_file: &Path) -> Result<Self, SyslogTlsError> {
        let pem = std::fs::read(ca_file).map_err(|source| SyslogTlsError::Read {
            path: ca_file.to_owned(),
            source,
        })?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.map_err(|_| SyslogTlsError::NoCertificate {
                path: ca_file.to_owned(),
            })?;
            roots
                .add(cert)
                .map_err(|source| SyslogTlsError::BadCertificate {
                    path: ca_file.to_owned(),
                    source,
                })?;
        }
        if roots.is_empty() {
            return Err(SyslogTlsError::NoCertificate {
                path: ca_file.to_owned(),
            });
        }
        // Named provider rather than the process default, so the sink does
        // not depend on boot having installed one first.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(SyslogTlsError::Config)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self(Arc::new(config)))
    }

    pub(super) fn connector(&self) -> tokio_rustls::TlsConnector {
        tokio_rustls::TlsConnector::from(Arc::clone(&self.0))
    }
}
