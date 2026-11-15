//! Explicit ClientHello naming with immutable per-connection verification identity.

use super::{ClientTls, Error};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// Public ClientHello SNI selection, independent of the verification hostname.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ClientSni {
    /// Preserve the original absent-SNI profile and ordinary name verification.
    #[default]
    Disabled,
    /// Send this bounded DNS name while verifying each connect's server_name.
    Named(String),
}

impl ClientSni {
    /// Validate and own an explicit DNS SNI name without roots, I/O or a connector.
    pub fn named(name: &str) -> Result<Self, Error> {
        dns_name(name)?;
        Ok(Self::Named(name.to_owned()))
    }
}

pub(super) fn validate(policy: &ClientSni) -> Result<(), Error> {
    if let ClientSni::Named(name) = policy {
        dns_name(name)?;
    }
    Ok(())
}

fn dns_name(name: &str) -> Result<ServerName<'static>, Error> {
    if name.is_empty() || name.len() > 253 || name.as_bytes().contains(&0) {
        return Err(Error::Configuration("invalid SNI DNS name"));
    }
    match ServerName::try_from(name.to_owned()) {
        Ok(name @ ServerName::DnsName(_)) => Ok(name),
        _ => Err(Error::Configuration("SNI requires a DNS name")),
    }
}

pub(super) fn connection(
    tls: &ClientTls,
    verification_name: ServerName<'static>,
) -> Result<(TlsConnector, ServerName<'static>), Error> {
    match &tls.1 {
        ClientSni::Disabled => Ok((TlsConnector::from(tls.0.clone()), verification_name)),
        ClientSni::Named(name) => {
            let wire_name = dns_name(name)?;
            let delegate = tls
                .2
                .as_ref()
                .ok_or(Error::Configuration("missing maintained TLS verifier"))?;
            // A connection owns its verifier name. Reusing ClientTls cannot
            // mutate another in-flight connection's certificate identity.
            let mut config = (*tls.0).clone();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(Verifier {
                    delegate: delegate.clone(),
                    verification_name,
                }));
            Ok((TlsConnector::from(Arc::new(config)), wire_name))
        }
    }
}

#[derive(Debug)]
struct Verifier {
    delegate: Arc<WebPkiServerVerifier>,
    verification_name: ServerName<'static>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _wire_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.delegate.verify_server_cert(
            end_entity,
            intermediates,
            &self.verification_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.delegate.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.delegate.root_hint_subjects()
    }
}
