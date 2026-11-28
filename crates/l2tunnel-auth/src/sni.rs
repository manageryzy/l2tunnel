//! Explicit ClientHello naming with immutable per-connection verification identity.

use super::{ClientTls, Error, ServerIdentity, hash};
use rustls::{
    DigitallySignedStruct, DistinguishedName, OtherError, SignatureScheme,
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
    let wire_name = match &tls.1 {
        ClientSni::Disabled => verification_name.clone(),
        ClientSni::Named(name) => dns_name(name)?,
    };
    let server_pin = tls.3;
    if matches!(&tls.1, ClientSni::Disabled) && server_pin.is_none() {
        return Ok((TlsConnector::from(tls.0.clone()), verification_name));
    }
    let delegate = tls
        .2
        .as_ref()
        .ok_or(Error::Configuration("missing maintained TLS verifier"))?;
    // A connection owns its verifier name and optional leaf pin. Reusing
    // ClientTls cannot mutate another in-flight connection's identity check.
    let mut config = (*tls.0).clone();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(Verifier {
            delegate: delegate.clone(),
            verification_name,
            server_pin,
        }));
    Ok((TlsConnector::from(Arc::new(config)), wire_name))
}

#[derive(Debug)]
struct Verifier {
    delegate: Arc<WebPkiServerVerifier>,
    verification_name: ServerName<'static>,
    server_pin: Option<ServerIdentity>,
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
        let verified = self.delegate.verify_server_cert(
            end_entity,
            intermediates,
            &self.verification_name,
            ocsp_response,
            now,
        )?;
        if let Some(expected) = self.server_pin {
            let actual = hash(end_entity.as_ref());
            let diff = actual
                .iter()
                .zip(expected.0.iter())
                .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
            if diff != 0 {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Other(OtherError(Arc::new(PinMismatchError))),
                ));
            }
        }
        Ok(verified)
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

#[derive(Debug)]
struct PinMismatchError;

impl std::fmt::Display for PinMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server leaf certificate SHA-256 pin mismatch")
    }
}

impl std::error::Error for PinMismatchError {}
