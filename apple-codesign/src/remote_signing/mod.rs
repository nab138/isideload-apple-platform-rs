// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Remote signing support.

pub mod session_negotiation;

use {thiserror::Error, x509_certificate::X509CertificateError};

/// URL of default server to use.
pub const DEFAULT_SERVER_URL: &str = "wss://ws.codesign.gregoryszorc.com/";

/// An error specific to remote signing.
#[derive(Debug, Error)]
pub enum RemoteSignError {
    #[error("unexpected message received from relay server: {0}")]
    ServerUnexpectedMessage(String),

    #[error("error reported from relay server: {0}")]
    ServerError(String),

    #[error("not compatible with relay server; try upgrading to a new release?")]
    ServerIncompatible,

    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("bad client state: {0}")]
    ClientState(&'static str),

    #[error("joining state not wanted for this session type: {0}")]
    SessionJoinUnwantedState(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM encoding error: {0}")]
    Pem(#[from] pem::PemError),

    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("SPKI error: {0}")]
    Spki(#[from] spki::Error),

    #[error("X.509 certificate handler error: {0}")]
    X509(#[from] X509CertificateError),
}

/// A function that receives session information.
pub type SessionInfoCallback = fn(sjs_base64: &str, sjs_pem: &str) -> Result<(), RemoteSignError>;
