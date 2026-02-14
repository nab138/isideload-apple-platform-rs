// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session establishment and crypto code for remote signing protocol.
//!
//! The intent of this module / file is to isolate the code with the highest
//! sensitivity for security matters.

use {
    crate::remote_signing::RemoteSignError,
    std::fmt::{Display, Formatter},
};

type Result<T> = std::result::Result<T, RemoteSignError>;

/// The role being assumed by a peer.
#[derive(Clone, Copy, Debug)]
pub enum Role {
    /// Peer who initiated the session.
    A,
    /// Peer who joined the session.
    B,
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::B => "B",
        })
    }
}

/// Describes a type that is capable of decrypting messages used during public key negotiation.
pub trait PublicKeyPeerDecrypt {
    /// Decrypt an encrypted message.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
