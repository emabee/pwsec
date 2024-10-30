#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

//! Support for password-based encryption.
//!
//! Two variants are provided currently, [`Chacha`] and [`ChachaB64`].
//!
//! Alternative classes with similar API and based on other encryption algorithms can be added.
mod chacha;
mod chacha_b64;

pub use crate::chacha::{Chacha, Cipher};
pub use crate::chacha_b64::{ChachaB64, CipherB64};

use thiserror::Error;

/// Errors that can occur during encryption or decryption.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// buffer writing failed
    #[error("buffer writing failed")]
    Io(#[from] std::io::Error),

    /// encryption call failed
    #[error("encryption failed")]
    Encrypt(String),

    /// decryption call failed
    #[error("decryption failed")]
    Decrypt(String),

    /// base64 decoding failed
    #[error("base64 decoding failed")]
    Decode(String),
}
