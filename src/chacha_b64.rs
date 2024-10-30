//! Password-based encryption, combined with base64 encoding.

use crate::{Chacha, Cipher, Error};
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, DecodeError, Engine as _};
use serde::{Deserialize, Serialize};

/// A wrapper around [`Chacha`], which uses `base64` to convert the [Cipher]-struct used by Chacha
/// into the fully String-based [`CipherB64`].
///
/// Like in [`Chacha`], the methods `encrypt` and `decrypt` just deal with the secret,
/// the methods `encrypt_auth` and `decrypt_auth` use additionally an authentication tag.
///
/// The return value of the encrypt methods is of type [`CipherB64`] and needs to be provided
/// with the same content to the decrypt call.
///
/// # Example with authentication tag
///
/// ```rust
/// use pwsec::{ChachaB64, CipherB64};
/// let secret = "this is some serialized form of the secret data".to_string();
/// let auth_tag = "this is just some informal and nonconfidential summary".to_string();
/// let pw = "LOIUo98zkjhB";
/// let chacha_b64 = ChachaB64::with_pbkdf2_rounds(123_456);
/// let cipher_b64 = chacha_b64.encrypt_auth(secret.as_bytes(), auth_tag.as_bytes(), pw).unwrap();
///
/// // CipherB64 implements std::fmt::Display for serialization...
/// let s = cipher_b64.to_string();
/// // ...and has a method parse() for reading from a String
/// let cipher_b64_2 = CipherB64::parse(&s).unwrap();
/// // Decryption needs the cipher_b64, the auth_tag, and the password:
/// let secret_2 = chacha_b64.decrypt_auth(cipher_b64_2, auth_tag.as_bytes(), pw).unwrap();
/// assert_eq!(secret.as_bytes(), secret_2);
/// ```
pub struct ChachaB64 {
    chacha: Chacha,
}
impl ChachaB64 {
    /// The constructor takes the number of rounds that pbkdf2 should use.
    ///
    /// Choose a random big value, like `125_642` or `101_864`, and use the same number
    /// for encryption and decryption.
    #[must_use]
    pub fn with_pbkdf2_rounds(pbkdf_rounds: u32) -> Self {
        Self {
            chacha: Chacha::with_pbkdf2_rounds(pbkdf_rounds),
        }
    }

    /// Encrypts a secret securely, based on a password.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `secret`: the sensitive data you want to encrypt
    ///   - `pw`: the password
    /// - Output:
    ///   A structure with the values that are needed for decrypting.
    ///
    /// # Errors
    ///
    /// `Error::Encrypt` can occur.
    pub fn encrypt(&self, secret: &[u8], pw: &str) -> Result<CipherB64<String, String>, Error> {
        Ok(self.chacha.encrypt(secret, pw)?.into())
    }

    /// Encrypts data securely, based on a password.
    ///
    /// # Parameters:
    /// - Input:
    ///   - secret: the sensitive data you want to encrypt
    ///   - auth: optional authentication tag that will not be encrypted, but must be provided
    ///     in unmodified form also to the decrypt call
    ///   - pw: the password
    /// - Output:
    ///   A structure with the values that are needed for decrypting.
    ///
    /// # Errors
    ///
    /// `Error::Encrypt` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn encrypt_auth(
        &self,
        secret: &[u8],
        auth: &[u8],
        pw: &str,
    ) -> Result<CipherB64<String, String>, Error> {
        Ok(self.chacha.encrypt_auth(secret, auth, pw)?.into())
    }

    /// Decrypts data that were encrypted with `encrypt()`.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `cipher_b64`: the output from `encrypt`
    ///   - `pw`: the password
    /// - Output:
    ///   - the sensitive data you had encrypted
    ///
    /// # Errors
    ///
    /// `Error::Decrypt` and `Error::Decode` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn decrypt(&self, cipher_b64: CipherB64<&str, &str>, pw: &str) -> Result<Vec<u8>, Error> {
        self.chacha.decrypt(
            &cipher_b64
                .try_into()
                .map_err(|e: DecodeError| Error::Decode(e.to_string()))?,
            pw,
        )
    }

    /// Decrypts data that were encrypted with `encrypt_auth()`.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `cipher_b64`: the output from `encrypt_auth`
    ///   - `auth`: the same value as it was given to the `encrypt_auth` call
    ///   - `pw`: the password
    /// - Output:
    ///   - the sensitive data you had encrypted
    ///
    /// # Errors
    ///
    /// `Error::Decrypt` and `Error::Decode` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn decrypt_auth(
        &self,
        cipher_b64: CipherB64<&str, &str>,
        auth: &[u8],
        pw: &str,
    ) -> Result<Vec<u8>, Error> {
        self.chacha.decrypt_auth(
            &cipher_b64
                .try_into()
                .map_err(|e: DecodeError| Error::Decode(e.to_string()))?,
            auth,
            pw,
        )
    }
}

/// The values that need to be provided to the decrypt call,
/// in addition to the password and the auth tag.
#[derive(Serialize, Deserialize)]
pub struct CipherB64<S1, S2> {
    /// The salt that was randomly generated and used within the key derivation
    /// within the encrypt call.
    pub salt: S1,
    /// The encrypted and authenticated secret, base64-encoded.
    pub ciphertext: S2,
    /// The randomly generated nonce that was used for the encryption, as base64-encoded String.
    pub nonce: S2,
}
impl CipherB64<&str, &str> {
    /// Parses a `CipherB64<&str, &str>` from a String (that is supposed to be formed by
    /// `CipherB64<S1, S2>::to_string`).
    #[must_use]
    pub fn parse(s: &str) -> Option<CipherB64<&str, &str>> {
        let mut cc_it = s.split(&[':']);
        match (cc_it.next(), cc_it.next(), cc_it.next()) {
            (Some(salt), Some(ciphertext), Some(nonce)) => Some(CipherB64::<&str, &str> {
                salt,
                ciphertext,
                nonce,
            }),
            _ => None,
        }
    }
}
/// Renders `CipherB64` in the form `<salt>:<ciphertext>:<nonce>`.
impl std::fmt::Display for CipherB64<String, String> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", &self.salt, &self.ciphertext, &self.nonce)
    }
}
impl std::convert::From<Cipher> for CipherB64<String, String> {
    fn from(cipher: Cipher) -> Self {
        CipherB64 {
            salt: cipher.salt,
            ciphertext: b64.encode(cipher.ciphertext),
            nonce: b64.encode(cipher.nonce),
        }
    }
}
impl std::convert::TryFrom<CipherB64<&str, &str>> for Cipher {
    type Error = DecodeError;

    fn try_from(cipher_b64: CipherB64<&str, &str>) -> Result<Self, Self::Error> {
        Ok(Cipher {
            salt: cipher_b64.salt.to_string(),
            ciphertext: b64.decode(cipher_b64.ciphertext.as_bytes())?,
            nonce: b64.decode(cipher_b64.nonce.as_bytes())?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{ChachaB64, CipherB64};
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_encrypt_decrypt() {
        let test_data = "daewörjlser,dk gjxlre.t98i1df.lskejr lewiri23r9ß iu4ötirjf";
        let pw = "LOIUo98zkjhB";

        let cc64 = ChachaB64::with_pbkdf2_rounds(145_654);
        // encrypt
        let cipher_b64 = cc64.encrypt(test_data.as_bytes(), pw).unwrap();

        // decrypt
        let cipher_b64_2 = CipherB64::<&str, &str> {
            salt: &cipher_b64.salt,
            ciphertext: &cipher_b64.ciphertext,
            nonce: &cipher_b64.nonce,
        };
        let test_data2 = String::from_utf8(cc64.decrypt(cipher_b64_2, pw).unwrap()).unwrap();

        assert_eq!(test_data, &test_data2);
    }

    // write a file with an encrypted secret and a unmodifiable summary in clear text
    #[test]
    fn test_with_auth() {
        #[derive(Serialize, Deserialize)]
        struct FileStruct {
            comment: String,
            description: String,
            encrypted_secret: String,
        }
        const COMMENT: &str = "# Dont' modify this file";

        let cc64 = ChachaB64::with_pbkdf2_rounds(145_654);

        let secret = vec!["elephant", "mouse", "bee", "swift"];
        let description = format!("{} mammals, {} insect, {} bird", 2, 1, 1);
        let pw = "LOIUo98zkjhB";

        let encrypted_secret = cc64
            .encrypt_auth(
                serde_json::to_string(&secret).unwrap().as_bytes(),
                description.as_bytes(),
                pw,
            )
            .unwrap();

        // write the file
        let file_content = FileStruct {
            comment: COMMENT.to_string(),
            description,
            encrypted_secret: encrypted_secret.to_string(),
        };
        let serialized_file_content = serde_json::to_string_pretty(&file_content).unwrap();
        // serialized_file_content will look like this
        // (the values in the encrypted_secret are volatile, of course):
        // {
        //     "comment": "# Dont' modify this file",
        //     "description": "2 mammals, 1 insect, 1 bird",
        //     "encrypted_secret": "<salt>:<ciphertext>:<nonce>"
        // }

        assert_eq!(
            serialized_file_content[0..114],
            r##"{
  "comment": "# Dont' modify this file",
  "description": "2 mammals, 1 insect, 1 bird",
  "encrypted_secret": "NkJ3RDl3UWJ5UWZPdEVOR2tKdHJBdw:2FeIy66BS8HFFDpX6+gNs6wf3gVhIii2QtMG2Bm1tfH1OubbMIEYMl5ZmYzUhBzykLEAQWXThmM0ayjCDWp"
}"##[0..114]
        );

        let file_content2: FileStruct = serde_json::from_str(&serialized_file_content).unwrap();
        let secret2: Vec<String> = serde_json::from_str(&String::from_utf8_lossy(
            &cc64
                .decrypt_auth(
                    CipherB64::parse(&file_content2.encrypted_secret).unwrap(),
                    file_content2.description.as_bytes(),
                    pw,
                )
                .unwrap(),
        ))
        .unwrap();

        assert_eq!(secret, secret2);
    }
}
