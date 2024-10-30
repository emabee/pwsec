use super::Error;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305,
};
use generic_array::GenericArray;
use pbkdf2::{password_hash::SaltString, pbkdf2_hmac_array};
use sha2::Sha256;

const KEY_LENGTH: usize = 32;
const SALT_LEN: usize = 22;
const NONCE_LEN: usize = 12;

/// A tool to encrypt and decrypt data with `chacha20poly1305`, with a key that is derived from the
/// given password using `pbkdf2`.
///
/// The methods `encrypt` and `decrypt` just deal with the secret,
/// the methods `encrypt_auth` and `decrypt_auth` use additionally an authentication tag.
///
/// The return value of the encrypt methods is of type [`Cipher`] and needs to be provided
/// with the same content to the decrypt call.
///
/// # Example with authentication tag
///
/// ```rust
/// use pwsec::Chacha;
/// let secret = b"this is some serialized form of the secret data";
/// let auth_tag = b"this is just some informal and nonconfidential summary";
/// let pw = "LOIUo98zkjhB";
/// let chacha = Chacha::with_pbkdf2_rounds(123_456);
/// let cipher = chacha.encrypt_auth(secret, auth_tag, pw).unwrap();
///
/// // Decryption needs the cipher, the auth_tag, and the password:
/// let decrypted_secret = chacha.decrypt_auth(&cipher, auth_tag, pw).unwrap();
/// assert_eq!(secret.to_vec(), decrypted_secret);
/// ```
pub struct Chacha {
    pbkdf_rounds: u32,
}
impl Chacha {
    /// The constructor takes the number of rounds that pbkdf2 should use.
    ///
    /// Choose a random big value, like `125_642` or `101_864`, and use the same number
    /// for encryption and decryption.
    #[must_use]
    pub fn with_pbkdf2_rounds(pbkdf_rounds: u32) -> Self {
        Self { pbkdf_rounds }
    }
    fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
        pbkdf2_hmac_array::<Sha256, KEY_LENGTH>(password.as_bytes(), salt, self.pbkdf_rounds)
    }

    /// Encrypts a secret securely, based on a password.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `secret`: the sensitive data you want to encrypt
    ///   - `pw`: the password
    /// - Output:
    ///   - the encrypted secret
    ///
    /// # Errors
    ///
    /// `Error::Encrypt` can occur.
    pub fn encrypt(&self, secret: &[u8], pw: &str) -> Result<Cipher, Error> {
        self.encrypt_auth(secret, &[0_u8; 0], pw)
    }

    /// Encrypts a secret securely, based on a password, and using an authentication tag.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `secret`: the sensitive data you want to encrypt
    ///   - `auth`: optional additional data that will not be encrypted, but must be provided
    ///     in unmodified form also to `decrypt_auth`
    ///   - `pw`: the password
    /// - Output:
    ///   - the sensitive data you had encrypted
    ///
    /// # Errors
    ///
    /// `Error::Encrypt` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn encrypt_auth(&self, secret: &[u8], auth: &[u8], pw: &str) -> Result<Cipher, Error> {
        let salt = SaltString::generate(&mut OsRng);
        debug_assert_eq!(salt.len(), SALT_LEN);

        let key = self.derive_key_from_password(pw, salt.as_str().as_bytes());

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        debug_assert_eq!(nonce.len(), NONCE_LEN);

        Ok(Cipher {
            salt: salt.to_string(),
            ciphertext: ChaCha20Poly1305::new_from_slice(&key)
            .unwrap(/*OK*/)
            .encrypt(
                &nonce,
                Payload {
                    msg: secret,
                    aad: auth,
                },
            )
            .map_err(|e| {
                Error::Encrypt(format!("can't encrypt the connection store, due to {e}"))
            })?,
            nonce: nonce.to_vec(),
        })
    }

    /// Decrypts data that were encrypted with `encrypt()`.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `cipher`: the output from `encrypt`
    ///   - `auth`: the same value as it was given to the encrypt call
    ///   - `pw`: the password
    /// - Output:
    ///   - the sensitive data you had encrypted
    ///
    /// # Errors
    ///
    /// `Error::Decrypt` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn decrypt(&self, cipher: &Cipher, pw: &str) -> Result<Vec<u8>, Error> {
        self.decrypt_auth(cipher, "".as_bytes(), pw)
    }

    /// Decrypts data that were encrypted with `encrypt()`.
    ///
    /// # Parameters:
    /// - Input:
    ///   - `cipher`: the output from `encrypt`
    ///   - `auth`: the same value as it was given to the encrypt call
    ///   - `pw`: the password
    /// - Output:
    ///   - the sensitive data you had encrypted
    ///
    /// # Errors
    ///
    /// `Error::Decrypt` can occur.
    #[allow(clippy::missing_panics_doc)]
    pub fn decrypt_auth(&self, cipher: &Cipher, auth: &[u8], pw: &str) -> Result<Vec<u8>, Error> {
        let key = self.derive_key_from_password(pw, cipher.salt.as_bytes());
        let ccp = ChaCha20Poly1305::new_from_slice(&key).unwrap(/*ok*/);
        ccp.decrypt(
            GenericArray::from_slice(&cipher.nonce),
            Payload {
                msg: &cipher.ciphertext,
                aad: auth,
            },
        )
        .map_err(|e| Error::Decrypt(e.to_string()))
    }
}

/// The values that need to be provided to the decrypt call,
/// in addition to the password and optionally the auth tag.
pub struct Cipher {
    /// The salt that was randomly generated and used within the key derivation
    /// within the encrypt call.
    pub salt: String,
    /// The encrypted and authenticated secret.
    pub ciphertext: Vec<u8>,
    /// The randomly generated nonce that was used for the encryption.
    pub nonce: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::Chacha;

    #[test]
    fn test_encrypt_decrypt() {
        let test_data = String::from("daewörjlser,dk gjxlre.t98i1df.lskejr lewiri23r9ß iu4ötirjf");
        let pw = "LOIUo98zkjhB";
        let chacha = Chacha::with_pbkdf2_rounds(123_456);
        let cipher = chacha.encrypt(test_data.as_bytes(), pw).unwrap();
        // ---
        let result = String::from_utf8(chacha.decrypt(&cipher, pw).unwrap()).unwrap();
        assert_eq!(test_data, result);
    }

    #[test]
    fn test_encrypt_auth_decrypt_auth() {
        let test_data = String::from("daewörjlser,dk gjxlre.t98i1df.lskejr lewiri23r9ß iu4ötirjf");
        let test_auth = "oirlyrkfdösadkflsdkgnfm";
        let pw = "LOIUo98zkjhB";
        let chacha = Chacha::with_pbkdf2_rounds(123_456);
        let cipher = chacha
            .encrypt_auth(test_data.as_bytes(), test_auth.as_bytes(), pw)
            .unwrap();
        // ---
        let result = String::from_utf8(
            chacha
                .decrypt_auth(&cipher, test_auth.as_bytes(), pw)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(test_data, result);
    }
}
