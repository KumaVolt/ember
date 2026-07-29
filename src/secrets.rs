//! Credentials Ember has to be able to hand back.
//!
//! Some passwords cannot be one-way hashed, because their whole job is to be
//! shown again: a customer forgets a database password and asks for it, and
//! "reset it and reconfigure your application" is a worse answer than reading
//! it out. Every panel of this kind stores them for that reason.
//!
//! So they are encrypted rather than hashed — ChaCha20-Poly1305 with a key
//! derived from Ember's own signing key, which lives at mode 0600.
//!
//! What this does and does not buy:
//!
//! * It protects the stored file **on its own** — a stray backup, a database
//!   copied off the box, a directory left readable. That is the realistic leak.
//! * It does **not** protect against someone who already has root on the
//!   machine. They can read the key. But Ember runs as root and can reset any
//!   password regardless, so that attacker had already won.
//!
//! The practical consequence is worth stating plainly: back up `$EMBER_HOME`
//! as carefully as the machine itself.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

/// Domain separation, so this key cannot be confused with the session one even
/// though both descend from the same secret.
const KEY_CONTEXT: &[u8] = b"ember:stored-credential:v1";

fn cipher() -> Result<ChaCha20Poly1305> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = crate::auth::secret_key_bytes()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("hmac accepts any key length");
    mac.update(KEY_CONTEXT);
    let derived = mac.finalize().into_bytes();

    let key =
        Key::try_from(&derived[..]).map_err(|_| anyhow::anyhow!("derived key is wrong size"))?;
    Ok(ChaCha20Poly1305::new(&key))
}

/// Encrypt a credential for storage. Returns `nonce.ciphertext`, both base64.
pub fn seal(plaintext: &str) -> Result<String> {
    let nonce_bytes = crate::auth::random_bytes(12)?;
    let nonce =
        Nonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow::anyhow!("bad nonce length"))?;

    let ciphertext = cipher()?
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("could not encrypt the credential"))?;

    Ok(format!(
        "{}.{}",
        BASE64.encode(nonce_bytes),
        BASE64.encode(ciphertext)
    ))
}

/// Decrypt a stored credential.
///
/// Fails rather than returning nonsense if the signing key was regenerated —
/// which is the one way stored credentials become unreadable, and the caller
/// should say so rather than showing an empty box.
pub fn open(stored: &str) -> Result<String> {
    let (nonce_b64, cipher_b64) = stored
        .split_once('.')
        .context("stored credential is malformed")?;

    let nonce_bytes = BASE64
        .decode(nonce_b64)
        .context("stored credential has a bad nonce")?;
    if nonce_bytes.len() != 12 {
        bail!("stored credential has a bad nonce");
    }
    let ciphertext = BASE64
        .decode(cipher_b64)
        .context("stored credential is not readable")?;

    let nonce =
        Nonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow::anyhow!("bad nonce length"))?;
    let plaintext = cipher()?
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| {
            anyhow::anyhow!(
                "could not decrypt this credential — it was stored under a different \
                 signing key. Reset the password to set a new one."
            )
        })?;

    String::from_utf8(plaintext).context("stored credential is not text")
}
