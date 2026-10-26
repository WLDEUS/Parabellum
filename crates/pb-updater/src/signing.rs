//! minisign (Ed25519) verification with `minisign-verify`.
//!
//! Only *pre-hashed* signatures (`ED`, the minisign default since 0.8) are accepted: they can be verified
//! by streaming the file through BLAKE2b, so a 1 GiB bundle never has to sit in memory. Legacy (`Ed`)
//! signatures are refused.

use crate::UpdateError;
use minisign_verify::{PublicKey, Signature};
use std::io::Read;
use std::path::Path;

/// Max size of a `.minisig` file.
pub(crate) const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;

/// Parse a minisign public key given either as the bare base64 string or as the 2-line `minisign.pub`
/// file (`untrusted comment: …` line followed by the base64 line).
pub(crate) fn parse_public_key(s: &str) -> Result<PublicKey, UpdateError> {
    let s = s.trim();
    let res = if s.lines().count() >= 2 {
        PublicKey::decode(s)
    } else {
        PublicKey::from_base64(s)
    };
    res.map_err(|e| UpdateError::Signature(format!("clé publique illisible : {e}")))
}

/// Verify `sig_text` (content of a `.minisig`) over the file at `path`, streaming.
/// Returns the signature's trusted comment on success.
pub(crate) fn verify_file(
    path: &Path,
    sig_text: &str,
    pk: &PublicKey,
) -> Result<String, UpdateError> {
    let sig = Signature::decode(sig_text.trim_start_matches('\u{feff}'))
        .map_err(|e| UpdateError::Signature(format!("signature illisible : {e}")))?;
    let mut verifier = pk
        .verify_stream(&sig)
        .map_err(|e| UpdateError::Signature(format!("signature non utilisable : {e}")))?;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        verifier.update(&buf[..n]);
    }
    verifier
        .finalize()
        .map_err(|e| UpdateError::Signature(format!("{} : {e}", file_label(path))))?;
    Ok(sig.trusted_comment().to_string())
}

/// Async wrapper running the hashing on the blocking pool.
pub(crate) async fn verify_file_async(
    path: &Path,
    sig_text: String,
    pk_text: String,
) -> Result<String, UpdateError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let pk = parse_public_key(&pk_text)?;
        verify_file(&path, &sig_text, &pk)
    })
    .await
    .map_err(|e| UpdateError::Signature(format!("vérification interrompue : {e}")))?
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! In-test key generation with the `minisign` crate.
    use std::io::Cursor;

    pub(crate) struct TestKey {
        pub(crate) kp: minisign::KeyPair,
    }

    impl TestKey {
        pub(crate) fn new() -> Self {
            Self {
                kp: minisign::KeyPair::generate_unencrypted_keypair().expect("keypair"),
            }
        }
        /// Bare base64 public key.
        pub(crate) fn public_b64(&self) -> String {
            self.kp.pk.to_base64()
        }
        /// 2-line `.pub` file content.
        pub(crate) fn public_file(&self) -> String {
            self.kp.pk.to_box().expect("pk box").to_string()
        }
        pub(crate) fn sign(&self, data: &[u8]) -> String {
            minisign::sign(
                Some(&self.kp.pk),
                &self.kp.sk,
                Cursor::new(data),
                Some("test"),
                None,
            )
            .expect("sign")
            .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::TestKey;
    use super::*;

    #[test]
    fn verifies_both_key_forms_and_rejects_tampering() {
        let key = TestKey::new();
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("data.bin");
        std::fs::write(&f, b"hello parabellum").unwrap();
        let sig = key.sign(b"hello parabellum");
        for pk_text in [key.public_b64(), key.public_file()] {
            let pk = parse_public_key(&pk_text).unwrap();
            assert_eq!(verify_file(&f, &sig, &pk).unwrap(), "test");
        }
        std::fs::write(&f, b"hello parabellum!").unwrap();
        let pk = parse_public_key(&key.public_b64()).unwrap();
        assert!(matches!(
            verify_file(&f, &sig, &pk),
            Err(UpdateError::Signature(_))
        ));
        // Wrong key.
        let other = TestKey::new();
        let pk2 = parse_public_key(&other.public_b64()).unwrap();
        std::fs::write(&f, b"hello parabellum").unwrap();
        assert!(verify_file(&f, &sig, &pk2).is_err());
        // Garbage.
        assert!(verify_file(&f, "nope", &pk).is_err());
        assert!(parse_public_key("not a key").is_err());
    }

    #[test]
    fn dnscrypt_key_constant_parses() {
        assert!(parse_public_key(crate::components::DNSCRYPT_MINISIGN_KEY).is_ok());
    }
}
