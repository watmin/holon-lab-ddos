//! Sealed denial context tokens.
//!
//! When the spectral firewall denies or rate-limits a request, a denial context
//! is built (verdict, residual, threshold, top anomalous fields, engram matches)
//! and sealed via AES-256-GCM encryption. The resulting base64 token is attached
//! as an `X-Denial-Context` response header.
//!
//! Operators can unseal the token offline with the same key to get a full
//! explainability record of why the request was denied.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::manifold::DrilldownAttribution;

/// Plaintext denial context — serialized to JSON before sealing.
#[derive(Debug, Serialize, Deserialize)]
pub struct DenialContext {
    /// "deny" or "rate_limit"
    pub verdict: String,
    /// Residual score that triggered the verdict.
    pub residual: f64,
    /// Baseline threshold at the time of denial.
    pub threshold: f64,
    /// Deny threshold at the time of denial.
    pub deny_threshold: f64,
    /// Top anomalous fields from drilldown.
    pub top_fields: Vec<FieldAttribution>,
    /// Source IP.
    pub src_ip: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Query string (if present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// User-Agent header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Header names in wire order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_names: Vec<String>,
    /// Cookie keys present (values omitted for size).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookie_keys: Vec<String>,
    /// Concentration ratio: max_score / mean_score. High = narrow.
    #[serde(default)]
    pub concentration: f64,
    /// Normalized Shannon entropy [0,1]. 1 = broad, 0 = narrow.
    #[serde(default)]
    pub entropy: f64,
    /// Gini coefficient [0,1]. 0 = broad, 1 = narrow.
    #[serde(default)]
    pub gini: f64,
    /// Timestamp (microseconds since epoch).
    pub timestamp_us: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FieldAttribution {
    pub field: String,
    pub score: f64,
}

impl From<&DrilldownAttribution> for FieldAttribution {
    fn from(a: &DrilldownAttribution) -> Self {
        Self {
            field: a.field.clone(),
            score: a.score,
        }
    }
}

/// 256-bit key for AES-256-GCM sealing.
#[derive(Clone)]
pub struct DenialKey {
    key_bytes: [u8; 32],
}

impl DenialKey {
    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key_bytes: bytes }
    }

    /// Access the raw key bytes (for persistence).
    pub fn raw_bytes(&self) -> &[u8; 32] {
        &self.key_bytes
    }

    /// Generate a random key.
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes).expect("RNG failure");
        Self { key_bytes }
    }

    fn aead_key(&self) -> LessSafeKey {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .expect("AES-256-GCM key creation");
        LessSafeKey::new(unbound)
    }
}

/// Seal a denial context into a base64 token.
///
/// Format: nonce(12) || ciphertext || tag(16), all base64-encoded.
pub fn seal(ctx: &DenialContext, key: &DenialKey) -> Result<String, String> {
    let json = serde_json::to_vec(ctx).map_err(|e| format!("serialize: {}", e))?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| "RNG failure".to_string())?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aead_key = key.aead_key();

    let mut in_out = json;
    aead_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "seal failure".to_string())?;

    // Prepend nonce
    let mut output = Vec::with_capacity(12 + in_out.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&in_out);

    Ok(URL_SAFE_NO_PAD.encode(&output))
}

/// Unseal a base64 token back into a denial context.
pub fn unseal(token: &str, key: &DenialKey) -> Result<DenialContext, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| format!("base64 decode: {}", e))?;

    if raw.len() < 12 + 16 {
        return Err("token too short".to_string());
    }

    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let nonce = Nonce::assume_unique_for_key(
        nonce_bytes.try_into().map_err(|_| "nonce length")?,
    );

    let aead_key = key.aead_key();
    let mut buf = ciphertext.to_vec();
    let plaintext = aead_key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "unseal failure (wrong key or tampered token)".to_string())?;

    serde_json::from_slice(plaintext).map_err(|e| format!("deserialize: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> DenialContext {
        DenialContext {
            verdict: "deny".to_string(),
            residual: 42.5,
            threshold: 10.0,
            deny_threshold: 20.0,
            top_fields: vec![
                FieldAttribution { field: "headers".into(), score: 15.3 },
                FieldAttribution { field: "path_shape".into(), score: 8.1 },
            ],
            src_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/admin/../../../etc/passwd".to_string(),
            query: Some("cmd=cat%20/etc/shadow".to_string()),
            user_agent: Some("Nikto/2.1.6".to_string()),
            header_names: vec!["Host".into(), "User-Agent".into(), "Accept".into()],
            cookie_keys: vec![],
            concentration: 2.1,
            entropy: 0.85,
            gini: 0.25,
            timestamp_us: 1700000000000000,
        }
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let key = DenialKey::generate();
        let ctx = sample_context();
        let token = seal(&ctx, &key).unwrap();
        let recovered = unseal(&token, &key).unwrap();
        assert_eq!(recovered.verdict, "deny");
        assert_eq!(recovered.residual, 42.5);
        assert_eq!(recovered.top_fields.len(), 2);
        assert_eq!(recovered.path, "/admin/../../../etc/passwd");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = DenialKey::generate();
        let key2 = DenialKey::generate();
        let ctx = sample_context();
        let token = seal(&ctx, &key1).unwrap();
        assert!(unseal(&token, &key2).is_err());
    }

    #[test]
    fn tampered_token_fails() {
        let key = DenialKey::generate();
        let ctx = sample_context();
        let token = seal(&ctx, &key).unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        if let Some(byte) = raw.last_mut() {
            *byte ^= 0xff;
        }
        let tampered = URL_SAFE_NO_PAD.encode(&raw);
        assert!(unseal(&tampered, &key).is_err());
    }

    #[test]
    fn token_is_url_safe_base64() {
        let key = DenialKey::generate();
        let ctx = sample_context();
        let token = seal(&ctx, &key).unwrap();
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        assert!(!token.contains('='));
    }

    #[test]
    fn empty_token_fails() {
        let key = DenialKey::generate();
        assert!(unseal("", &key).is_err());
    }

    #[test]
    fn rate_limit_context_roundtrip() {
        let key = DenialKey::generate();
        let ctx = DenialContext {
            verdict: "rate_limit".to_string(),
            residual: 15.2,
            threshold: 10.0,
            deny_threshold: 20.0,
            top_fields: vec![],
            src_ip: "192.168.1.1".to_string(),
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            query: None,
            user_agent: None,
            header_names: vec![],
            cookie_keys: vec![],
            concentration: 0.0,
            entropy: 0.0,
            gini: 0.0,
            timestamp_us: 1700000000000000,
        };
        let token = seal(&ctx, &key).unwrap();
        let recovered = unseal(&token, &key).unwrap();
        assert_eq!(recovered.verdict, "rate_limit");
        assert!(recovered.top_fields.is_empty());
    }
}
