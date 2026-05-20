// Copyright (c) 2023 Elektrobit Automotive GmbH
//
// This program and the accompanying materials are made available under the
// terms of the Apache License, Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use common::secure_io::{secure_read, secure_write};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Counter state persisted to disk
#[derive(Debug, Serialize, Deserialize)]
struct CounterState {
    /// Per-source counter tracking (ephemeral connections)
    #[serde(default)]
    source_counters: HashMap<String, u64>,
    /// Per-key_id counter tracking (global replay protection)
    #[serde(default)]
    key_counters: HashMap<String, u64>,
}

/// Configuration policy for signature verification
#[derive(Debug, Clone)]
pub struct SignaturePolicy {
    /// Reject unsigned manifests if true
    pub require_signature: bool,
    /// Require counter field in signatures (if false, counter is optional)
    pub require_counter: bool,
    /// List of allowed key IDs (empty = accept any key_id)
    pub allowed_key_ids: Vec<String>,
    /// Minimum counter value (initial floor)
    pub min_counter: u64,
}

/// Parsed and verified signed YAML document
#[derive(Debug)]
pub struct SignedYamlDocument {
    /// The unsigned content (YAML before signature block)
    pub unsigned_content: String,
    /// Decoded signature bytes (used internally for verification)
    #[allow(dead_code)]
    pub signature: Vec<u8>,
    /// Which key signed this document
    pub key_id: String,
    /// Unix timestamp when signed (stored but not currently used for validation)
    #[allow(dead_code)]
    pub timestamp: i64,
    /// Monotonic counter for rollback protection (None if not present)
    pub counter: Option<u64>,
}

/// Signature validator with Ed25519 verification
pub struct SignatureValidator {
    /// Map of key_id -> Ed25519 public key
    public_keys: HashMap<String, Vec<u8>>,
    /// Map of source -> last seen counter for rollback protection (per-connection)
    source_counters: HashMap<String, u64>,
    /// Map of key_id -> highest counter seen for that key (global replay protection)
    key_counters: HashMap<String, u64>,
    /// Verification policy
    policy: SignaturePolicy,
    /// Path to counter state file
    counter_state_path: PathBuf,
}

/// Errors that can occur during signature verification
#[derive(Debug)]
pub enum SignatureError {
    /// No signature block found in YAML
    MissingSignature,
    /// Signature block format is invalid
    InvalidSignatureFormat,
    /// The key_id is not recognized (replaced by GenericVerificationFailure for timing attack mitigation)
    #[allow(dead_code)]
    UnknownKeyId(String),
    /// The key_id is not in the allowed list
    KeyIdNotAllowed(String),
    /// Ed25519 signature verification failed (replaced by GenericVerificationFailure for timing attack mitigation)
    #[allow(dead_code)]
    SignatureVerificationFailed,
    /// Generic verification failure (prevents timing attacks)
    GenericVerificationFailure,
    /// Counter rollback detected
    CounterRollback {
        current: u64,
        last_seen: u64,
        source: String,
    },
    /// Counter is required by policy but not present in signature
    CounterRequired,
    /// I/O error (file operations, counter persistence)
    IoError(String),
    /// YAML parsing error
    ParseError(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::MissingSignature => {
                write!(f, "No signature block found in YAML document")
            }
            SignatureError::InvalidSignatureFormat => {
                write!(f, "Signature block has invalid format")
            }
            SignatureError::UnknownKeyId(key_id) => {
                write!(f, "Unknown key ID: {}", key_id)
            }
            SignatureError::KeyIdNotAllowed(key_id) => {
                write!(f, "Key ID not in allowed list: {}", key_id)
            }
            SignatureError::SignatureVerificationFailed => {
                write!(f, "Ed25519 signature verification failed")
            }
            SignatureError::GenericVerificationFailure => {
                write!(f, "Signature verification failed")
            }
            SignatureError::CounterRollback {
                current,
                last_seen,
                source,
            } => {
                write!(
                    f,
                    "Counter rollback detected for source '{}': current={}, last_seen={}",
                    source, current, last_seen
                )
            }
            SignatureError::CounterRequired => {
                write!(f, "Counter is required by policy but signature has no counter")
            }
            SignatureError::IoError(msg) => write!(f, "I/O error: {}", msg),
            SignatureError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Signature block format in YAML
#[derive(Debug, Deserialize, Serialize)]
struct SignatureBlock {
    signature: String,
    key_id: String,
    timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    counter: Option<u64>,
}

const DEFAULT_COUNTER_STATE_PATH: &str = "/var/lib/ankaios/signature_counters.json";

impl SignatureValidator {
    /// Get the current verification policy
    pub fn policy(&self) -> &SignaturePolicy {
        &self.policy
    }

    /// Create a new signature validator from a keys directory
    ///
    /// Loads Ed25519 public keys from PEM files in the specified directory.
    /// Counter state is loaded from the counter state file if it exists.
    ///
    /// # Arguments
    /// * `keys_dir` - Path to directory containing *.pub PEM files
    /// * `policy` - Verification policy configuration
    ///
    /// Counter state path can be configured via ANKAIOS_COUNTER_STATE_PATH env var
    /// (defaults to /var/lib/ankaios/signature_counters.json)
    pub fn from_keys_directory(
        keys_dir: &Path,
        policy: SignaturePolicy,
    ) -> Result<Self, SignatureError> {
        let mut public_keys = HashMap::new();

        // Load public keys from directory
        if keys_dir.exists() {
            let entries = fs::read_dir(keys_dir)
                .map_err(|e| SignatureError::IoError(format!("Cannot read keys directory: {}", e)))?;

            for entry in entries {
                let entry = entry.map_err(|e| SignatureError::IoError(e.to_string()))?;
                let path = entry.path();

                // Only process .pub files
                if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                    let key_id = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| {
                            SignatureError::ParseError(format!("Invalid key filename: {:?}", path))
                        })?
                        .to_string();

                    let pem_content = fs::read_to_string(&path).map_err(|e| {
                        SignatureError::IoError(format!("Cannot read key file {:?}: {}", path, e))
                    })?;

                    let public_key_bytes = Self::parse_ed25519_public_key(&pem_content)?;
                    public_keys.insert(key_id.clone(), public_key_bytes);
                    log::info!("Loaded Ed25519 public key: {}", key_id);
                }
            }
        } else {
            log::warn!("Keys directory does not exist: {:?}", keys_dir);
        }

        // Load counter state from disk
        // Priority: ENV var, then default
        let counter_state_path = std::env::var("ANKAIOS_COUNTER_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_COUNTER_STATE_PATH));

        let mut validator = Self {
            public_keys,
            source_counters: HashMap::new(),
            key_counters: HashMap::new(),
            policy,
            counter_state_path,
        };

        if let Err(e) = validator.load_counters() {
            log::warn!("Failed to load counter state: {}. Starting with empty counters.", e);
        }

        Ok(validator)
    }

    /// Verify a signed YAML document
    ///
    /// # Arguments
    /// * `signed_yaml` - The complete signed YAML string (content + signature block)
    /// * `source` - Source identifier (e.g., "persistence:vehicle-123", "cli:user@laptop")
    ///
    /// # Returns
    /// `Ok(SignedYamlDocument)` if signature is valid, `Err(SignatureError)` otherwise
    pub fn verify_signed_yaml(
        &mut self,
        signed_yaml: &str,
        source: &str,
    ) -> Result<SignedYamlDocument, SignatureError> {
        // Extract signature block
        let (unsigned_content, sig_block) = Self::extract_signature_block(signed_yaml)?;

        // Check if key_id is in allowed list (if policy specifies)
        if !self.policy.allowed_key_ids.is_empty()
            && !self.policy.allowed_key_ids.contains(&sig_block.key_id)
        {
            return Err(SignatureError::KeyIdNotAllowed(sig_block.key_id));
        }

        // Verify Ed25519 signature
        self.verify_signature(&unsigned_content, &sig_block.signature, &sig_block.key_id)?;

        // Handle counter validation
        if let Some(counter) = sig_block.counter {
            // Counter is present - validate it
            self.check_counter(counter, &sig_block.key_id, source)?;
            // Update counters and persist
            self.source_counters.insert(source.to_string(), counter);
            // Update global key counter for replay protection
            self.key_counters.insert(sig_block.key_id.clone(), counter);
            self.save_counters()?;
        } else if self.policy.require_counter {
            // No counter but policy requires it
            return Err(SignatureError::CounterRequired);
        }
        // else: counter is optional and not present, which is fine

        // Decode signature bytes for return value
        let signature_bytes = BASE64_STANDARD.decode(&sig_block.signature)
            .map_err(|e| SignatureError::ParseError(format!("Invalid base64 signature: {}", e)))?;

        Ok(SignedYamlDocument {
            unsigned_content,
            signature: signature_bytes,
            key_id: sig_block.key_id,
            timestamp: sig_block.timestamp,
            counter: sig_block.counter,
        })
    }

    /// Extract signature block from signed YAML
    fn extract_signature_block(yaml: &str) -> Result<(String, SignatureBlock), SignatureError> {
        // Split on YAML document separator
        let parts: Vec<&str> = yaml.split("\n---\n").collect();

        if parts.len() < 2 {
            return Err(SignatureError::MissingSignature);
        }

        let unsigned_content = parts[0].to_string();
        let sig_block_yaml = parts[1];

        // Parse signature block
        log::debug!("Attempting to parse signature block:\n{}", sig_block_yaml);
        let sig_block: SignatureBlock = serde_yaml::from_str(sig_block_yaml)
            .map_err(|e| {
                log::error!("Failed to parse signature block: {}", e);
                log::error!("Signature block content:\n{}", sig_block_yaml);
                SignatureError::InvalidSignatureFormat
            })?;

        Ok((unsigned_content, sig_block))
    }

    /// Verify Ed25519 signature with constant-time error handling
    ///
    /// Uses GenericVerificationFailure for all errors to prevent timing attacks
    /// that could leak information about which keys exist or which step failed.
    fn verify_signature(
        &self,
        unsigned_content: &str,
        signature_base64: &str,
        key_id: &str,
    ) -> Result<(), SignatureError> {
        // Decode signature (constant-time)
        let signature_bytes = BASE64_STANDARD
            .decode(signature_base64)
            .map_err(|_| SignatureError::GenericVerificationFailure)?;

        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::GenericVerificationFailure)?;

        let signature = Signature::from_bytes(&signature_array);

        // Key lookup with constant-time comparison
        // Iterate through ALL keys to prevent timing leaks about which keys exist
        let mut found_key: Option<&Vec<u8>> = None;
        for (stored_key_id, public_key_bytes) in &self.public_keys {
            if Self::constant_time_eq(stored_key_id.as_bytes(), key_id.as_bytes()) {
                found_key = Some(public_key_bytes);
            }
        }

        let public_key_bytes = found_key.ok_or(SignatureError::GenericVerificationFailure)?;

        let public_key_array: [u8; 32] = public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::GenericVerificationFailure)?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|_| SignatureError::GenericVerificationFailure)?;

        // Signature verification (already constant-time in ed25519_dalek)
        verifying_key
            .verify(unsigned_content.as_bytes(), &signature)
            .map_err(|_| SignatureError::GenericVerificationFailure)?;

        Ok(())
    }

    /// Constant-time byte slice comparison
    ///
    /// Prevents timing attacks by always comparing all bytes,
    /// regardless of when a mismatch is found.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            diff |= byte_a ^ byte_b;
        }

        diff == 0
    }

    /// Check counter for rollback protection
    fn check_counter(&self, counter: u64, key_id: &str, source: &str) -> Result<(), SignatureError> {
        // Skip rollback checks for startup manifest - it's the baseline state
        // that gets loaded on every boot with the same counter
        if source == "startup-manifest" {
            return Ok(());
        }

        // Check against minimum counter
        if counter < self.policy.min_counter {
            return Err(SignatureError::CounterRollback {
                current: counter,
                last_seen: self.policy.min_counter,
                source: source.to_string(),
            });
        }

        // Check against highest counter seen for this key_id (global replay protection)
        if let Some(&last_seen) = self.key_counters.get(key_id) {
            if counter <= last_seen {
                return Err(SignatureError::CounterRollback {
                    current: counter,
                    last_seen,
                    source: format!("key:{}", key_id),
                });
            }
        }

        // Check against last seen counter for this source (per-connection tracking)
        if let Some(&last_seen) = self.source_counters.get(source) {
            if counter <= last_seen {
                return Err(SignatureError::CounterRollback {
                    current: counter,
                    last_seen,
                    source: source.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Persist counter state to disk with secure I/O
    ///
    /// Uses secure_write to prevent:
    /// - TOCTOU races (atomic write via temp file + rename)
    /// - Symlink attacks (O_NOFOLLOW on Unix)
    /// - Unauthorized access (0600 permissions)
    fn save_counters(&self) -> Result<(), SignatureError> {
        let state = CounterState {
            source_counters: self.source_counters.clone(),
            key_counters: self.key_counters.clone(),
        };

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| SignatureError::IoError(format!("Cannot serialize counters: {}", e)))?;

        secure_write(&self.counter_state_path, &json)
            .map_err(|e| SignatureError::IoError(format!("Cannot write counters: {}", e)))?;

        Ok(())
    }

    /// Load counter state from disk with secure I/O
    ///
    /// Uses secure_read to prevent symlink attacks (O_NOFOLLOW on Unix)
    fn load_counters(&mut self) -> Result<(), SignatureError> {
        if !self.counter_state_path.exists() {
            // File doesn't exist yet, start with empty counters
            return Ok(());
        }

        let json = secure_read(&self.counter_state_path)
            .map_err(|e| SignatureError::IoError(format!("Cannot read counters: {}", e)))?;

        let state: CounterState = serde_json::from_str(&json)
            .map_err(|e| SignatureError::IoError(format!("Cannot parse counters: {}", e)))?;

        self.source_counters = state.source_counters;
        self.key_counters = state.key_counters;

        Ok(())
    }

    /// Parse Ed25519 public key from PEM format
    fn parse_ed25519_public_key(pem_content: &str) -> Result<Vec<u8>, SignatureError> {
        // Simple PEM parser for Ed25519 public keys
        // Format: -----BEGIN PUBLIC KEY-----\nbase64...\n-----END PUBLIC KEY-----
        let lines: Vec<&str> = pem_content.lines().collect();

        let mut in_key = false;
        let mut base64_content = String::new();

        for line in lines {
            let trimmed = line.trim();
            if trimmed == "-----BEGIN PUBLIC KEY-----" {
                in_key = true;
                continue;
            }
            if trimmed == "-----END PUBLIC KEY-----" {
                break;
            }
            if in_key {
                base64_content.push_str(trimmed);
            }
        }

        if base64_content.is_empty() {
            return Err(SignatureError::ParseError(
                "No PEM content found".to_string(),
            ));
        }

        let der_bytes = BASE64_STANDARD.decode(&base64_content)
            .map_err(|e| SignatureError::ParseError(format!("Invalid base64 in PEM: {}", e)))?;

        // Extract raw Ed25519 key from DER encoding
        // DER format for Ed25519 public key has the actual key in the last 32 bytes
        if der_bytes.len() < PUBLIC_KEY_LENGTH {
            return Err(SignatureError::ParseError(format!(
                "PEM too short: expected at least {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                der_bytes.len()
            )));
        }

        // The last 32 bytes are the raw Ed25519 public key
        let key_bytes = der_bytes[der_bytes.len() - PUBLIC_KEY_LENGTH..].to_vec();

        Ok(key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    // Mutex to serialize tests that modify ANKAIOS_COUNTER_STATE_PATH environment variable
    // Environment variables are process-global, so concurrent tests that modify the same
    // env var will interfere with each other, causing intermittent failures.
    // Tests that set ANKAIOS_COUNTER_STATE_PATH must lock this mutex first.
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to serialize environment variable access across tests
    /// Returns a guard that holds the lock - tests must keep this alive during validator usage
    #[allow(dead_code)]
    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap()
    }

    fn create_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[
            157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196,
            068, 073, 197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
        ]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_signed_yaml(
        content: &str,
        signing_key: &SigningKey,
        key_id: &str,
        counter: Option<u64>,
    ) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Sign the content exactly as it will be extracted (after split on "\n---\n")
        // The content should NOT include the trailing "\n" that's part of the separator
        let content_to_sign = content.trim_end_matches('\n');
        let signature = signing_key.sign(content_to_sign.as_bytes());
        let signature_base64 = BASE64_STANDARD.encode(signature.to_bytes());

        // Format the full signed YAML (counter is optional)
        // Include a newline before --- to match typical YAML document format
        if let Some(counter_value) = counter {
            format!(
                "{}\n---\nsignature: {}\nkey_id: {}\ntimestamp: {}\ncounter: {}\n",
                content_to_sign, signature_base64, key_id, timestamp, counter_value
            )
        } else {
            format!(
                "{}\n---\nsignature: {}\nkey_id: {}\ntimestamp: {}\n",
                content_to_sign, signature_base64, key_id, timestamp
            )
        }
    }

    fn setup_test_keys(temp_dir: &Path, verifying_key: &VerifyingKey, key_id: &str) {
        let key_bytes = verifying_key.to_bytes();
        let der_encoded = [
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ][..],
            &key_bytes[..],
        ]
        .concat();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64_STANDARD.encode(&der_encoded)
        );

        std::fs::write(temp_dir.join(format!("{}.pub", key_id)), pem).unwrap();
    }

    #[test]
    fn test_signature_validator_creation() {
        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec!["test-key".to_string()],
            min_counter: 0,
        };

        let validator = SignatureValidator::from_keys_directory(Path::new("/tmp"), policy);
        assert!(validator.is_ok());
    }

    #[test]
    fn test_extract_signature_block_valid() {
        let signed_yaml = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
---
signature: dGVzdA==
key_id: test-key
timestamp: 1234567890
counter: 42
"#;

        let result = SignatureValidator::extract_signature_block(signed_yaml);
        assert!(result.is_ok());

        let (unsigned, sig_block) = result.unwrap();
        assert!(unsigned.contains("apiVersion: v1"));
        assert_eq!(sig_block.key_id, "test-key");
        assert_eq!(sig_block.timestamp, 1234567890);
        assert_eq!(sig_block.counter, Some(42));
    }

    #[test]
    fn test_extract_signature_block_missing() {
        let unsigned_yaml = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
"#;

        let result = SignatureValidator::extract_signature_block(unsigned_yaml);
        assert!(matches!(result, Err(SignatureError::MissingSignature)));
    }

    #[test]
    fn test_verify_valid_signature() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(1));

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec![],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        let result = validator.verify_signed_yaml(&signed_yaml, "test-source");
        if let Err(ref e) = result {
            eprintln!("Verification error: {:?}", e);
        }
        assert!(result.is_ok());

        let doc = result.unwrap();
        assert_eq!(doc.key_id, "test-key");
        assert_eq!(doc.counter, Some(1));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (_, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        // Create a valid signature for different content (tampering scenario)
        let wrong_content = "different content\n";
        let (signing_key, _) = create_test_keypair();
        let wrong_signature = signing_key.sign(wrong_content.as_bytes());
        let wrong_signature_base64 = BASE64_STANDARD.encode(wrong_signature.to_bytes());

        // Use that signature with different content (should fail verification)
        let signed_yaml = format!(
            r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
---
signature: {}
key_id: test-key
timestamp: 1234567890
counter: 1
"#,
            wrong_signature_base64
        );

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec![],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        let result = validator.verify_signed_yaml(&signed_yaml, "test-source");
        if let Err(ref e) = result {
            eprintln!("Invalid signature test error: {:?}", e);
        }
        assert!(matches!(
            result,
            Err(SignatureError::GenericVerificationFailure)
        ));
    }

    #[test]
    fn test_counter_rollback_detection() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec![],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        // Verify with counter=2
        let signed_yaml_2 = create_signed_yaml(content, &signing_key, "test-key", Some(2));
        assert!(validator
            .verify_signed_yaml(&signed_yaml_2, "test-source")
            .is_ok());

        // Try to verify with counter=1 (rollback)
        let signed_yaml_1 = create_signed_yaml(content, &signing_key, "test-key", Some(1));
        let result = validator.verify_signed_yaml(&signed_yaml_1, "test-source");

        assert!(matches!(result, Err(SignatureError::CounterRollback { .. })));
    }

    #[test]
    fn test_allowed_key_ids() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(1));

        // Policy only allows "allowed-key"
        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec!["allowed-key".to_string()],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        let result = validator.verify_signed_yaml(&signed_yaml, "test-source");
        assert!(matches!(result, Err(SignatureError::KeyIdNotAllowed(_))));
    }

    #[test]
    fn test_per_source_counters() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
                        allowed_key_ids: vec![],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        // Source A with counter=5
        let signed_yaml_a = create_signed_yaml(content, &signing_key, "test-key", Some(5));
        assert!(validator
            .verify_signed_yaml(&signed_yaml_a, "source-a")
            .is_ok());

        // Source B with counter=6 should work (higher than global key counter)
        // Note: Global key counter prevents cross-source replay attacks
        let signed_yaml_b = create_signed_yaml(content, &signing_key, "test-key", Some(6));
        assert!(validator
            .verify_signed_yaml(&signed_yaml_b, "source-b")
            .is_ok());

        // Source A with counter=5 should fail (same as last seen for source-a)
        let signed_yaml_a2 = create_signed_yaml(content, &signing_key, "test-key", Some(5));
        let result = validator.verify_signed_yaml(&signed_yaml_a2, "source-a");
        assert!(matches!(result, Err(SignatureError::CounterRollback { .. })));
    }

    #[test]
    fn test_parse_ed25519_public_key() {
        let pem = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBb2+pDT1P8OD0ywCXGMjSx9E9bhI=
-----END PUBLIC KEY-----"#;

        let result = SignatureValidator::parse_ed25519_public_key(pem);
        assert!(result.is_ok());

        let key_bytes = result.unwrap();
        assert_eq!(key_bytes.len(), 32);
    }

    // CRITICAL SECURITY TEST: Counter persistence
    #[test]
    fn test_counter_persistence_save_and_load() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let counter_path = temp_dir.path().join("counters.json");

        // First validator: verify counter=5
        {
            let policy = SignaturePolicy {
                require_signature: true,
            require_counter: false,
                allowed_key_ids: vec![],
                min_counter: 0,
            };

            unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy.clone()).unwrap();

            let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(5));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-a").is_ok());

            // Counter should be persisted automatically
            // Force save to ensure it's written before next validator loads
            validator.save_counters().expect("Failed to save counters");
        }

        // Second validator: load from disk, counter=4 should fail
        {
            let policy = SignaturePolicy {
                require_signature: true,
            require_counter: false,
                allowed_key_ids: vec![],
                min_counter: 0,
            };

            unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(4));
            let result = validator.verify_signed_yaml(&signed_yaml, "source-a");
            assert!(
                matches!(result, Err(SignatureError::CounterRollback { .. })),
                "Counter should be loaded from disk and reject rollback"
            );

            // Counter=6 should work
            let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(6));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-a").is_ok());
        }
    }

    #[test]
    fn test_counter_file_corruption_recovery() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let counter_path = temp_dir.path().join("counters.json");

        // Write corrupted counter file
        std::fs::write(&counter_path, "{ invalid json }").unwrap();

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
            allowed_key_ids: vec![],
            min_counter: 0,
        };

        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

        // Should recover gracefully (start with empty counters)
        let signed_yaml = create_signed_yaml(content, &signing_key, "test-key", Some(1));
        assert!(
            validator.verify_signed_yaml(&signed_yaml, "source-a").is_ok(),
            "Should recover from corrupted counter file"
        );
    }

    // CRITICAL OPERATIONAL TEST: Key rotation
    #[test]
    fn test_key_rotation_workflow() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key_1, verifying_key_1) = create_test_keypair();
        let (signing_key_2, verifying_key_2) = create_test_keypair();

        // Setup two keys
        setup_test_keys(temp_dir.path(), &verifying_key_1, "key-2025");
        setup_test_keys(temp_dir.path(), &verifying_key_2, "key-2026");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }

        // Phase 1: Only key-2025 allowed
        {
            let policy = SignaturePolicy {
                require_signature: true,
            require_counter: false,
                allowed_key_ids: vec!["key-2025".to_string()],
                min_counter: 0,
            };

            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            // Signature with key-2025 should work
            let signed_yaml = create_signed_yaml(content, &signing_key_1, "key-2025", Some(1));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-a").is_ok());

            // Signature with key-2026 should fail
            let signed_yaml = create_signed_yaml(content, &signing_key_2, "key-2026", Some(1));
            let result = validator.verify_signed_yaml(&signed_yaml, "source-a");
            assert!(
                matches!(result, Err(SignatureError::KeyIdNotAllowed(_))),
                "key-2026 should not be allowed yet"
            );
        }

        // Phase 2: Both keys allowed (rotation period)
        {
            let policy = SignaturePolicy {
                require_signature: true,
            require_counter: false,
                allowed_key_ids: vec!["key-2025".to_string(), "key-2026".to_string()],
                min_counter: 0,
            };

            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            // Both keys should work
            let signed_yaml = create_signed_yaml(content, &signing_key_1, "key-2025", Some(2));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-a").is_ok());

            let signed_yaml = create_signed_yaml(content, &signing_key_2, "key-2026", Some(2));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-b").is_ok());
        }

        // Phase 3: Only key-2026 allowed (old key removed)
        {
            let policy = SignaturePolicy {
                require_signature: true,
            require_counter: false,
                allowed_key_ids: vec!["key-2026".to_string()],
                min_counter: 0,
            };

            unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            // Signature with key-2025 should now fail
            let signed_yaml = create_signed_yaml(content, &signing_key_1, "key-2025", Some(3));
            let result = validator.verify_signed_yaml(&signed_yaml, "source-a");
            assert!(
                matches!(result, Err(SignatureError::KeyIdNotAllowed(_))),
                "key-2025 should be rejected after rotation"
            );

            // Signature with key-2026 should work
            let signed_yaml = create_signed_yaml(content, &signing_key_2, "key-2026", Some(3));
            assert!(validator.verify_signed_yaml(&signed_yaml, "source-b").is_ok());
        }
    }

    // CRITICAL INTEGRATION TEST: End-to-end with real Ed25519 cryptography
    #[test]
    fn test_real_ed25519_end_to_end_integration() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();

        // Setup validator with real Ed25519 key
        setup_test_keys(temp_dir.path(), &verifying_key, "real-key");

        // Create realistic manifest content
        let manifest = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n    agent: agent_A\n    runtimeConfig: |\n      image: nginx:latest\n  redis:\n    runtime: podman\n    agent: agent_B\n    runtimeConfig: |\n      image: redis:7.0";

        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
            allowed_key_ids: vec!["real-key".to_string()],
            min_counter: 0,
        };

        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }
        let mut validator =
            SignatureValidator::from_keys_directory(temp_dir.path(), policy)
                .unwrap();

        // CRITICAL: Real Ed25519 verification with helper function
        let signed_yaml = create_signed_yaml(manifest, &signing_key, "real-key", Some(1));

        let result = validator.verify_signed_yaml(&signed_yaml, "test-source");
        assert!(
            result.is_ok(),
            "Real Ed25519 signature verification failed: {:?}",
            result
        );

        let verified = result.unwrap();
        assert_eq!(verified.key_id, "real-key");
        assert_eq!(verified.counter, Some(1));

        // SECURITY: Tampering detection with real cryptography
        let tampered = signed_yaml.replace("nginx:latest", "malicious:backdoor");
        let tampered_result = validator.verify_signed_yaml(&tampered, "test-source");
        assert!(
            matches!(tampered_result, Err(SignatureError::GenericVerificationFailure)),
            "Tampered signature should fail cryptographic verification"
        );

        // SECURITY: Replay attack prevention (counter)
        // Try to reuse counter=1 (should fail because we already saw it)
        let replay_yaml = create_signed_yaml(manifest, &signing_key, "real-key", Some(1));
        let replay_result = validator.verify_signed_yaml(&replay_yaml, "test-source");
        assert!(
            matches!(replay_result, Err(SignatureError::CounterRollback { .. })),
            "Replay with same counter should be rejected"
        );

        // SECURITY: Counter increment works
        let counter_2_yaml = create_signed_yaml(manifest, &signing_key, "real-key", Some(2));
        let result_2 = validator.verify_signed_yaml(&counter_2_yaml, "test-source");
        assert!(
            result_2.is_ok(),
            "Counter increment should succeed: {:?}",
            result_2
        );

        // SECURITY: Wrong key detection
        // Create a different keypair (simulates attacker with different key)
        let wrong_signing_key = SigningKey::from_bytes(&[
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        ]);
        let wrong_key_yaml = create_signed_yaml(manifest, &wrong_signing_key, "real-key", Some(3));

        let wrong_key_result = validator.verify_signed_yaml(&wrong_key_yaml, "test-source");
        assert!(
            matches!(wrong_key_result, Err(SignatureError::GenericVerificationFailure)),
            "Signature with wrong key should fail verification"
        );
    }

    // FEATURE TEST: Optional counter support
    #[test]
    fn test_optional_counter_support() {
        let _guard = lock_env(); // Serialize env var access
        let temp_dir = TempDir::new().unwrap();
        let (signing_key, verifying_key) = create_test_keypair();
        setup_test_keys(temp_dir.path(), &verifying_key, "test-key");

        let content = "apiVersion: v1\nworkloads:\n  nginx:\n    runtime: podman\n";
        let counter_path = temp_dir.path().join("counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_path); }

        // Test 1: Counter optional (require_counter: false)
        {
            let policy = SignaturePolicy {
                require_signature: true,
                require_counter: false,
                allowed_key_ids: vec![],
                min_counter: 0,
            };

            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            // Signature without counter should work
            let signed_no_counter = create_signed_yaml(content, &signing_key, "test-key", None);
            let result = validator.verify_signed_yaml(&signed_no_counter, "startup-manifest");
            assert!(
                result.is_ok(),
                "Signature without counter should succeed when counter is optional"
            );
            assert_eq!(result.unwrap().counter, None, "Counter should be None");

            // Signature with counter should also work
            let signed_with_counter = create_signed_yaml(content, &signing_key, "test-key", Some(1));
            let result = validator.verify_signed_yaml(&signed_with_counter, "runtime-update");
            assert!(result.is_ok(), "Signature with counter should also work: {:?}", result);
            let verified = result.unwrap();
            assert_eq!(verified.counter, Some(1), "Counter should be Some(1)");
        }

        // Test 2: Counter required (require_counter: true)
        {
            let policy = SignaturePolicy {
                require_signature: true,
                require_counter: true,
                allowed_key_ids: vec![],
                min_counter: 0,
            };

            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            // Signature without counter should FAIL
            let signed_no_counter = create_signed_yaml(content, &signing_key, "test-key", None);
            let result = validator.verify_signed_yaml(&signed_no_counter, "update-source");
            assert!(
                matches!(result, Err(SignatureError::CounterRequired)),
                "Signature without counter should fail when counter is required"
            );

            // Signature with counter should work
            let signed_with_counter = create_signed_yaml(content, &signing_key, "test-key", Some(10));
            assert!(
                validator
                    .verify_signed_yaml(&signed_with_counter, "update-source")
                    .is_ok(),
                "Signature with counter should succeed"
            );
        }

        // Test 3: Verify counter-less signatures can be verified multiple times (idempotent)
        {
            let policy = SignaturePolicy {
                require_signature: true,
                require_counter: false,
                allowed_key_ids: vec![],
                min_counter: 0,
            };

            let mut validator =
                SignatureValidator::from_keys_directory(temp_dir.path(), policy).unwrap();

            let signed_no_counter = create_signed_yaml(content, &signing_key, "test-key", None);

            // Should succeed multiple times (no counter tracking)
            assert!(
                validator
                    .verify_signed_yaml(&signed_no_counter, "startup")
                    .is_ok(),
                "First verification should succeed"
            );
            assert!(
                validator
                    .verify_signed_yaml(&signed_no_counter, "startup")
                    .is_ok(),
                "Second verification should succeed (no replay detection without counter)"
            );
            assert!(
                validator
                    .verify_signed_yaml(&signed_no_counter, "startup")
                    .is_ok(),
                "Third verification should succeed (idempotent without counter)"
            );
        }
    }

    #[test]
    fn test_startup_manifest_signed_file_loads_successfully() {
        let _guard = lock_env(); // Serialize env var access
        // This test exercises the ACTUAL server startup path that was missing from test coverage:
        // 1. Read signed manifest from disk
        // 2. Verify signature
        // 3. Parse unsigned content as YAML
        // 4. Load into server state
        //
        // This catches the bug where we tried to parse the full signed YAML
        // (including signature block) which caused serde_yaml to fail with
        // "deserializing from YAML containing more than one document is not supported"

        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let keys_dir = temp_dir.path().join("keys");

        fs::create_dir_all(&keys_dir).expect("Failed to create keys directory");

        // Step 1: Use existing test keypair
        let (signing_key, verifying_key) = create_test_keypair();

        // Save public key in PEM format using the helper function
        setup_test_keys(&keys_dir, &verifying_key, "startup-key-2026");

        // Step 2: Create unsigned manifest content
        let unsigned_content = r#"apiVersion: v1
workloads:
  nginx-startup:
    runtime: podman
    agent: agent_A
    tags:
      - key: owner
        value: test
    runtimeConfig: |
      image: nginx:latest
      commandOptions: ["-p", "8080:80"]
configs:
  database-config:
    config: |
      host=localhost
      port=5432
"#;

        // Step 3: Sign the manifest using helper function
        let signed_content = create_signed_yaml(
            unsigned_content,
            &signing_key,
            "startup-key-2026",
            Some(1), // counter
        );

        // Step 5: Verify the signature using SignatureValidator (what the server does)
        let policy = SignaturePolicy {
            require_signature: true,
            require_counter: false,
            allowed_key_ids: vec!["startup-key-2026".to_string()],
            min_counter: 0,
        };

        // Use temp directory for counter state (not /var/lib/ankaios/)
        let counter_state_path = temp_dir.path().join("signature_counters.json");
        unsafe { std::env::set_var("ANKAIOS_COUNTER_STATE_PATH", &counter_state_path); }

        let mut validator = SignatureValidator::from_keys_directory(
            &keys_dir,
            policy,
        )
        .expect("Failed to create signature validator");

        let verified_doc = validator
            .verify_signed_yaml(&signed_content, "startup-manifest")
            .expect("Signature verification failed");

        assert_eq!(verified_doc.key_id, "startup-key-2026");
        assert_eq!(verified_doc.counter, Some(1));

        // Step 6: THE CRITICAL TEST - Parse the UNSIGNED content (not the full signed YAML)
        // This is what the server MUST do to avoid the multi-document YAML error

        // WRONG WAY (what the bug was):
        // let state: StateSpec = serde_yaml::from_str(&signed_content).expect("...");
        // This fails with: "deserializing from YAML containing more than one document is not supported"

        // RIGHT WAY (the fix):
        let unsigned_content_from_verification = &verified_doc.unsigned_content;

        #[derive(serde::Deserialize, Debug)]
        struct StateSpec {
            #[serde(rename = "apiVersion")]
            api_version: String,
            workloads: Option<serde_yaml::Value>,
            configs: Option<serde_yaml::Value>,
        }

        let state: StateSpec = serde_yaml::from_str(unsigned_content_from_verification)
            .expect("Failed to parse unsigned content - this is the bug we're testing for!");

        // Step 7: Verify the parsed state contains expected data
        assert_eq!(state.api_version, "v1", "API version should be v1");
        assert!(state.workloads.is_some(), "Workloads should be present");
        assert!(state.configs.is_some(), "Configs should be present");

        let workloads = state.workloads.as_ref().unwrap();
        assert!(
            workloads.get("nginx-startup").is_some(),
            "nginx-startup workload should be present"
        );

        let configs = state.configs.as_ref().unwrap();
        assert!(
            configs.get("database-config").is_some(),
            "database-config should be present"
        );

        // Step 8: Verify that trying to parse the FULL signed YAML fails
        // (demonstrating why the fix was necessary)
        let parse_result: Result<StateSpec, _> = serde_yaml::from_str(&signed_content);
        assert!(
            parse_result.is_err(),
            "Parsing full signed YAML should fail (multi-document not supported)"
        );

        if let Err(e) = parse_result {
            let error_msg = e.to_string();
            assert!(
                error_msg.contains("more than one document")
                    || error_msg.contains("unexpected content"),
                "Error should mention multi-document issue, got: {}",
                error_msg
            );
        }
    }
}
