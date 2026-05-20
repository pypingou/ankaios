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
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::key_manager::{parse_ed25519_private_key, parse_ed25519_public_key};

#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureInfo {
    pub signature: String,
    pub key_id: String,
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
}

pub fn sign_manifest(
    manifest_path: &Path,
    key_path: &Path,
    key_id: &str,
    counter: Option<u64>,
) -> anyhow::Result<String> {
    // Read manifest
    let yaml_content = fs::read_to_string(manifest_path)?;

    // Strip existing signature if present
    let unsigned_content = strip_signature_block(&yaml_content);

    // Read signing key
    let key_pem = fs::read_to_string(key_path)?;
    let signing_key = parse_ed25519_private_key(&key_pem)?;

    // Get timestamp
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // Sign the unsigned content (without trailing newline that will be added by separator)
    let content_to_sign = unsigned_content.trim_end_matches('\n');
    let signature = signing_key.sign(content_to_sign.as_bytes());

    // Build signature block (counter is optional)
    let signature_block = if let Some(counter_value) = counter {
        format!(
            "---\nsignature: {}\nkey_id: {}\ntimestamp: {}\ncounter: {}\n",
            BASE64_STANDARD.encode(signature.to_bytes()),
            key_id,
            timestamp,
            counter_value
        )
    } else {
        format!(
            "---\nsignature: {}\nkey_id: {}\ntimestamp: {}\n",
            BASE64_STANDARD.encode(signature.to_bytes()),
            key_id,
            timestamp
        )
    };

    // Combine (add newline before separator if content doesn't end with one)
    let result = if content_to_sign.is_empty() {
        signature_block
    } else {
        format!("{}\n{}", content_to_sign, signature_block)
    };

    Ok(result)
}

pub fn verify_manifest(manifest_path: &Path, pubkey_path: &Path) -> anyhow::Result<()> {
    let yaml_content = fs::read_to_string(manifest_path)?;
    let (unsigned, sig_block) = extract_signature_block(&yaml_content)?;

    let key_pem = fs::read_to_string(pubkey_path)?;
    let verifying_key = parse_ed25519_public_key(&key_pem)?;

    let sig_bytes = BASE64_STANDARD.decode(&sig_block.signature)?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?,
    );

    verifying_key
        .verify(unsigned.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;

    Ok(())
}

pub fn extract_signature_info(manifest_path: &Path) -> anyhow::Result<SignatureInfo> {
    let yaml_content = fs::read_to_string(manifest_path)?;
    let (_unsigned, sig_block) = extract_signature_block(&yaml_content)?;
    Ok(sig_block)
}

fn strip_signature_block(yaml: &str) -> String {
    yaml.split("\n---\n")
        .next()
        .unwrap_or(yaml)
        .to_string()
}

fn extract_signature_block(yaml: &str) -> anyhow::Result<(String, SignatureInfo)> {
    let parts: Vec<&str> = yaml.split("\n---\n").collect();

    if parts.len() < 2 {
        anyhow::bail!("No signature block found in YAML");
    }

    let unsigned = parts[0].to_string();
    let sig_block_yaml = parts[1];

    let sig_block: SignatureInfo = serde_yaml::from_str(sig_block_yaml)
        .map_err(|e| anyhow::anyhow!("Invalid signature block format: {}", e))?;

    Ok((unsigned, sig_block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::generate_keypair;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn setup_test_keypair(temp_dir: &Path) -> (PathBuf, PathBuf) {
        let key_id = "test-key";
        generate_keypair(key_id, temp_dir).unwrap();

        let private_path = temp_dir.join(format!("{}.pem", key_id));
        let public_path = temp_dir.join(format!("{}.pub", key_id));

        (private_path, public_path)
    }

    fn create_test_manifest(temp_dir: &Path) -> PathBuf {
        let manifest_path = temp_dir.join("test-manifest.yaml");
        let content = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
    agent: agent_A
    runtimeConfig: |
      image: nginx:latest
"#;
        fs::write(&manifest_path, content).unwrap();
        manifest_path
    }

    #[test]
    fn test_sign_manifest() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, _) = setup_test_keypair(temp_dir.path());
        let manifest = create_test_manifest(temp_dir.path());

        let signed = sign_manifest(&manifest, &private_key, "test-key", Some(42)).unwrap();

        // Check signature block is present
        assert!(signed.contains("---\n"));
        assert!(signed.contains("signature:"));
        assert!(signed.contains("key_id: test-key"));
        assert!(signed.contains("counter: 42"));
        assert!(signed.contains("timestamp:"));
    }

    #[test]
    fn test_sign_and_verify() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, public_key) = setup_test_keypair(temp_dir.path());
        let manifest = create_test_manifest(temp_dir.path());

        let signed = sign_manifest(&manifest, &private_key, "test-key", Some(1)).unwrap();

        // Write signed content
        let signed_path = temp_dir.path().join("signed.yaml");
        fs::write(&signed_path, signed).unwrap();

        // Verify should succeed
        assert!(verify_manifest(&signed_path, &public_key).is_ok());
    }

    #[test]
    fn test_verify_tampered_manifest() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, public_key) = setup_test_keypair(temp_dir.path());
        let manifest = create_test_manifest(temp_dir.path());

        let mut signed = sign_manifest(&manifest, &private_key, "test-key", Some(1)).unwrap();

        // Tamper with content
        signed = signed.replace("nginx:latest", "malicious:backdoor");

        let signed_path = temp_dir.path().join("tampered.yaml");
        fs::write(&signed_path, signed).unwrap();

        // Verify should fail
        assert!(verify_manifest(&signed_path, &public_key).is_err());
    }

    #[test]
    fn test_extract_signature_info() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, _) = setup_test_keypair(temp_dir.path());
        let manifest = create_test_manifest(temp_dir.path());

        let signed = sign_manifest(&manifest, &private_key, "test-key-2026", Some(42)).unwrap();

        let signed_path = temp_dir.path().join("signed.yaml");
        fs::write(&signed_path, signed).unwrap();

        let info = extract_signature_info(&signed_path).unwrap();

        assert_eq!(info.key_id, "test-key-2026");
        assert_eq!(info.counter, Some(42));
        assert!(info.timestamp > 0);
    }

    #[test]
    fn test_strip_signature_block() {
        let signed_yaml = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
---
signature: abc123
key_id: test
timestamp: 123456
counter: 1
"#;

        let stripped = strip_signature_block(signed_yaml);

        assert!(!stripped.contains("signature:"));
        assert!(stripped.contains("apiVersion: v1"));
        assert!(stripped.contains("nginx:"));
    }

    #[test]
    fn test_strip_unsigned_manifest() {
        let unsigned = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
"#;

        let stripped = strip_signature_block(unsigned);

        assert_eq!(stripped, unsigned);
    }

    #[test]
    fn test_extract_signature_block_missing() {
        let unsigned = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
"#;

        let result = extract_signature_block(unsigned);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No signature block"));
    }

    #[test]
    fn test_resign_manifest() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, public_key) = setup_test_keypair(temp_dir.path());
        let manifest = create_test_manifest(temp_dir.path());

        // Sign with counter=1
        let signed1 = sign_manifest(&manifest, &private_key, "test-key", Some(1)).unwrap();
        fs::write(&manifest, &signed1).unwrap();

        // Re-sign with counter=2 (should strip old signature)
        let signed2 = sign_manifest(&manifest, &private_key, "test-key", Some(2)).unwrap();

        let signed_path = temp_dir.path().join("signed2.yaml");
        fs::write(&signed_path, signed2).unwrap();

        // Verify new signature
        assert!(verify_manifest(&signed_path, &public_key).is_ok());

        // Check counter is updated
        let info = extract_signature_info(&signed_path).unwrap();
        assert_eq!(info.counter, Some(2));
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let temp_dir = TempDir::new().unwrap();

        // Generate two different keypairs
        let (private_key1, _) = setup_test_keypair(&temp_dir.path().join("key1"));
        let (_, public_key2) = setup_test_keypair(&temp_dir.path().join("key2"));

        let manifest = create_test_manifest(temp_dir.path());

        // Sign with key1
        let signed = sign_manifest(&manifest, &private_key1, "test-key", Some(1)).unwrap();
        let signed_path = temp_dir.path().join("signed.yaml");
        fs::write(&signed_path, signed).unwrap();

        // Verify with key2 should fail
        assert!(verify_manifest(&signed_path, &public_key2).is_err());
    }

    #[test]
    fn test_signature_preserves_yaml_structure() {
        let temp_dir = TempDir::new().unwrap();
        let (private_key, _) = setup_test_keypair(temp_dir.path());

        // Create manifest with specific formatting
        let manifest_path = temp_dir.path().join("test.yaml");
        let original_content = r#"apiVersion: v1
workloads:
  nginx:
    runtime: podman
    agent: agent_A
    tags:
      env: production
      team: platform"#;
        fs::write(&manifest_path, original_content).unwrap();

        let signed = sign_manifest(&manifest_path, &private_key, "test-key", Some(1)).unwrap();

        // Extract unsigned part
        let unsigned_part = signed.split("\n---\n").next().unwrap();

        // Should preserve original structure (minus trailing newline)
        assert_eq!(unsigned_part.trim(), original_content.trim());
    }
}

