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
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::Rng;
use std::fs;
use std::path::Path;

const ED25519_OID: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub fn generate_keypair(key_id: &str, output_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(output_dir)?;

    // Generate Ed25519 keypair
    let mut rng = rand::rng();
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = rng.random();
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Write private key
    let private_path = output_dir.join(format!("{}.pem", key_id));
    let private_pem = format_ed25519_private_key(&signing_key);
    fs::write(&private_path, private_pem)?;

    // Set secure permissions (0600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&private_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&private_path, perms)?;
    }

    // Write public key
    let public_path = output_dir.join(format!("{}.pub", key_id));
    let public_pem = format_ed25519_public_key(&verifying_key);
    fs::write(&public_path, public_pem)?;

    Ok(())
}

fn format_ed25519_private_key(key: &SigningKey) -> String {
    // PKCS#8 format for Ed25519 private key
    let key_bytes = key.to_bytes();

    // Build PKCS#8 structure
    let mut pkcs8 = Vec::new();

    // SEQUENCE
    pkcs8.extend_from_slice(&[0x30, 0x53]); // tag, length

    // version INTEGER 0
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x00]);

    // privateKeyAlgorithm AlgorithmIdentifier
    pkcs8.extend_from_slice(&[0x30, 0x05]); // SEQUENCE
    pkcs8.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID for Ed25519

    // privateKey OCTET STRING
    pkcs8.extend_from_slice(&[0x04, 0x22]); // OCTET STRING tag, length
    pkcs8.extend_from_slice(&[0x04, 0x20]); // inner OCTET STRING tag, length
    pkcs8.extend_from_slice(&key_bytes);

    // public key (optional, included for compatibility)
    let verifying_key = key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();
    pkcs8.extend_from_slice(&[0xa1, 0x23]); // context tag [1]
    pkcs8.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING
    pkcs8.extend_from_slice(&pub_bytes);

    let base64_content = BASE64_STANDARD.encode(&pkcs8);

    // Format as PEM with line breaks every 64 characters
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in base64_content.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    pem
}

fn format_ed25519_public_key(key: &VerifyingKey) -> String {
    let key_bytes = key.to_bytes();

    // Build DER structure for Ed25519 public key
    let mut der = Vec::new();
    der.extend_from_slice(ED25519_OID);
    der.extend_from_slice(&key_bytes);

    let base64_content = BASE64_STANDARD.encode(&der);

    // Format as PEM with line breaks every 64 characters
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64_content.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    pem
}

pub fn parse_ed25519_private_key(pem_content: &str) -> anyhow::Result<SigningKey> {
    let lines: Vec<&str> = pem_content.lines().collect();

    let mut in_key = false;
    let mut base64_content = String::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN PRIVATE KEY-----" {
            in_key = true;
            continue;
        }
        if trimmed == "-----END PRIVATE KEY-----" {
            break;
        }
        if in_key {
            base64_content.push_str(trimmed);
        }
    }

    if base64_content.is_empty() {
        anyhow::bail!("No PEM content found");
    }

    let der_bytes = BASE64_STANDARD.decode(&base64_content)?;

    // Parse PKCS#8 to extract the raw Ed25519 private key (32 bytes)
    // The key is nested: skip version, algorithm identifier, and OCTET STRING headers
    // Simplified parser: look for the 32-byte key after the inner OCTET STRING tag (0x04 0x20)
    for i in 0..der_bytes.len().saturating_sub(34) {
        if der_bytes[i] == 0x04 && der_bytes[i + 1] == 0x20 {
            let key_bytes: [u8; 32] = der_bytes[i + 2..i + 34]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
            return Ok(SigningKey::from_bytes(&key_bytes));
        }
    }

    anyhow::bail!("Could not parse Ed25519 private key from PKCS#8 format")
}

pub fn parse_ed25519_public_key(pem_content: &str) -> anyhow::Result<VerifyingKey> {
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
        anyhow::bail!("No PEM content found");
    }

    let der_bytes = BASE64_STANDARD.decode(&base64_content)?;

    // The last 32 bytes are the raw Ed25519 public key
    if der_bytes.len() < 32 {
        anyhow::bail!("PEM too short: expected at least 32 bytes, got {}", der_bytes.len());
    }

    let key_bytes: [u8; 32] = der_bytes[der_bytes.len() - 32..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_keypair() {
        let temp_dir = TempDir::new().unwrap();
        let key_id = "test-key";

        generate_keypair(key_id, temp_dir.path()).unwrap();

        // Check files exist
        let private_path = temp_dir.path().join(format!("{}.pem", key_id));
        let public_path = temp_dir.path().join(format!("{}.pub", key_id));
        assert!(private_path.exists());
        assert!(public_path.exists());

        // Check private key permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&private_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_keypair_format_and_parse() {
        let temp_dir = TempDir::new().unwrap();
        let key_id = "test-key";

        generate_keypair(key_id, temp_dir.path()).unwrap();

        let private_path = temp_dir.path().join(format!("{}.pem", key_id));
        let public_path = temp_dir.path().join(format!("{}.pub", key_id));

        // Parse the generated keys
        let private_pem = fs::read_to_string(&private_path).unwrap();
        let public_pem = fs::read_to_string(&public_path).unwrap();

        let signing_key = parse_ed25519_private_key(&private_pem).unwrap();
        let verifying_key = parse_ed25519_public_key(&public_pem).unwrap();

        // Verify they match
        assert_eq!(signing_key.verifying_key().to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn test_parse_invalid_private_key() {
        let invalid_pem = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----";
        assert!(parse_ed25519_private_key(invalid_pem).is_err());
    }

    #[test]
    fn test_parse_invalid_public_key() {
        let invalid_pem = "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----";
        assert!(parse_ed25519_public_key(invalid_pem).is_err());
    }

    #[test]
    fn test_parse_missing_pem_markers() {
        let no_markers = "SGVsbG8gV29ybGQ=";
        assert!(parse_ed25519_private_key(no_markers).is_err());
        assert!(parse_ed25519_public_key(no_markers).is_err());
    }

    #[test]
    fn test_format_ed25519_private_key_structure() {
        let mut rng = rand::rng();
        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = rng.random();
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);

        let pem = format_ed25519_private_key(&signing_key);

        // Check PEM structure
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(pem.lines().count() > 2);
    }

    #[test]
    fn test_format_ed25519_public_key_structure() {
        let mut rng = rand::rng();
        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = rng.random();
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let pem = format_ed25519_public_key(&verifying_key);

        // Check PEM structure
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(pem.lines().count() > 2);
    }

    #[test]
    fn test_roundtrip_private_key() {
        let mut rng = rand::rng();
        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = rng.random();
        let original_key = SigningKey::from_bytes(&secret_key_bytes);

        let pem = format_ed25519_private_key(&original_key);
        let parsed_key = parse_ed25519_private_key(&pem).unwrap();

        assert_eq!(original_key.to_bytes(), parsed_key.to_bytes());
    }

    #[test]
    fn test_roundtrip_public_key() {
        let mut rng = rand::rng();
        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = rng.random();
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let original_key = signing_key.verifying_key();

        let pem = format_ed25519_public_key(&original_key);
        let parsed_key = parse_ed25519_public_key(&pem).unwrap();

        assert_eq!(original_key.to_bytes(), parsed_key.to_bytes());
    }
}

