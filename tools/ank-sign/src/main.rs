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

mod key_manager;
mod signer;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ank-sign")]
#[command(about = "Sign and verify Ankaios manifests with Ed25519", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 key pair
    GenerateKey {
        /// Key ID (e.g., production-key-2026)
        #[arg(short, long)]
        key_id: String,

        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
    },

    /// Sign a manifest file
    Sign {
        /// Path to YAML manifest to sign
        manifest: PathBuf,

        /// Path to private key PEM file
        #[arg(short, long)]
        key: PathBuf,

        /// Key ID to embed in signature
        #[arg(short = 'i', long)]
        key_id: String,

        /// Counter value for rollback protection (optional)
        #[arg(short, long)]
        counter: Option<u64>,

        /// Output file (default: overwrite input)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a signed manifest
    Verify {
        /// Path to signed manifest
        manifest: PathBuf,

        /// Path to public key PEM file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Extract signature information (without verifying)
    Info {
        /// Path to signed manifest
        manifest: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey { key_id, output_dir } => {
            key_manager::generate_keypair(&key_id, &output_dir)?;
            println!("✅ Generated keypair:");
            println!("   Private: {}/{}.pem", output_dir.display(), key_id);
            println!("   Public:  {}/{}.pub", output_dir.display(), key_id);
            println!();
            println!("⚠️  Keep the private key secure and never share it!");
        }

        Commands::Sign {
            manifest,
            key,
            key_id,
            counter,
            output,
        } => {
            let signed = signer::sign_manifest(&manifest, &key, &key_id, counter)?;
            let output_path = output.unwrap_or_else(|| manifest.clone());
            std::fs::write(&output_path, signed)?;
            println!("✅ Signed manifest: {}", output_path.display());
            println!("   Key ID: {}", key_id);
            if let Some(counter_value) = counter {
                println!("   Counter: {}", counter_value);
            } else {
                println!("   Counter: (none)");
            }
        }

        Commands::Verify { manifest, key } => {
            signer::verify_manifest(&manifest, &key)?;
            println!("✅ Signature valid");
        }

        Commands::Info { manifest } => {
            let info = signer::extract_signature_info(&manifest)?;
            println!("Signature Information:");
            println!("  Key ID: {}", info.key_id);
            if let Some(counter_value) = info.counter {
                println!("  Counter: {}", counter_value);
            } else {
                println!("  Counter: (none)");
            }
            println!("  Timestamp: {}", info.timestamp);

            // Convert timestamp to human-readable format
            if let Ok(duration) = std::time::UNIX_EPOCH.elapsed() {
                let current_time = duration.as_secs() as i64;
                let age_seconds = current_time - info.timestamp;

                if age_seconds >= 0 {
                    let hours = age_seconds / 3600;
                    let minutes = (age_seconds % 3600) / 60;
                    println!("  Age: {}h {}m ago", hours, minutes);
                } else {
                    println!("  Age: {} seconds in the future (clock skew?)", -age_seconds);
                }
            }
        }
    }

    Ok(())
}
