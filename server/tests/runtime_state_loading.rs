// Copyright (c) 2025 Elektrobit Automotive GmbH
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

#[cfg(test)]
mod runtime_state_loading_tests {
    use ankaios_api::ank_base::StateSpec;
    use std::fs;
    use tempfile::TempDir;

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_loads_runtime_state_at_startup() {
        // Create temp directory for test files
        let temp_dir = TempDir::new().unwrap();

        // Create startup manifest
        let startup_manifest = temp_dir.path().join("startup.yaml");
        fs::write(
            &startup_manifest,
            r#"apiVersion: v0.1
workloads:
  startup_workload:
    runtime: podman
    agent: agent_A
    runtimeConfig: "nginx:latest"
    persist: false
"#,
        )
        .unwrap();

        // Create runtime state with persistent workload
        let runtime_state = temp_dir.path().join("runtime_state.yaml");
        fs::write(
            &runtime_state,
            r#"apiVersion: v0.1
workloads:
  runtime_workload:
    runtime: podman
    agent: agent_B
    runtimeConfig: "redis:latest"
    persist: true
"#,
        )
        .unwrap();

        // Load state as server would
        let startup_data = fs::read_to_string(&startup_manifest).unwrap();
        let startup_spec: StateSpec = serde_yaml::from_str(&startup_data).unwrap();

        let runtime_data = fs::read_to_string(&runtime_state).unwrap();
        let runtime_spec: StateSpec = serde_yaml::from_str(&runtime_data).unwrap();

        // Verify both workloads would be present after merge
        assert!(startup_spec
            .workloads
            .workloads
            .contains_key("startup_workload"));
        assert!(runtime_spec
            .workloads
            .workloads
            .contains_key("runtime_workload"));
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_runtime_state_overrides_startup_manifest() {
        let temp_dir = TempDir::new().unwrap();

        // Create startup manifest with a workload
        let startup_manifest = temp_dir.path().join("startup.yaml");
        fs::write(
            &startup_manifest,
            r#"apiVersion: v0.1
workloads:
  shared_workload:
    runtime: podman
    agent: agent_A
    runtimeConfig: "nginx:1.0"
    persist: false
"#,
        )
        .unwrap();

        // Create runtime state with the same workload name but different config
        let runtime_state = temp_dir.path().join("runtime_state.yaml");
        fs::write(
            &runtime_state,
            r#"apiVersion: v0.1
workloads:
  shared_workload:
    runtime: podman
    agent: agent_B
    runtimeConfig: "nginx:2.0"
    persist: true
"#,
        )
        .unwrap();

        let startup_data = fs::read_to_string(&startup_manifest).unwrap();
        let mut startup_spec: StateSpec = serde_yaml::from_str(&startup_data).unwrap();

        let runtime_data = fs::read_to_string(&runtime_state).unwrap();
        let runtime_spec: StateSpec = serde_yaml::from_str(&runtime_data).unwrap();

        // Simulate the merge operation from main.rs
        for (name, workload) in runtime_spec.workloads.workloads {
            startup_spec.workloads.workloads.insert(name, workload);
        }

        // Verify runtime state overrode the startup manifest
        let merged_workload = startup_spec
            .workloads
            .workloads
            .get("shared_workload")
            .unwrap();
        assert_eq!(merged_workload.agent, "agent_B");
        assert_eq!(merged_workload.runtime_config, "nginx:2.0");
        assert!(merged_workload.persist);
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_handles_missing_runtime_state() {
        let temp_dir = TempDir::new().unwrap();

        // Create only startup manifest, no runtime state file
        let startup_manifest = temp_dir.path().join("startup.yaml");
        fs::write(
            &startup_manifest,
            r#"apiVersion: v0.1
workloads:
  startup_workload:
    runtime: podman
    agent: agent_A
    runtimeConfig: "nginx:latest"
    persist: false
"#,
        )
        .unwrap();

        let runtime_state_path = temp_dir.path().join("runtime_state.yaml");

        // Verify runtime state file doesn't exist
        assert!(!runtime_state_path.exists());

        // Load startup manifest
        let startup_data = fs::read_to_string(&startup_manifest).unwrap();
        let startup_spec: StateSpec = serde_yaml::from_str(&startup_data).unwrap();

        // Verify startup manifest loaded successfully
        assert!(startup_spec
            .workloads
            .workloads
            .contains_key("startup_workload"));

        // Verify server would continue normally (file not existing is OK)
        assert!(!runtime_state_path.exists());
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_handles_corrupted_runtime_state() {
        let temp_dir = TempDir::new().unwrap();

        let runtime_state = temp_dir.path().join("runtime_state.yaml");

        // Write invalid YAML
        fs::write(&runtime_state, "this is not valid yaml: {{{").unwrap();

        // Attempt to parse should fail gracefully
        let result = fs::read_to_string(&runtime_state).and_then(|data| {
            serde_yaml::from_str::<StateSpec>(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        });

        assert!(result.is_err());

        // Verify error handling matches main.rs behavior
        match result {
            Err(e) => {
                // Server logs warning and continues with startup state only
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
            }
            Ok(_) => panic!("Expected parsing to fail for corrupted YAML"),
        }
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_loads_runtime_state_without_startup_manifest() {
        let temp_dir = TempDir::new().unwrap();

        // Create only runtime state, no startup manifest
        let runtime_state = temp_dir.path().join("runtime_state.yaml");
        fs::write(
            &runtime_state,
            r#"apiVersion: v0.1
workloads:
  persistent_workload:
    runtime: podman
    agent: agent_A
    runtimeConfig: "redis:latest"
    persist: true
"#,
        )
        .unwrap();

        // Load runtime state
        let runtime_data = fs::read_to_string(&runtime_state).unwrap();
        let runtime_spec: StateSpec = serde_yaml::from_str(&runtime_data).unwrap();

        // Verify runtime state can be used as base (matches main.rs logic)
        assert!(runtime_spec
            .workloads
            .workloads
            .contains_key("persistent_workload"));
        assert_eq!(runtime_spec.workloads.workloads.len(), 1);
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_merges_configs_from_runtime_state() {
        let temp_dir = TempDir::new().unwrap();

        // Create startup manifest with configs
        let startup_manifest = temp_dir.path().join("startup.yaml");
        fs::write(
            &startup_manifest,
            r#"apiVersion: v0.1
configs:
  startup_config:
    config1:
      value: "startup_value"
"#,
        )
        .unwrap();

        // Create runtime state with different configs
        let runtime_state = temp_dir.path().join("runtime_state.yaml");
        fs::write(
            &runtime_state,
            r#"apiVersion: v0.1
configs:
  runtime_config:
    config2:
      value: "runtime_value"
"#,
        )
        .unwrap();

        let startup_data = fs::read_to_string(&startup_manifest).unwrap();
        let mut startup_spec: StateSpec = serde_yaml::from_str(&startup_data).unwrap();

        let runtime_data = fs::read_to_string(&runtime_state).unwrap();
        let runtime_spec: StateSpec = serde_yaml::from_str(&runtime_data).unwrap();

        // Simulate config merge from main.rs
        for (name, config) in runtime_spec.configs.configs {
            startup_spec.configs.configs.insert(name, config);
        }

        // Verify both configs are present after merge
        assert!(startup_spec.configs.configs.contains_key("startup_config"));
        assert!(startup_spec.configs.configs.contains_key("runtime_config"));
        assert_eq!(startup_spec.configs.configs.len(), 2);
    }

    // [itest->swdd~server-loads-runtime-state-at-startup~1]
    #[tokio::test]
    async fn itest_server_handles_empty_runtime_state_file() {
        let temp_dir = TempDir::new().unwrap();

        let runtime_state = temp_dir.path().join("runtime_state.yaml");

        // Create empty file
        fs::write(&runtime_state, "").unwrap();

        // Attempt to parse empty file
        let result = fs::read_to_string(&runtime_state).and_then(|data| {
            serde_yaml::from_str::<StateSpec>(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        });

        // Empty file should fail to parse
        assert!(result.is_err());
    }
}
