*** Settings ***
Documentation    Signature utility keywords for Ankaios E2E testing
Library          OperatingSystem
Library          Process
Library          Collections

*** Variables ***
${RESOURCES_DIR}    ${CURDIR}
${ANKAIOS_TARGET}        %{ANKAIOS_TARGET=x86_64-unknown-linux-gnu}
${ANKAIOS_BIN_DIR}       ${CURDIR}/../../target/${ANKAIOS_TARGET}/release

*** Keywords ***
Verify Test Environment
    [Documentation]    Verify that all required binaries and images exist before running tests

    # Check for all required binaries
    File Should Exist    ${ANKAIOS_BIN_DIR}/ank-server
    ...    msg=ank-server binary not found. Run: cargo build --release --target ${ANKAIOS_TARGET} -p ank-server

    File Should Exist    ${ANKAIOS_BIN_DIR}/ank-agent
    ...    msg=ank-agent binary not found. Run: cargo build --release --target ${ANKAIOS_TARGET} -p ank-agent

    File Should Exist    ${ANKAIOS_BIN_DIR}/ank
    ...    msg=ank binary not found. Run: cargo build --release --target ${ANKAIOS_TARGET} -p ank

    File Should Exist    ${ANKAIOS_BIN_DIR}/ank-sign
    ...    msg=ank-sign binary not found. Run: cargo build --release --target ${ANKAIOS_TARGET} -p ank-sign

    # Check for persistence plugin container image
    ${persist_image_check}=    Run Process    podman    images    -q    localhost/ank-persist:test    shell=False
    Should Not Be Empty    ${persist_image_check.stdout}
    ...    msg=Persistence plugin image not found. Run: podman build -t localhost/ank-persist:test -f examples/plugins/basic_persistency/Containerfile .

    # Check for fleet connector container image
    ${fleet_image_check}=    Run Process    podman    images    -q    localhost/fleet-connector:test    shell=False
    Should Not Be Empty    ${fleet_image_check.stdout}
    ...    msg=Fleet connector image not found. Run: podman build -t localhost/fleet-connector:test -f tools/tutorials/fleet_management/fleet-connector/Dockerfile tools/tutorials/fleet_management/fleet-connector

    Log    ✅ Test environment verified: all binaries and images found

Build Persistence Plugin Container
    [Documentation]    Build the persistence plugin container image for E2E testing

    Log    Building persistence plugin container image...

    # Use EXECDIR to reference repo root (where robot was executed from)
    ${result}=    Run Process
    ...    podman    build
    ...    -t    localhost/ank-persist:test
    ...    -f    examples/plugins/basic_persistency/Dockerfile
    ...    .
    ...    cwd=${EXECDIR}
    ...    timeout=300s

    Should Be Equal As Integers    ${result.rc}    0
    ...    msg=Failed to build persistence plugin container: ${result.stderr}

    Log    Persistence plugin container image built: localhost/ank-persist:test

Generate Ed25519 Keypair
    [Arguments]    ${key_id}    ${output_dir}
    [Documentation]    Generate Ed25519 keypair using ank-sign

    Create Directory    ${output_dir}

    ${result}=    Run Process
    ...    ${ANKAIOS_BIN_DIR}/ank-sign    generate-key    --key-id    ${key_id}    --output-dir    ${output_dir}
    ...    shell=False
    Should Be Equal As Integers    ${result.rc}    0    msg=Keypair generation failed: ${result.stderr}

    Should Exist    ${output_dir}/${key_id}.pem
    Should Exist    ${output_dir}/${key_id}.pub

    Log    Generated keypair: ${key_id}

Sign Manifest
    [Arguments]    ${manifest_path}    ${private_key_path}    ${counter}
    [Documentation]    Sign YAML manifest with Ed25519 signature using ank-sign

    # Extract key_id from filename (e.g., /tmp/keys/test-key.pem -> test-key)
    ${key_id}=    Run Process    basename    ${private_key_path}    .pem    shell=False
    ${key_id}=    Set Variable    ${key_id.stdout.strip()}

    ${result}=    Run Process
    ...    ${ANKAIOS_BIN_DIR}/ank-sign    sign    ${manifest_path}
    ...    --key    ${private_key_path}
    ...    --key-id    ${key_id}
    ...    --counter    ${counter}
    ...    shell=False

    Should Be Equal As Integers    ${result.rc}    0    msg=Signing failed: ${result.stderr}

    Log    Signed manifest: ${manifest_path} with counter=${counter}

Verify Manifest Signature
    [Arguments]    ${manifest_path}    ${public_key_path}
    [Documentation]    Verify Ed25519 signature on manifest using ank-sign

    ${result}=    Run Process
    ...    ${ANKAIOS_BIN_DIR}/ank-sign    verify    ${manifest_path}
    ...    --key    ${public_key_path}
    ...    shell=False

    Return From Keyword If    ${result.rc} == 0    VALID
    Return From Keyword    INVALID

Start Ankaios Server
    [Arguments]    ${signature_verification_enabled}=${False}    ${require_signature}=${False}    ${keys_dir}=/tmp/test-keys    ${persistence_plugin}=${False}    ${workloads_dir}=/tmp/ankaios-test/workloads
    [Documentation]    Start ank-server with signature verification config

    # Convert booleans to lowercase strings for TOML
    ${sig_enabled_str}=    Evaluate    str(${signature_verification_enabled}).lower()
    ${sig_required_str}=    Evaluate    str(${require_signature}).lower()

    # Get parent directory of workloads_dir for persistence file path
    ${test_dir}=    Evaluate    str(pathlib.Path("${workloads_dir}").parent)    modules=pathlib

    # Use test_dir for all temporary files
    ${config_file}=    Set Variable    ${test_dir}/ank-server.conf
    ${startup_file}=    Set Variable    ${test_dir}/startup.yaml
    ${server_log}=    Set Variable    ${test_dir}/ankaios-server.log
    ${agent_log}=    Set Variable    ${test_dir}/ankaios-agent.log
    ${counter_state}=    Set Variable    ${test_dir}/signature-counters.json

    # Create temp config file
    ${config}=    Catenate    SEPARATOR=\n
    ...    version = "v1"
    ...    startup_manifest = "${startup_file}"
    ...    [signature_verification]
    ...    enabled = ${sig_enabled_str}
    ...    require_signature = ${sig_required_str}
    ...    keys_directory = "${keys_dir}"

    Create File    ${config_file}    ${config}

    # Create startup manifest (with or without persistence plugin)
    Run Keyword If    ${persistence_plugin}
    ...    Create Startup Manifest With Persistence Plugin    ${test_dir}    ${startup_file}
    ...    ELSE
    ...    Create Startup Manifest Without Persistence    ${startup_file}

    # Sign startup manifest if signature verification is enabled
    Run Keyword If    ${signature_verification_enabled}
    ...    Sign Startup Manifest    ${keys_dir}    ${startup_file}

    # Start server process (with --insecure for test environment)
    # Set counter state path to test directory for isolation
    Start Process    ${ANKAIOS_BIN_DIR}/ank-server    --server-config    ${config_file}    --insecure
    ...    alias=ankaios-server    stdout=${server_log}    stderr=STDOUT
    ...    env:ANKAIOS_COUNTER_STATE_PATH=${counter_state}

    Sleep    2s    reason=Wait for server to initialize

    # Start agent process (needed to run workloads, --insecure for test environment)
    Start Process    ${ANKAIOS_BIN_DIR}/ank-agent    --name    agent_A    --insecure
    ...    alias=ankaios-agent    stdout=${agent_log}    stderr=STDOUT

    Sleep    2s    reason=Wait for agent to connect and register

    # If persistence plugin is enabled, wait for it to start and be ready
    Run Keyword If    ${persistence_plugin}    Wait For Persistence Plugin To Be Ready

    Log    Ankaios server and agent started with signature_verification=${signature_verification_enabled}

Create Startup Manifest Without Persistence
    [Arguments]    ${startup_file}
    [Documentation]    Create minimal startup manifest

    ${manifest}=    Catenate    SEPARATOR=\n
    ...    apiVersion: v1
    ...    workloads: {}

    Create File    ${startup_file}    ${manifest}

Sign Startup Manifest
    [Arguments]    ${keys_dir}    ${startup_file}
    [Documentation]    Sign the startup manifest with most recently generated key

    # Get last .pem key file (most recently generated in this test)
    ${key_files}=    List Files In Directory    ${keys_dir}    *.pem
    ${key_count}=    Get Length    ${key_files}
    ${last_index}=    Evaluate    ${key_count} - 1
    ${last_key}=    Get From List    ${key_files}    ${last_index}
    ${key_path}=    Set Variable    ${keys_dir}/${last_key}

    # Sign the startup manifest
    Sign Manifest    ${startup_file}    ${key_path}    0

    Log    Signed startup manifest with ${last_key}

Create Startup Manifest With Persistence Plugin
    [Arguments]    ${test_dir}    ${startup_file}
    [Documentation]    Create startup manifest that includes persistence plugin as workload

    # Create workloads directory inside test_dir
    Create Directory    ${test_dir}/workloads

    # Create manifest with persistence plugin workload using container image
    # Mount test_dir and set PERSISTENCE_FILE_PATH to derive workloads/ subdirectory
    ${manifest}=    Catenate    SEPARATOR=\n
    ...    apiVersion: v1
    ...    workloads:
    ...    ${SPACE}${SPACE}basic_persistency:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtime: podman
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}agent: agent_A
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtimeConfig: |
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}image: localhost/ank-persist:test
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}commandOptions: ["-v", "${test_dir}:${test_dir}:z", "-e", "PERSISTENCE_FILE_PATH=${test_dir}/runtime_state.yaml", "-e", "RUST_LOG=debug"]
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}controlInterfaceAccess:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}allowRules:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- type: StateRule
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}operation: ReadWrite
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}filterMasks:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- "desiredState.workloads.*"
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- "desiredState.configs.*"
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- "workloadStates.*.*.*.state"
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- "desiredState.configs"

    Create File    ${startup_file}    ${manifest}

    Log    Created startup manifest with persistence plugin container using test dir: ${test_dir}

Stop Ankaios Server
    [Documentation]    Stop the Ankaios server and agent

    ${result_agent}=    Terminate Process    ankaios-agent
    Run Keyword And Ignore Error    Log    Agent stopped with exit code: ${result_agent.rc}

    ${result_server}=    Terminate Process    ankaios-server
    Run Keyword And Ignore Error    Log    Server stopped with exit code: ${result_server.rc}

    # Force stop specific Ankaios containers (workloads and persistence plugin)
    # Using specific name patterns to avoid stopping unrelated containers
    Run Keyword And Ignore Error    Run Process    bash    -c    podman stop $(podman ps -q --filter name\=nginx-persistent) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman rm -f $(podman ps -aq --filter name\=nginx-persistent) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman stop $(podman ps -q --filter name\=mqtt) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman rm -f $(podman ps -aq --filter name\=mqtt) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman stop $(podman ps -q --filter name\=workload) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman rm -f $(podman ps -aq --filter name\=workload) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman stop $(podman ps -q --filter name\=basic_persistency) 2>/dev/null
    Run Keyword And Ignore Error    Run Process    bash    -c    podman rm -f $(podman ps -aq --filter name\=basic_persistency) 2>/dev/null

    Sleep    2s    reason=Wait for server port to be released and containers to fully stop

Wait For Persistence Plugin To Be Ready
    [Documentation]    Wait for persistence plugin to be running and ready to process events

    # Wait for plugin container to start
    Sleep    5s    reason=Wait for persistence plugin workload to start

    # Verify plugin is running
    ${workloads}=    Get Workloads
    Should Contain    ${workloads}    basic_persistency    msg=Persistence plugin workload should be running

    Log    Persistence plugin workload is running and ready

Start Persistence Plugin
    [Arguments]    ${test_dir}
    [Documentation]    Wait for persistence plugin workload to start
    ...    Plugin is deployed via startup manifest by Start Ankaios Server
    ...    This keyword just waits for it to be running

    Wait For Persistence Plugin To Be Ready

    Log    Persistence plugin workload is running, using dir: ${test_dir}/workloads

Stop Persistence Plugin
    [Documentation]    Stop the persistence plugin workload

    # Try graceful deletion via ank CLI first
    Run Keyword And Ignore Error    Run Process    ${ANKAIOS_BIN_DIR}/ank    --insecure    delete    workload    basic_persistency

    # Force stop any remaining containers (in case server was already stopped)
    ${containers}=    Run Process    podman    ps    -a    --filter    name\=basic_persistency    --format    {{.ID}}
    Run Keyword If    "${containers.stdout}" != ""    Run Process    podman    stop    ${containers.stdout}
    Run Keyword If    "${containers.stdout}" != ""    Run Process    podman    rm    ${containers.stdout}

    Log    Persistence plugin stopped

Apply Manifest
    [Arguments]    ${manifest_path}
    [Documentation]    Apply manifest via ank CLI. Fails only on actual apply errors (signature/policy), not on workload state timeouts.

    ${result}=    Run Process    ${ANKAIOS_BIN_DIR}/ank    --insecure    apply    ${manifest_path}
    ...    shell=False    timeout=10s

    Log    STDOUT: ${result.stdout}
    Log    STDERR: ${result.stderr}
    Log    Return Code: ${result.rc}

    # Check for signature/policy errors in stderr (these should fail the keyword)
    ${has_signature_error}=    Run Keyword And Return Status
    ...    Should Contain Any    ${result.stderr}
    ...    Signature required    signature verification failed    Counter rollback    Signature verification

    # Fail if there was a signature/policy error
    Run Keyword If    ${has_signature_error}
    ...    Fail    ank apply rejected manifest: ${result.stderr}

    RETURN    ${result.stdout}

Get Workloads
    [Documentation]    Get current workload list

    ${result}=    Run Process    ${ANKAIOS_BIN_DIR}/ank    --insecure    get    workloads    shell=False

    Log    Workloads: ${result.stdout}

    RETURN    ${result.stdout}

Delete Workload Signed
    [Arguments]    ${workload_name}    ${private_key_path}    ${counter}
    [Documentation]    Delete a workload using signed ank apply -d (delete mode)
    ...    Creates a signed manifest listing the workload to delete and uses apply -d flag

    ${manifest_path}=    Set Variable    /tmp/delete_${workload_name}.yaml

    # Create manifest listing the workload to delete
    # The manifest must include the workload spec for ank apply -d to know what to delete
    ${deletion_manifest}=    Catenate    SEPARATOR=\n
    ...    apiVersion: v1
    ...    workloads:
    ...    ${SPACE}${SPACE}${workload_name}:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtime: podman
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}agent: agent_A
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtimeConfig: ""

    Create File    ${manifest_path}    ${deletion_manifest}

    # Sign the deletion manifest
    Sign Manifest    ${manifest_path}    ${private_key_path}    ${counter}

    # Apply in delete mode with --insecure flag
    ${result}=    Run Process
    ...    ${ANKAIOS_BIN_DIR}/ank    --insecure    apply    -d    ${manifest_path}
    ...    shell=False    timeout=10s

    Log    Delete output: ${result.stdout}
    Log    Delete stderr: ${result.stderr}
    Log    Delete rc: ${result.rc}

    # Check for errors (signature/policy issues should fail)
    ${has_error}=    Run Keyword And Return Status
    ...    Should Contain Any    ${result.stderr}
    ...    Signature required    signature verification failed    Counter rollback

    Run Keyword If    ${has_error}
    ...    Fail    Signed deletion failed: ${result.stderr}

    # Clean up
    Remove File    ${manifest_path}

    Log    Deleted workload ${workload_name} using signed ank apply -d with counter=${counter}

Get Ankaios Server Logs
    [Documentation]    Read server logs

    ${logs}=    Get File    ${TEST_DIR}/ankaios-server.log
    RETURN    ${logs}

Get Persistence Plugin Logs
    [Documentation]    Read persistence plugin logs

    ${logs}=    Get File    /tmp/ank-persist.log
    RETURN    ${logs}

Cleanup Ankaios
    [Documentation]    Clean up all Ankaios processes

    Run Keyword And Ignore Error    Stop Ankaios Server
    Run Keyword And Ignore Error    Stop Persistence Plugin

    Log    Ankaios processes stopped
