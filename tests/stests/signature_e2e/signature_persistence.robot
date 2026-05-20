*** Settings ***
Documentation    End-to-end tests for signature preservation through persistence plugin
Resource         ../../resources/signature_utils.resource
Library          OperatingSystem
Library          Process
Library          String
Suite Setup      Setup Test Run Directory
Suite Teardown   Run Keywords    Cleanup Ankaios    AND    Cleanup Test Run Directory

*** Variables ***
${TEST_RUN_ID}           ${EMPTY}
${KEYS_DIR}              ${EMPTY}
${TEST_DIR}              ${EMPTY}
${WORKLOADS_DIR}         ${EMPTY}
${FIXTURES_DIR}          ${CURDIR}/fixtures
${ANKAIOS_TARGET}        %{ANKAIOS_TARGET=x86_64-unknown-linux-gnu}
${ANKAIOS_BIN_DIR}       ${CURDIR}/../../../target/${ANKAIOS_TARGET}/release

*** Keywords ***
Setup Test Run Directory
    [Documentation]    Create unique test directory for this run and cleanup old containers

    # Verify environment before starting tests
    Verify Test Environment

    # Kill any stray server/agent processes from previous runs
    Run Process    pkill    -f    ank-server    shell=False
    Run Process    pkill    -f    ank-agent    shell=False
    Sleep    1s    reason=Wait for processes to die

    # Stop any existing test containers to avoid state pollution
    # Clean up persistence plugin containers
    ${result_plugin}=    Run Process    podman    ps    -a    --filter    name\=basic_persistency    --format\={{.Names}}    shell=False
    @{plugin_containers}=    Split String    ${result_plugin.stdout}    \n
    FOR    ${container}    IN    @{plugin_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    # Clean up test workload containers (nginx, mqtt, test workloads)
    ${result_workloads}=    Run Process    podman    ps    -a    --filter    name\=nginx    --format\={{.Names}}    shell=False
    @{workload_containers}=    Split String    ${result_workloads.stdout}    \n
    FOR    ${container}    IN    @{workload_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    # Clean up mqtt test containers
    ${result_mqtt}=    Run Process    podman    ps    -a    --filter    name\=mqtt    --format\={{.Names}}    shell=False
    @{mqtt_containers}=    Split String    ${result_mqtt.stdout}    \n
    FOR    ${container}    IN    @{mqtt_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    # Clean up generic test workload containers
    ${result_test}=    Run Process    podman    ps    -a    --filter    name\=workload    --format\={{.Names}}    shell=False
    @{test_containers}=    Split String    ${result_test.stdout}    \n
    FOR    ${container}    IN    @{test_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    ${timestamp}=    Evaluate    int(__import__('time').time())
    ${random}=    Evaluate    __import__('random').randint(1000, 9999)
    ${TEST_RUN_ID}=    Set Variable    ${timestamp}-${random}
    Set Suite Variable    ${TEST_RUN_ID}
    ${TEST_DIR}=    Set Variable    /tmp/ankaios-test-${TEST_RUN_ID}
    Set Suite Variable    ${TEST_DIR}
    ${KEYS_DIR}=    Set Variable    ${TEST_DIR}/keys
    Set Suite Variable    ${KEYS_DIR}
    ${WORKLOADS_DIR}=    Set Variable    ${TEST_DIR}/workloads
    Set Suite Variable    ${WORKLOADS_DIR}

    # Clean up any existing test directory from previous failed runs
    Run Keyword And Ignore Error    Remove Directory    ${TEST_DIR}    recursive=True

    Create Directory    ${TEST_DIR}
    Log    Created test directory: ${TEST_DIR}

Cleanup Test Run Directory
    [Documentation]    Remove test directory and containers after run
    # Remove persistence plugin containers
    ${result_plugin}=    Run Process    podman    ps    -a    --filter    name\=basic_persistency    --format\={{.Names}}    shell=False
    @{plugin_containers}=    Split String    ${result_plugin.stdout}    \n
    FOR    ${container}    IN    @{plugin_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    # Remove test workload containers
    ${result_workloads}=    Run Process    podman    ps    -a    --filter    name\=nginx    --format\={{.Names}}    shell=False
    @{workload_containers}=    Split String    ${result_workloads.stdout}    \n
    FOR    ${container}    IN    @{workload_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    ${result_mqtt}=    Run Process    podman    ps    -a    --filter    name\=mqtt    --format\={{.Names}}    shell=False
    @{mqtt_containers}=    Split String    ${result_mqtt.stdout}    \n
    FOR    ${container}    IN    @{mqtt_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    ${result_test}=    Run Process    podman    ps    -a    --filter    name\=workload    --format\={{.Names}}    shell=False
    @{test_containers}=    Split String    ${result_test.stdout}    \n
    FOR    ${container}    IN    @{test_containers}
        Run Keyword If    "${container}" != ""    Run Process    podman    rm    -f    ${container}    shell=False
    END

    # CRITICAL: Only remove if TEST_DIR was actually set (prevents deleting CWD on setup failure)
    Run Keyword If    "${TEST_DIR}" != ""    Run Keyword And Ignore Error    Remove Directory    ${TEST_DIR}    recursive=True
    Run Keyword If    "${TEST_DIR}" != ""    Log    Cleaned up test directory: ${TEST_DIR}

*** Test Cases ***
Signed Manifest Is Persisted With Signature Block
    [Documentation]    Verify that persistence plugin saves signed YAML with signature intact
    [Tags]    signature    persistence    critical

    # Setup: Generate test keypair
    Generate Ed25519 Keypair    test-key-001    ${KEYS_DIR}

    # Copy template and sign it
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/test_manifest.yaml
    Sign Manifest    /tmp/test_manifest.yaml    ${KEYS_DIR}/test-key-001.pem    1

    # Start server with signature verification enabled
    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Apply signed manifest
    ${result}=    Apply Manifest    /tmp/test_manifest.yaml
    Log    Apply result: ${result}

    # Wait for persistence
    Sleep    3s    reason=Wait for workload to reach Running state and persist

    # Verify workload persisted to separate file in workloads directory
    File Should Exist    ${WORKLOADS_DIR}/nginx-persistent.yaml
    ...    msg=Workload file should exist in workloads directory

    ${persisted_content}=    Get File    ${WORKLOADS_DIR}/nginx-persistent.yaml
    Should Contain    ${persisted_content}    ---
    ...    msg=Workload file must contain signature separator
    Should Contain    ${persisted_content}    signature:
    ...    msg=Workload file must contain signature field
    Should Contain    ${persisted_content}    key_id: test-key-001
    ...    msg=Workload file must contain correct key_id
    Should Contain    ${persisted_content}    counter: 1
    ...    msg=Workload file must contain correct counter

    # Verify signature is still valid
    ${verify_result}=    Verify Manifest Signature
    ...    ${WORKLOADS_DIR}/nginx-persistent.yaml
    ...    ${KEYS_DIR}/test-key-001.pub

    Should Be Equal    ${verify_result}    VALID
    ...    msg=Persisted workload file signature must be valid

    Log    ✅ SUCCESS: Persistence file contains valid signature

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/test_manifest.yaml
    ...    AND    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Server Restart Restores Signed State Successfully
    [Documentation]    Verify complete signature chain through restart
    [Tags]    signature    persistence    restart    critical

    # Ensure clean state (in case previous test didn't clean up properly)
    Run Keyword And Ignore Error    Terminate Process    ankaios-agent
    Run Keyword And Ignore Error    Terminate Process    ankaios-server
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}
    Sleep    2s    reason=Ensure previous test processes are dead

    # Setup
    Generate Ed25519 Keypair    test-key-002    ${KEYS_DIR}
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/test_manifest2.yaml
    Sign Manifest    /tmp/test_manifest2.yaml    ${KEYS_DIR}/test-key-002.pem    10

    # Initial application
    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    ${result}=    Apply Manifest    /tmp/test_manifest2.yaml
    Log    Initial apply: ${result}

    Sleep    3s    reason=Wait for persistence

    # Verify workload is running
    ${workloads}=    Get Workloads
    Should Contain    ${workloads}    nginx-persistent
    ...    msg=Workload should be present before restart

    # Verify workload file was created
    File Should Exist    ${WORKLOADS_DIR}/nginx-persistent.yaml
    ...    msg=Workload file should be created in workloads directory

    # Restart server (simulates reboot)
    Stop Ankaios Server
    Sleep    2s    reason=Ensure clean shutdown

    # Start fresh server + plugin
    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    Sleep    3s    reason=Wait for state restoration

    # Verify workload was restored
    ${workloads_after}=    Get Workloads
    Should Contain    ${workloads_after}    nginx-persistent
    ...    msg=Workload should be restored after restart

    # Verify server logs show signature verification on restore
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    signature verified
    ...    msg=Server should verify signature during restoration

    Log    ✅ SUCCESS: Workload restored successfully with signature verification

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/test_manifest2.yaml
    ...    AND    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Tampered Persistence File Is Rejected On Restore
    [Documentation]    Verify signature chain detects tampering
    [Tags]    signature    security    tampering    critical

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-003    ${KEYS_DIR}
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/test_manifest3.yaml
    Sign Manifest    /tmp/test_manifest3.yaml    ${KEYS_DIR}/test-key-003.pem    20

    # Initial setup
    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    Apply Manifest    /tmp/test_manifest3.yaml
    Sleep    3s    reason=Wait for persistence

    # Verify workload exists
    ${workloads_before}=    Get Workloads
    Should Contain    ${workloads_before}    nginx-persistent

    # Stop server
    Stop Ankaios Server
    Sleep    1s

    # TAMPER: Modify workload file
    ${original}=    Get File    ${WORKLOADS_DIR}/nginx-persistent.yaml
    ${tampered}=    Replace String    ${original}    nginx:latest    malicious:backdoor
    Create File    ${WORKLOADS_DIR}/nginx-persistent.yaml    ${tampered}

    Log    ⚠️ Tampered workload file - replaced nginx:latest with malicious:backdoor

    # Try to restart with tampered file
    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    Sleep    3s    reason=Wait for restoration attempt

    # Verify server rejected tampered state
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    signature verification failed
    ...    msg=Server should reject tampered persistence file

    # Verify workload was NOT restored
    ${workloads_after}=    Get Workloads
    Should Not Contain    ${workloads_after}    nginx-persistent
    ...    msg=Tampered workload should not be restored

    Log    ✅ SUCCESS: Tampered persistence file was rejected

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/test_manifest3.yaml
    ...    AND    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Unsigned Manifest Is Rejected When Require Signature Is True
    [Documentation]    Verify policy enforcement for unsigned manifests
    [Tags]    signature    policy    security

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-004    ${KEYS_DIR}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Try to apply unsigned manifest
    Copy File    ${FIXTURES_DIR}/unsigned_workload.yaml    /tmp/unsigned_test.yaml

    ${result}=    Run Keyword And Ignore Error
    ...    Apply Manifest    /tmp/unsigned_test.yaml

    # Verify rejection
    ${status}    ${output}=    Set Variable    ${result}

    Should Be Equal    ${status}    FAIL
    ...    msg=Unsigned manifest should be rejected

    # Check logs for signature requirement error
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    Signature required
    ...    msg=Logs should indicate signature requirement

    Log    ✅ SUCCESS: Unsigned manifest was rejected as expected

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/unsigned_test.yaml
    ...    AND    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Counter Rollback Attack Is Prevented
    [Documentation]    Verify monotonic counter enforcement prevents replay attacks
    [Tags]    signature    security    counter    critical

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-005    ${KEYS_DIR}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Apply manifest with counter=50
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/test_counter.yaml
    Sign Manifest    /tmp/test_counter.yaml    ${KEYS_DIR}/test-key-005.pem    50

    ${result1}=    Apply Manifest    /tmp/test_counter.yaml
    Log    Applied with counter=50: ${result1}
    Sleep    1s

    # Apply manifest with counter=51 (should succeed)
    Sign Manifest    /tmp/test_counter.yaml    ${KEYS_DIR}/test-key-005.pem    51

    ${result2}=    Apply Manifest    /tmp/test_counter.yaml
    Should Not Contain    ${result2}    error
    ...    msg=Counter=51 should be accepted after counter=50
    Sleep    1s

    # Try to apply manifest with counter=49 (rollback attempt)
    Sign Manifest    /tmp/test_counter.yaml    ${KEYS_DIR}/test-key-005.pem    49

    ${rollback_result}=    Run Keyword And Ignore Error
    ...    Apply Manifest    /tmp/test_counter.yaml

    ${status}    ${output}=    Set Variable    ${rollback_result}

    Should Be Equal    ${status}    FAIL
    ...    msg=Counter rollback should be rejected

    # Verify logs show counter rollback detection
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    Counter rollback
    ...    msg=Logs should indicate counter rollback attempt

    Log    ✅ SUCCESS: Counter rollback attack was prevented

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/test_counter.yaml
    ...    AND    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Multiple Workloads Persist To Separate Files Without Overwriting
    [Documentation]    Verify per-workload file persistence prevents workload loss
    ...    This test reproduces the production bug where mqtt_test overwrote mqtt_fedora.
    ...    With per-workload files, each workload gets its own .yaml file with complete signature.
    [Tags]    signature    persistence    multi-workload    critical

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-006    ${KEYS_DIR}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Start persistence plugin

    # Create and apply first workload (mqtt_fedora equivalent)
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/workload1.yaml
    # Modify to create mqtt_fedora workload
    ${content1}=    Get File    /tmp/workload1.yaml
    ${modified1}=    Replace String    ${content1}    nginx-persistent    mqtt_fedora
    Create File    /tmp/workload1.yaml    ${modified1}
    Sign Manifest    /tmp/workload1.yaml    ${KEYS_DIR}/test-key-006.pem    1778665427

    ${result1}=    Apply Manifest    /tmp/workload1.yaml
    Log    Applied mqtt_fedora: ${result1}
    Sleep    3s    reason=Wait for persistence

    # Verify mqtt_fedora was persisted to its own file
    File Should Exist    ${WORKLOADS_DIR}/mqtt_fedora.yaml
    ...    msg=mqtt_fedora should be persisted to separate file

    ${mqtt_fedora_content}=    Get File    ${WORKLOADS_DIR}/mqtt_fedora.yaml
    Should Contain    ${mqtt_fedora_content}    mqtt_fedora
    Should Contain    ${mqtt_fedora_content}    counter: 1778665427
    ...    msg=mqtt_fedora file should have counter=1778665427

    # Create and apply second workload (mqtt_test equivalent)
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/workload2.yaml
    # Modify to create mqtt_test workload
    ${content2}=    Get File    /tmp/workload2.yaml
    ${modified2}=    Replace String    ${content2}    nginx-persistent    mqtt_test
    Create File    /tmp/workload2.yaml    ${modified2}
    Sign Manifest    /tmp/workload2.yaml    ${KEYS_DIR}/test-key-006.pem    1778665428

    ${result2}=    Apply Manifest    /tmp/workload2.yaml
    Log    Applied mqtt_test: ${result2}
    Sleep    3s    reason=Wait for persistence

    # CRITICAL VERIFICATION: Both workload files must exist
    File Should Exist    ${WORKLOADS_DIR}/mqtt_fedora.yaml
    ...    msg=mqtt_fedora should NOT be overwritten by mqtt_test
    File Should Exist    ${WORKLOADS_DIR}/mqtt_test.yaml
    ...    msg=mqtt_test should be persisted to separate file

    # Verify mqtt_fedora file is unchanged
    ${mqtt_fedora_final}=    Get File    ${WORKLOADS_DIR}/mqtt_fedora.yaml
    Should Contain    ${mqtt_fedora_final}    mqtt_fedora
    Should Contain    ${mqtt_fedora_final}    counter: 1778665427
    Should Not Contain    ${mqtt_fedora_final}    mqtt_test
    ...    msg=mqtt_fedora file must not contain mqtt_test data

    # Verify mqtt_test file has correct signature
    ${mqtt_test_content}=    Get File    ${WORKLOADS_DIR}/mqtt_test.yaml
    Should Contain    ${mqtt_test_content}    mqtt_test
    Should Contain    ${mqtt_test_content}    counter: 1778665428
    Should Not Contain    ${mqtt_test_content}    mqtt_fedora
    ...    msg=mqtt_test file must not contain mqtt_fedora data

    # Verify both workloads are running
    ${workloads}=    Get Workloads
    Should Contain    ${workloads}    mqtt_fedora
    ...    msg=mqtt_fedora should be running
    Should Contain    ${workloads}    mqtt_test
    ...    msg=mqtt_test should be running

    # Test server restart - both workloads should restore
    # Check what files exist before restart
    ${files_before}=    Run Process    ls    -la    ${WORKLOADS_DIR}    shell=False
    Log    Files before restart: ${files_before.stdout}

    Stop Ankaios Server
    Sleep    2s

    # Verify files still exist after server stop
    ${files_after_stop}=    Run Process    ls    -la    ${WORKLOADS_DIR}    shell=False
    Log    Files after stop: ${files_after_stop.stdout}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    Sleep    3s    reason=Wait for restoration

    # Preserve logs for debugging
    Run Process    cp    ${TEST_DIR}/ankaios-server.log    /tmp/test6-restart.log    shell=False

    # Check plugin logs
    ${plugin_container}=    Run Process    podman    ps    -q    --filter    name\=basic_persistency    shell=False
    ${plugin_logs}=    Run Process    podman    logs    --tail    100    ${plugin_container.stdout.strip()}    shell=False
    Log    Plugin logs after restart: ${plugin_logs.stdout}

    # Verify both workloads restored from separate files
    ${workloads_after}=    Get Workloads
    Log    Workloads after restart: ${workloads_after}
    Should Contain    ${workloads_after}    mqtt_fedora
    ...    msg=mqtt_fedora should be restored after restart
    Should Contain    ${workloads_after}    mqtt_test
    ...    msg=mqtt_test should be restored after restart

    # Verify signatures were validated on restore
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    signature verified
    ...    msg=Server should verify signatures during restoration

    Log    ✅ SUCCESS: Multiple workloads persisted to separate files, no overwriting occurred

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/workload1.yaml
    ...    AND    Remove File    /tmp/workload2.yaml
    ...    AND    Remove Directory    ${WORKLOADS_DIR}    recursive=True

Complete Workload Lifecycle With Updates And Deletions
    [Documentation]    End-to-end test covering full lifecycle: add, update, delete with signature verification
    ...    Tests the complete flow:
    ...    1. Add multiple signed workloads
    ...    2. Update workloads with new signatures (higher counters)
    ...    3. Delete workloads and verify file cleanup
    ...    4. Verify persistence through server restart
    [Tags]    signature    persistence    lifecycle    critical

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-007    ${KEYS_DIR}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Phase 1: Add multiple workloads
    Log    === PHASE 1: Adding multiple workloads ===

    # Add workload A (counter=100)
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/workload_a.yaml
    ${content_a}=    Get File    /tmp/workload_a.yaml
    ${modified_a}=    Replace String    ${content_a}    nginx-persistent    workload_a
    Create File    /tmp/workload_a.yaml    ${modified_a}
    Sign Manifest    /tmp/workload_a.yaml    ${KEYS_DIR}/test-key-007.pem    100

    Apply Manifest    /tmp/workload_a.yaml
    Sleep    2s

    # Add workload B (counter=101)
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/workload_b.yaml
    ${content_b}=    Get File    /tmp/workload_b.yaml
    ${modified_b}=    Replace String    ${content_b}    nginx-persistent    workload_b
    Create File    /tmp/workload_b.yaml    ${modified_b}
    Sign Manifest    /tmp/workload_b.yaml    ${KEYS_DIR}/test-key-007.pem    101

    Apply Manifest    /tmp/workload_b.yaml
    Sleep    2s

    # Add workload C (counter=102)
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/workload_c.yaml
    ${content_c}=    Get File    /tmp/workload_c.yaml
    ${modified_c}=    Replace String    ${content_c}    nginx-persistent    workload_c
    Create File    /tmp/workload_c.yaml    ${modified_c}
    Sign Manifest    /tmp/workload_c.yaml    ${KEYS_DIR}/test-key-007.pem    102

    Apply Manifest    /tmp/workload_c.yaml
    Sleep    2s

    # Verify all three workload files exist
    File Should Exist    ${WORKLOADS_DIR}/workload_a.yaml
    File Should Exist    ${WORKLOADS_DIR}/workload_b.yaml
    File Should Exist    ${WORKLOADS_DIR}/workload_c.yaml

    # Verify counters
    ${file_a}=    Get File    ${WORKLOADS_DIR}/workload_a.yaml
    Should Contain    ${file_a}    counter: 100
    ${file_b}=    Get File    ${WORKLOADS_DIR}/workload_b.yaml
    Should Contain    ${file_b}    counter: 101
    ${file_c}=    Get File    ${WORKLOADS_DIR}/workload_c.yaml
    Should Contain    ${file_c}    counter: 102

    Log    ✅ Phase 1 complete: 3 workloads persisted

    # Phase 2: Update workloads with new signatures
    Log    === PHASE 2: Updating workloads with new signatures ===

    # Update workload A (counter 100 → 200)
    Sign Manifest    /tmp/workload_a.yaml    ${KEYS_DIR}/test-key-007.pem    200
    Apply Manifest    /tmp/workload_a.yaml
    Sleep    2s

    # Verify workload A file updated with new counter
    ${file_a_updated}=    Get File    ${WORKLOADS_DIR}/workload_a.yaml
    Should Contain    ${file_a_updated}    counter: 200
    Should Not Contain    ${file_a_updated}    counter: 100

    # Update workload B (counter 101 → 201)
    Sign Manifest    /tmp/workload_b.yaml    ${KEYS_DIR}/test-key-007.pem    201
    Apply Manifest    /tmp/workload_b.yaml
    Sleep    2s

    # Verify workload B file updated
    ${file_b_updated}=    Get File    ${WORKLOADS_DIR}/workload_b.yaml
    Should Contain    ${file_b_updated}    counter: 201

    # Verify workload C unchanged
    ${file_c_unchanged}=    Get File    ${WORKLOADS_DIR}/workload_c.yaml
    Should Contain    ${file_c_unchanged}    counter: 102

    # Verify all three files still exist
    File Should Exist    ${WORKLOADS_DIR}/workload_a.yaml
    File Should Exist    ${WORKLOADS_DIR}/workload_b.yaml
    File Should Exist    ${WORKLOADS_DIR}/workload_c.yaml

    Log    ✅ Phase 2 complete: Workloads A and B updated with new signatures

    # Phase 3: Delete workloads and verify file cleanup
    Log    === PHASE 3: Deleting workloads ===

    # Diagnostic: Check what files exist before deletion
    ${before_files}=    Run Process    ls    ${WORKLOADS_DIR}    shell=False
    Log    Files before deletion: ${before_files.stdout}

    # Delete workload B using signed deletion
    Delete Workload Signed    workload_b    ${KEYS_DIR}/test-key-007.pem    300
    Sleep    5s    reason=Wait for persistence plugin to process deletion event

    # Diagnostic: Check files after deletion
    ${after_files}=    Run Process    ls    ${WORKLOADS_DIR}    shell=False
    Log    Files after deletion: ${after_files.stdout}

    # Check plugin logs
    ${plugin_container}=    Run Process    podman    ps    -q    --filter    name\=basic_persistency    shell=False
    ${logs}=    Run Process    podman    logs    --tail    100    ${plugin_container.stdout.strip()}    shell=False
    Log    Plugin logs (last 100 lines): ${logs.stdout}

    # Preserve server logs for analysis
    Run Process    cp    ${TEST_DIR}/ankaios-server.log    /tmp/test7-deletion-server.log    shell=False

    # Verify workload B file was deleted
    File Should Not Exist    ${WORKLOADS_DIR}/workload_b.yaml
    ...    msg=Workload B file should be deleted when workload is removed

    # Verify workloads A and C still exist
    File Should Exist    ${WORKLOADS_DIR}/workload_a.yaml
    File Should Exist    ${WORKLOADS_DIR}/workload_c.yaml

    # Delete workload C using signed deletion
    Delete Workload Signed    workload_c    ${KEYS_DIR}/test-key-007.pem    301
    Sleep    5s    reason=Wait for persistence plugin to process deletion event

    # Verify workload C file was deleted
    File Should Not Exist    ${WORKLOADS_DIR}/workload_c.yaml

    # Verify only workload A remains
    File Should Exist    ${WORKLOADS_DIR}/workload_a.yaml
    File Should Not Exist    ${WORKLOADS_DIR}/workload_b.yaml
    File Should Not Exist    ${WORKLOADS_DIR}/workload_c.yaml

    Log    ✅ Phase 3 complete: Workloads B and C deleted, files removed

    # Phase 4: Server restart - verify only workload A restores
    Log    === PHASE 4: Testing persistence through restart ===

    Stop Ankaios Server
    Sleep    2s

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    Sleep    3s    reason=Wait for restoration

    # Verify only workload A was restored
    ${workloads_after_restart}=    Get Workloads
    Should Contain    ${workloads_after_restart}    workload_a
    ...    msg=Workload A should be restored
    Should Not Contain    ${workloads_after_restart}    workload_b
    ...    msg=Workload B should NOT be restored (was deleted)
    Should Not Contain    ${workloads_after_restart}    workload_c
    ...    msg=Workload C should NOT be restored (was deleted)

    # Verify workload A still has updated counter
    ${file_a_final}=    Get File    ${WORKLOADS_DIR}/workload_a.yaml
    Should Contain    ${file_a_final}    counter: 200

    # Verify signature verification happened
    ${logs}=    Get Ankaios Server Logs
    Should Contain    ${logs}    signature verified

    Log    ✅ SUCCESS: Complete lifecycle test passed - add, update, delete, and restore work correctly

    [Teardown]    Run Keywords
    ...    Stop Ankaios Server
    ...    AND    Remove File    /tmp/workload_a.yaml
    ...    AND    Remove File    /tmp/workload_b.yaml
    ...    AND    Remove File    /tmp/workload_c.yaml
    ...    AND    Remove Directory    ${WORKLOADS_DIR}    recursive=True

MQTT Signed Manifest Deletion Via Fleet Connector
    [Documentation]    Verify signed manifest deletion via MQTT preserves signatures
    ...    Tests the complete fleet management flow with signature preservation:
    ...    1. Fleet sends multiple signed manifests via MQTT
    ...    2. Fleet sends signed delete request via MQTT
    ...    3. Verify signature verification works for both apply and delete
    ...    4. Verify persistence correctly handles signed deletions
    [Tags]    signature    mqtt    fleet-connector    deletion    critical

    # Clean state from previous tests
    Run Keyword And Ignore Error    Remove Directory    ${WORKLOADS_DIR}    recursive=True
    Create Directory    ${WORKLOADS_DIR}

    # Setup
    Generate Ed25519 Keypair    test-key-008    ${KEYS_DIR}

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}

    # Start MQTT broker
    # First ensure image is pulled
    ${pull_result}=    Run Process    podman    pull    eclipse-mosquitto:2    shell=False
    Log    Image pull result: ${pull_result.rc}

    # Create safe container names (replace spaces with hyphens)
    ${safe_suite_name}=    Replace String    ${SUITE_NAME}    ${SPACE}    -
    ${mqtt_broker_name}=    Set Variable    mqtt-broker-${safe_suite_name}-${TEST_RUN_ID}
    ${fleet_connector_name}=    Set Variable    fleet-connector-${safe_suite_name}-${TEST_RUN_ID}

    # Clean up any existing containers from previous failed runs
    Run Keyword And Ignore Error    Run Process    podman    stop    ${mqtt_broker_name}    shell=False
    Run Keyword And Ignore Error    Run Process    podman    rm    ${mqtt_broker_name}    shell=False
    Sleep    1s    reason=Wait for cleanup

    ${mqtt_result}=    Run Process    podman    run    -d    --rm    --name    ${mqtt_broker_name}    -p    1883:1883    eclipse-mosquitto:2
    ...    shell=False
    Should Be Equal As Integers    ${mqtt_result.rc}    0    msg=MQTT broker should start: ${mqtt_result.stderr}
    Sleep    2s    reason=Wait for MQTT broker to start

    # Deploy fleet connector as an Ankaios workload (not standalone container)
    # This gives it automatic control interface access
    # Using local build with fixed SDK (delete_manifest now preserves signed_yaml)
    ${fleet_manifest}=    Catenate    SEPARATOR=\n
    ...    apiVersion: v1
    ...    workloads:
    ...    ${SPACE}${SPACE}fleet_connector:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtime: podman
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}agent: agent_A
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}runtimeConfig: |
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}image: localhost/fleet-connector:test
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}commandOptions: ["--network=host", "-e", "MQTT_BROKER_ADDR=localhost", "-e", "VIN=test_vehicle_001", "-e", "RUST_LOG=debug"]
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}controlInterfaceAccess:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}allowRules:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- type: StateRule
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}operation: ReadWrite
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}filterMasks:
    ...    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}- "desiredState.workloads.*"

    Create File    /tmp/fleet_connector.yaml    ${fleet_manifest}
    Sign Manifest    /tmp/fleet_connector.yaml    ${KEYS_DIR}/test-key-008.pem    500
    Apply Manifest    /tmp/fleet_connector.yaml
    Sleep    5s    reason=Wait for fleet connector workload to start

    # Verify fleet connector is running
    ${workloads}=    Get Workloads
    Should Contain    ${workloads}    fleet_connector    msg=Fleet connector workload should be running

    # Apply first workload via MQTT
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/mqtt_workload_1.yaml
    ${content1}=    Get File    /tmp/mqtt_workload_1.yaml
    ${modified1}=    Replace String    ${content1}    nginx-persistent    mqtt_workload_1
    ${modified1}=    Replace String    ${modified1}    persist: ALWAYS    persist: ALWAYS
    ${modified1}=    Replace String    ${modified1}    commandOptions: ["-p", "8080:80"]    commandOptions: []
    Create File    /tmp/mqtt_workload_1.yaml    ${modified1}
    Sign Manifest    /tmp/mqtt_workload_1.yaml    ${KEYS_DIR}/test-key-008.pem    501

    # Publish via MQTT
    ${mqtt_content1}=    Get File    /tmp/mqtt_workload_1.yaml
    ${result1}=    Run Process    podman    exec    ${mqtt_broker_name}    mosquitto_pub    -h    localhost    -t    vehicle/test_vehicle_001/manifest/apply/req    -m    ${mqtt_content1}    shell=False
    Should Be Equal As Integers    ${result1.rc}    0    msg=MQTT publish should succeed
    Sleep    3s    reason=Wait for fleet connector to process and apply

    # Preserve server logs for debugging
    Run Process    cp    ${TEST_DIR}/ankaios-server.log    /tmp/test8-mqtt-apply.log    shell=False

    # Check plugin logs
    ${plugin_container}=    Run Process    podman    ps    -q    --filter    name\=basic_persistency    shell=False
    ${plugin_logs}=    Run Process    podman    logs    --tail    100    ${plugin_container.stdout.strip()}    shell=False
    Log    Plugin logs after MQTT apply: ${plugin_logs.stdout}

    # Verify first workload applied and persisted
    File Should Exist    ${WORKLOADS_DIR}/mqtt_workload_1.yaml
    ${persisted1}=    Get File    ${WORKLOADS_DIR}/mqtt_workload_1.yaml
    Should Contain    ${persisted1}    mqtt_workload_1
    Should Contain    ${persisted1}    counter: 501

    # Apply second workload via MQTT
    Copy File    ${FIXTURES_DIR}/signed_workload.yaml    /tmp/mqtt_workload_2.yaml
    ${content2}=    Get File    /tmp/mqtt_workload_2.yaml
    ${modified2}=    Replace String    ${content2}    nginx-persistent    mqtt_workload_2
    ${modified2}=    Replace String    ${modified2}    persist: ALWAYS    persist: ALWAYS
    ${modified2}=    Replace String    ${modified2}    commandOptions: ["-p", "8080:80"]    commandOptions: []
    Create File    /tmp/mqtt_workload_2.yaml    ${modified2}
    Sign Manifest    /tmp/mqtt_workload_2.yaml    ${KEYS_DIR}/test-key-008.pem    502

    ${mqtt_content2}=    Get File    /tmp/mqtt_workload_2.yaml
    ${result2}=    Run Process    podman    exec    ${mqtt_broker_name}    mosquitto_pub    -h    localhost    -t    vehicle/test_vehicle_001/manifest/apply/req    -m    ${mqtt_content2}    shell=False
    Should Be Equal As Integers    ${result2.rc}    0
    Sleep    3s

    # Verify second workload applied and persisted
    File Should Exist    ${WORKLOADS_DIR}/mqtt_workload_2.yaml
    ${persisted2}=    Get File    ${WORKLOADS_DIR}/mqtt_workload_2.yaml
    Should Contain    ${persisted2}    mqtt_workload_2
    Should Contain    ${persisted2}    counter: 502

    # Verify both workloads running
    ${workloads}=    Get Workloads
    Should Contain    ${workloads}    mqtt_workload_1
    Should Contain    ${workloads}    mqtt_workload_2

    # CRITICAL TEST: Delete mqtt_workload_1 via signed MQTT manifest
    Log    === Testing signed deletion via MQTT ===

    # Create deletion manifest (same workload definition, will be sent to delete topic)
    Copy File    /tmp/mqtt_workload_1.yaml    /tmp/mqtt_delete_1.yaml
    # Re-sign with higher counter for deletion
    Sign Manifest    /tmp/mqtt_delete_1.yaml    ${KEYS_DIR}/test-key-008.pem    503

    # Publish to DELETE topic
    ${mqtt_delete_content}=    Get File    /tmp/mqtt_delete_1.yaml
    Log    Publishing delete manifest to MQTT with counter=503
    ${delete_result}=    Run Process    podman    exec    ${mqtt_broker_name}    mosquitto_pub    -h    localhost    -t    vehicle/test_vehicle_001/manifest/delete/req    -m    ${mqtt_delete_content}    shell=False
    Should Be Equal As Integers    ${delete_result.rc}    0    msg=MQTT delete publish should succeed
    Sleep    5s    reason=Wait for deletion to process

    # Check fleet connector logs
    ${fleet_logs}=    Run Process    podman    logs    --tail    50    fleet_connector.${TEST_RUN_ID}    shell=False
    Log    Fleet connector logs: ${fleet_logs.stdout}

    # Verify signature was verified during deletion
    ${server_logs}=    Get Ankaios Server Logs
    Log    Checking server logs for deletion counter=503
    Should Contain    ${server_logs}    signature verified
    ...    msg=Server should verify signature for delete request

    # Verify mqtt_workload_1 was deleted
    ${workloads_after_delete}=    Get Workloads
    Should Not Contain    ${workloads_after_delete}    mqtt_workload_1
    ...    msg=mqtt_workload_1 should be deleted
    Should Contain    ${workloads_after_delete}    mqtt_workload_2
    ...    msg=mqtt_workload_2 should still exist

    # Verify persistence file was removed
    File Should Not Exist    ${WORKLOADS_DIR}/mqtt_workload_1.yaml
    ...    msg=Deleted workload file should be removed from persistence
    File Should Exist    ${WORKLOADS_DIR}/mqtt_workload_2.yaml
    ...    msg=Non-deleted workload file should remain

    # Test server restart - only mqtt_workload_2 should restore
    Log    === Testing persistence after signed deletion ===

    Stop Ankaios Server
    Sleep    2s

    Start Ankaios Server
    ...    signature_verification_enabled=${True}
    ...    require_signature=${True}
    ...    keys_dir=${KEYS_DIR}
    ...    persistence_plugin=${True}
    ...    workloads_dir=${WORKLOADS_DIR}
    Sleep    3s

    # Verify only mqtt_workload_2 restored
    ${workloads_restored}=    Get Workloads
    Should Not Contain    ${workloads_restored}    mqtt_workload_1
    ...    msg=Deleted workload should NOT restore
    Should Contain    ${workloads_restored}    mqtt_workload_2
    ...    msg=Non-deleted workload should restore

    Log    ✅ SUCCESS: MQTT signed deletion flow works - SDK preserves signatures, persistence handles deletion

    [Teardown]    Run Keywords
    ...    Run Process    podman    stop    ${mqtt_broker_name}    shell=False
    ...    AND    Stop Ankaios Server
    ...    AND    Remove File    /tmp/mqtt_workload_1.yaml
    ...    AND    Remove File    /tmp/mqtt_workload_2.yaml
    ...    AND    Remove File    /tmp/mqtt_delete_1.yaml
    ...    AND    Remove File    /tmp/fleet_connector.yaml
    ...    AND    Remove Directory    ${WORKLOADS_DIR}    recursive=True
