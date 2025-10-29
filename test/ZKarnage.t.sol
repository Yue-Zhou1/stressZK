// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZKarnage Test Suite - Taiko Hoodi Testnet
 * @notice Tests for ZKarnage attack functions deployed on Taiko Hoodi testnet
 * @dev This test suite:
 *      - Forks Taiko Hoodi testnet (https://rpc.hoodi.taiko.xyz)
 *      - Uses deployed contract at 0x06853c001EeAC3d55351baD197092E2045B0Cf31
 *      - Measures EVM gas consumption for each attack
 *      - IMPORTANT: Gas measurements here are EVM gas, NOT ZK cycles
 *                   For actual ZK cycle data, use test_attacks.sh workflow
 *
 * Usage:
 *   forge test -vvv                    # Run all tests
 *   forge test --match-test testBnPairing -vvv  # Run specific test
 */

import {Test} from "../lib/forge-std/src/Test.sol";
import {console} from "../lib/forge-std/src/console.sol";
import "../src/ZKarnage.sol";

contract ZKarnageTest is Test {
    ZKarnage public zkarnage;
    uint256 public forkId;

    // --- Local Event Definitions (to satisfy vm.expectEmit syntax) ---
    // These must match the signatures in ZKarnage.sol exactly.
    event OpcodeResult(string name, uint256 gasUsed);
    event PrecompileResult(string name, uint256 gasUsed);
    event AttackSummary(uint256 numContracts, uint256 totalSize);
    // ContractAccessed event is not explicitly checked here, but could be added if needed.
    // event ContractAccessed(address indexed target, uint256 size);

    // Deployed contract address on Taiko Hoodi testnet
    address constant DEPLOYED_CONTRACT = 0xFd73aFC0fA12667f037fd4F000e993982dbCD8F4;

    // Taiko Hoodi testnet configuration
    string constant TAIKO_HOODI_RPC = "https://rpc.hoodi.taiko.xyz";
    uint256 constant TAIKO_HOODI_CHAIN_ID = 167013;

    // Test addresses (will use deployed contract address as test target)
    address[] testAddresses;
    
    // Gas limits for different attacks (Adjust as needed based on runs)
    uint256 constant JUMPDEST_GAS_LIMIT = 1_000_000;
    uint256 constant MCOPY_GAS_LIMIT = 1_000_000;
    uint256 constant CALLDATACOPY_GAS_LIMIT = 1_000_000;
    uint256 constant MODEXP_GAS_LIMIT = 1_000_000;
    uint256 constant BN_PAIRING_GAS_LIMIT = 5_000_000;
    uint256 constant BN_MUL_GAS_LIMIT = 5_500_000;
    uint256 constant ECRECOVER_GAS_LIMIT = 500_000;
    uint256 constant EXTCODESIZE_GAS_LIMIT = 100_000;
    uint256 constant KECCAK_GAS_LIMIT = 2_000_000;
    uint256 constant SHA256_GAS_LIMIT = 2_000_000;
    
    function setUp() public {
        console.log("\n=== Taiko Hoodi Testnet Fork Setup ===");

        // Create fork of Taiko Hoodi testnet
        forkId = vm.createFork(TAIKO_HOODI_RPC);
        vm.selectFork(forkId);

        console.log("Fork created with ID:", forkId);
        console.log("Chain ID:", block.chainid);
        console.log("Current block:", block.number);
        console.log("Using deployed contract:", DEPLOYED_CONTRACT);

        // Connect to deployed contract instead of deploying new one
        zkarnage = ZKarnage(DEPLOYED_CONTRACT);

        // Verify contract exists on fork
        require(address(zkarnage).code.length > 0, "Contract not found at deployed address");
        console.log("Contract code size:", address(zkarnage).code.length, "bytes");

        // Set up test addresses for EXTCODESIZE attack
        // Note: Use actual contracts on Taiko Hoodi with code
        // You can find more contracts at https://hoodi.taikoscan.io/
        testAddresses = new address[](3);
        testAddresses[0] = DEPLOYED_CONTRACT; // Our ZKarnage contract itself

        // Add more addresses if you want to test EXTCODESIZE with real contracts:
        // Visit https://hoodi.taikoscan.io/ and find contracts with large bytecode
        // For now, we'll just use our contract multiple times for basic testing
        testAddresses[1] = DEPLOYED_CONTRACT;
        testAddresses[2] = DEPLOYED_CONTRACT;

        console.log("Setup complete!\n");
    }

    function testJumpdestAttack() public {
        console.log("\n=== Testing JUMPDEST Attack ===");
        uint256 iterations = 6200;

        uint256 gasStart = gasleft();
        // Use low-level call to avoid staticcall optimization
        (bool success, ) = address(zkarnage).call(
            abi.encodeWithSelector(zkarnage.executeJumpdestAttack.selector, iterations)
        );
        require(success, "executeJumpdestAttack failed");
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total Gas used for JUMPDEST attack tx:", gasUsed);
        if (iterations > 0) {
             console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, JUMPDEST_GAS_LIMIT, "Gas usage too high for JUMPDEST attack");
    }

    function testMcopyAttack() public {
        console.log("\n=== Testing Memory Operations (MCOPY) Attack ===");
        uint256 size = 4096;
        uint256 iterations = 2500;

        uint256 gasStart = gasleft();
        // Use low-level call to avoid optimization and ensure proper gas measurement
        (bool success, ) = address(zkarnage).call(
            abi.encodeWithSelector(zkarnage.executeMcopyAttack.selector, size, iterations)
        );
        require(success, "executeMcopyAttack failed");
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total Gas used for memory operations attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, MCOPY_GAS_LIMIT, "Gas usage too high for memory operations attack");
    }

    function testCalldatacopyAttack() public {
        console.log("\n=== Testing CALLDATACOPY Attack ===");
        uint256 size = 32 * 1024; // 32KB
        uint256 iterations = 50;
        
        uint256 gasStart = gasleft();
        // Expect OpcodeResult event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit OpcodeResult("CALLDATACOPY", 0);
        zkarnage.executeCalldatacopyAttack(size, iterations);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("Total Gas used for CALLDATACOPY attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        console.log("Gas per KB (external):", (gasUsed * 1024) / size);
        assertLt(gasUsed, CALLDATACOPY_GAS_LIMIT, "Gas usage too high for CALLDATACOPY attack");
    }

    function testModExpAttack() public {
        console.log("\n=== Testing MODEXP Attack ===");
        uint256 iterations = 330;

        uint256 gasStart = gasleft();
        // Use low-level call to avoid staticcall optimization
        (bool success, ) = address(zkarnage).call(
            abi.encodeWithSelector(zkarnage.executeModExpAttack.selector, iterations)
        );
        require(success, "executeModExpAttack failed");
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total Gas used for MODEXP attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, MODEXP_GAS_LIMIT, "Gas usage too high for MODEXP attack");
    }

    function testBnPairingAttack() public {
        console.log("\n=== Testing BN_PAIRING Attack ===");
        uint256 iterations = 5;

        uint256 gasStart = gasleft();
        (bool success, ) = address(zkarnage).call(
            abi.encodeWithSelector(zkarnage.executeBnPairingAttack.selector, iterations)
        );
        require(success, "executeBnPairingAttack failed");
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total Gas used for BN_PAIRING attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, BN_PAIRING_GAS_LIMIT, "Gas usage too high for BN_PAIRING attack");
    }

    function testBnMulAttack() public {
        console.log("\n=== Testing BN_MUL Attack ===");
        uint256 iterations = 8;
        
        uint256 gasStart = gasleft();
        // Expect PrecompileResult event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit PrecompileResult("BN_MUL", 0);
        zkarnage.executeBnMulAttack(iterations);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("Total Gas used for BN_MUL attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, BN_MUL_GAS_LIMIT, "Gas usage too high for BN_MUL attack");
    }

    function testEcrecoverAttack() public {
        console.log("\n=== Testing ECRECOVER Attack ===");
        uint256 iterations = 50; // Increased iterations
        
        uint256 gasStart = gasleft();
        // Expect PrecompileResult event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit PrecompileResult("ECRECOVER", 0);
        zkarnage.executeEcrecoverAttack(iterations);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("Total Gas used for ECRECOVER attack tx:", gasUsed);
        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, ECRECOVER_GAS_LIMIT, "Gas usage too high for ECRECOVER attack");
    }
    
    function testKeccakAttack() public {
        console.log("\n=== Testing KECCAK256 Attack ===");
        uint256 iterations = 1000;
        uint256 dataSize = 1024; // 1 KB

        uint256 gasStart = gasleft();
        // Expect OpcodeResult event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit OpcodeResult("KECCAK256", 0);
        zkarnage.executeKeccakAttack(iterations, dataSize);
        uint256 gasUsed = gasStart - gasleft();

        // Broke down the log statement
        console.log("Total Gas used for KECCAK256 attack tx:");
        console.log("- Iterations:", iterations);
        console.log("- Data Size:", dataSize);
        console.log("- Gas Used:", gasUsed);

        if (iterations > 0) {
            console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, KECCAK_GAS_LIMIT, "Gas usage too high for KECCAK256 attack");
    }

    function testSha256Attack() public {
        console.log("\n=== Testing SHA256 Attack ===");
        uint256 iterations = 1000;
        uint256 dataSize = 1024; // 1 KB

        uint256 gasStart = gasleft();
        // Expect PrecompileResult event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit PrecompileResult("SHA256", 0);
        zkarnage.executeSha256Attack(iterations, dataSize);
        uint256 gasUsed = gasStart - gasleft();

        // Broke down the log statement
        console.log("Total Gas used for SHA256 attack tx:");
        console.log("- Iterations:", iterations);
        console.log("- Data Size:", dataSize);
        console.log("- Gas Used:", gasUsed);

        if (iterations > 0) {
             console.log("Approx Gas per iteration (external):", gasUsed / iterations);
        }
        assertLt(gasUsed, SHA256_GAS_LIMIT, "Gas usage too high for SHA256 attack");
    }

    function testExtcodesizeAttack() public {
        console.log("\n=== Testing EXTCODESIZE Attack ===");
        
        uint256 gasStart = gasleft();
        // Expect AttackSummary event (only check emitter)
        vm.expectEmit(false, false, false, false, address(zkarnage));
        // Provide the expected event signature template
        emit AttackSummary(testAddresses.length, 0);
        zkarnage.executeAttack(testAddresses);
        uint256 gasUsed = gasStart - gasleft();
        
        uint256 totalSize = 0;
        for (uint i = 0; i < testAddresses.length; i++) {
            uint256 size = testAddresses[i].code.length;
            totalSize += size;
            // console.log("Contract", i, "Size:", size); // Uncomment for debugging
        }
        
        console.log("Total Gas used for EXTCODESIZE attack tx:", gasUsed);
        console.log("Total bytecode size accessed:", totalSize, "bytes");
        if (totalSize > 0) {
            console.log("Gas per KB (external):", (gasUsed * 1024) / totalSize);
        }
        assertLt(gasUsed, EXTCODESIZE_GAS_LIMIT, "Gas usage too high for EXTCODESIZE attack");
    }

    function testAllAttacks() public {
        testJumpdestAttack();
        testMcopyAttack();
        testCalldatacopyAttack();
        testModExpAttack();
        testBnPairingAttack();
        testBnMulAttack();
        testEcrecoverAttack();
        testKeccakAttack();
        testSha256Attack();
        testExtcodesizeAttack();
    }
}