// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ZKarnage {
    event ContractAccessed(address indexed target, uint256 size);
    event AttackSummary(uint256 numContracts, uint256 totalSize);
    event ModExpResult(uint256 gasUsed, uint256 result);
    event PrecompileResult(string name, uint256 gasUsed);
    event OpcodeResult(string name, uint256 gasUsed);
    
    // Storage variables to ensure hash results are used and persisted
    bytes32 public accumulatedHash;
    bytes32 public accumulatedSha256Hash;
    
    // Precompile addresses
    address constant ECRECOVER_PRECOMPILE = 0x0000000000000000000000000000000000000001;
    address constant SHA256_PRECOMPILE = 0x0000000000000000000000000000000000000002;
    address constant IDENTITY_PRECOMPILE = 0x0000000000000000000000000000000000000004;
    address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;
    address constant BN_ADD_PRECOMPILE = 0x0000000000000000000000000000000000000006;
    address constant BN_MUL_PRECOMPILE = 0x0000000000000000000000000000000000000007;
    address constant BN_PAIRING_PRECOMPILE = 0x0000000000000000000000000000000000000008;
    
    // Original EXTCODESIZE attack
    function executeAttack(address[] calldata targets) external {
        uint256 totalSize = 0;
        
        for (uint256 i = 0; i < targets.length; i++) {
            address target = targets[i];
            uint256 size;
            
            assembly {
                size := extcodesize(target)
            }
            
            totalSize += size;
            emit ContractAccessed(target, size);
        }
        
        emit AttackSummary(targets.length, totalSize);
    }

    // JUMPDEST attack - Most expensive opcode (1037.68 cycles/gas)
    function executeJumpdestAttack(uint256 iterations) external pure {
        assembly {
                    // This is the most gas-efficient loop structure. The for loop's
                    // condition check and decrement will compile to opcodes that
                    // end in a JUMPI back to the start of the loop. The body is
                    // empty, adding no extra gas cost per iteration.
                    for { let i := iterations } i { i := sub(i, 1) } {
                        // The loop body is intentionally empty.
                        // We are stressing the JUMPI and JUMPDEST validation,
                        // not any operations within the loop.
                    }
                }
    }

    // MCOPY attack - Second most expensive opcode (666.39 cycles/gas)
    // function executeMcopyAttack(uint256 size, uint256 iterations) external {
    //     uint256 gasStart = gasleft();
    //     bytes memory data = new bytes(size);
        
    //     assembly {
    //         for { let i := 0 } lt(i, iterations) { i := add(i, 1) } {
    //             // Perform memory operations using mstore/mload
    //             let value := mload(add(data, 64))
    //             mstore(add(data, 32), value)
    //             value := mload(add(data, 96))
    //             mstore(add(data, 64), value)
    //             value := mload(add(data, 128))
    //             mstore(add(data, 96), value)
    //         }
    //     }
        
    //     emit OpcodeResult("MCOPY", gasStart - gasleft());
    // }

    /**
     * @notice Executes memory copy operations in a loop to stress the prover's
     * memory validation logic. Uses MLOAD/MSTORE for backwards compatibility
     * with networks that don't support MCOPY (pre-Cancun). Memory operations
     * can be computationally intensive to prove in a ZK circuit.
     * @param size The size of the memory chunk to copy in each iteration (in bytes).
     * @param iterations The number of copy operations to perform.
     */
    function executeMcopyAttack(uint256 size, uint256 iterations) external pure {
        // Allocate memory buffer - expansion cost paid once
        bytes memory data = new bytes(size);

        assembly {
            // Countdown loop for minimal gas overhead (matching executeJumpdestAttack pattern)
            for { let i := iterations } i { i := sub(i, 1) } {
                // Perform fixed memory operations using MLOAD/MSTORE
                // Each iteration does a small fixed number of operations to minimize gas
                // while still stressing the memory subsystem for ZK proving
                let value := mload(add(data, 64))
                mstore(add(data, 32), value)
                value := mload(add(data, 96))
                mstore(add(data, 64), value)
                value := mload(add(data, 128))
                mstore(add(data, 96), value)
            }
        }
    }

    // CALLDATACOPY attack - Third most expensive opcode (580.81 cycles/gas)
    function executeCalldatacopyAttack(uint256 size, uint256 iterations) external {
        uint256 gasStart = gasleft();
        bytes memory output = new bytes(size);
        
        assembly {
            for { let i := 0 } lt(i, iterations) { i := add(i, 1) } {
                calldatacopy(add(output, 32), 0, size)
            }
        }
        
        emit OpcodeResult("CALLDATACOPY", gasStart - gasleft());
    }

    /**
     * @notice Executes MODEXP precompile optimized for minimal gas and maximum ZK cycles.
     *
     * Parameters optimized for maximum ZK stress with minimal gas:
     * - Base: 32 bytes (coprime to modulus to force real modular arithmetic)
     * - Exponent: 64 bytes of 0xFF (maximizes Montgomery ladder iterations)
     * - Modulus: 32 bytes (coprime to base, avoids trivial reductions)
     *
     * @param iterations The number of MODEXP operations to perform.
     */
    function executeModExpAttack(uint256 iterations) external view {
        // Using an unchecked block saves ~100 gas per iteration by removing overflow checks
        unchecked {
            for (uint256 i = 0; i < iterations; i++) {
                assembly {
                    // Get free memory pointer (costs 3 gas but ensures memory safety)
                    let p := mload(0x40)

                    // Prepare input for MODEXP precompile
                    // Format: [base_length][exp_length][mod_length][base_data][exponent_data][modulus_data]
                    mstore(p, 0x20)                      // Base length: 32 bytes
                    mstore(add(p, 0x20), 0x40)           // Exponent length: 64 bytes
                    mstore(add(p, 0x40), 0x20)           // Modulus length: 32 bytes

                    // Base: Large coprime number (~2^255 + random)
                    // Using coprime values forces the ZK prover to do real modular arithmetic
                    // rather than taking shortcuts for trivial cases like base == modulus
                    mstore(add(p, 0x60), 0x8000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed)

                    // Exponent: All 0xFF (64 bytes = 2 x 32 bytes)
                    // Maximum value forces the Montgomery ladder to perform maximum iterations
                    mstore(add(p, 0x80), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                    mstore(add(p, 0xA0), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

                    // Modulus: Different coprime number (ensures gcd(base, modulus) = 1)
                    // This is 2^256 - 59, a pseudo-prime that ensures full computation
                    mstore(add(p, 0xC0), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC5)

                    // Call MODEXP precompile using staticcall (correct for non-state-modifying precompiles)
                    // Input: 3*32 (lengths) + 32 (base) + 64 (exponent) + 32 (modulus) = 224 bytes (0xE0)
                    // We reuse memory location p for output to save gas on memory allocation
                    // pop() discards the success value to save gas (we don't check for success
                    // because the goal is purely to force the ZK prover to verify the computation)
                    pop(staticcall(
                        gas(),      // Forward all available gas
                        0x05,       // Address of MODEXP precompile
                        p,          // Input memory offset
                        0xE0,       // Input size (224 bytes)
                        p,          // Output memory offset (reuse input location)
                        0x20        // Output size (32 bytes)
                    ))
                }
            }
        }
    }

    /**
     * @notice Executes BN_PAIRING precompile optimized for minimal gas and maximum ZK cycles.
     *
     * Gas Cost: per iteration (loop overhead + precompile base + 2 pairs)
     *
     * BN254 pairing is the most expensive precompile for ZK provers because it requires:
     * - Miller loop computations over extension fields (Fp12)
     * - Final exponentiation with large powers
     * - Multiple elliptic curve point operations
     *
     * @param iterations The number of pairing operations to perform.
     */
    function executeBnPairingAttack(uint256 iterations) external view {
        assembly {
            // Get free memory pointer for our input buffer
            let p := mload(0x40)

            // Prepare pairing input: 2 pairs = 384 bytes (192 bytes per pair)
            // Each pair is (G1_point, G2_point) where:
            // - G1 point: 64 bytes (x, y in Fp)
            // - G2 point: 128 bytes (x, y in Fp2, represented as 4 x 32-byte values)

            // === First Pairing: e(G1, G2) ===

            mstore(p, 0x0000000000000000000000000000000000000000000000000000000000000001) // G1.x
            mstore(add(p, 0x20), 0x0000000000000000000000000000000000000000000000000000000000000002) // G1.y

            mstore(add(p, 0x40), 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // G2.x real part
            mstore(add(p, 0x60), 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // G2.x imaginary part
            mstore(add(p, 0x80), 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // G2.y real part
            mstore(add(p, 0xA0), 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // G2.y imaginary part

            // === Second Pairing: e(-G1, G2) ===

            mstore(add(p, 0xC0), 0x0000000000000000000000000000000000000000000000000000000000000001) // -G1.x (same as G1.x)
            mstore(add(p, 0xE0), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45) // -G1.y (negated)

            // Same G2 generator point as first pair (real parts first!)
            mstore(add(p, 0x100), 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // G2.x real
            mstore(add(p, 0x120), 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // G2.x imaginary
            mstore(add(p, 0x140), 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // G2.y real
            mstore(add(p, 0x160), 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // G2.y imaginary

            // This configuration ensures e(G1, G2) * e(-G1, G2) = 1 (valid pairing)
            // forcing the precompile to perform full Miller loop + final exponentiation

            // Countdown loop for minimal gas overhead (matching executeJumpdestAttack pattern)
            for { let i := iterations } i { i := sub(i, 1) } {
                // Call BN_PAIRING precompile (address 0x08)
                // Input: 384 bytes (2 pairs)
                // Output: 32 bytes (1 if valid pairing, 0 otherwise)
                pop(staticcall(
                    gas(),         // Forward all available gas
                    0x08,          // BN_PAIRING precompile address
                    p,             // Input memory offset
                    0x180,         // Input size: 384 bytes (0x180 in hex)
                    add(p, 0x180), // Output memory offset (after input, not overlapping)
                    0x20           // Output size: 32 bytes
                ))
            }
        }
    }

    // BN_MUL attack - (17.48 cycles/gas)
    function executeBnMulAttack(uint256 iterations) external {
        // Input for point multiplication (96 bytes: point x, y, scalar)
        bytes memory input = new bytes(96);

        // Use valid BN254 G1 generator point (x, y)
        bytes32 g1_x = bytes32(uint256(1));
        bytes32 g1_y = bytes32(uint256(2));

        // Use a large scalar (close to curve order) to maximize multiplication work
        // This forces many point doubling operations in the scalar multiplication
        bytes32 scalar = bytes32(uint256(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000));

        assembly {
            mstore(add(input, 32), g1_x)
            mstore(add(input, 64), g1_y)
            mstore(add(input, 96), scalar)
        }

        uint256 gasStart = gasleft();
        bool success;

        for(uint i = 0; i < iterations; i++) {
            // Use a large gas stipend
            assembly {
                // BN_MUL output is 64 bytes
                success := call(500000, BN_MUL_PRECOMPILE, 0, add(input, 32), 96, 0, 64)
            }
            require(success, "BN_MUL call failed");
        }

        uint256 gasUsed = gasStart - gasleft();
        emit PrecompileResult("BN_MUL", gasUsed);
    }

    // ECRECOVER attack - (15.74 cycles/gas)
    function executeEcrecoverAttack(uint256 iterations) external {
        // Note: These are test values designed to maximize ECRECOVER computation
        // They are not a real signature but have proper formatting and range to force
        // full elliptic curve operations instead of early validation failure
        bytes32 hash = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925;

        // Signature components in valid range (not actual signatures, but realistic values)
        // r and s are within secp256k1 curve order, v is valid (27 or 28)
        // This ensures ECRECOVER performs full point recovery computation for ZK stress testing
        uint8 v = 28;
        bytes32 r = 0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608;
        bytes32 s = 0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada;

        // Pre-allocate memory for input to avoid allocation inside loop
        bytes memory input = new bytes(128);

        uint256 gasStart = gasleft();
        bool success;
        address recoveredAddr; // To store result, preventing removal by optimizer

        for(uint i = 0; i < iterations; i++) {
             // Vary the hash each iteration to ensure different work is done
             bytes32 currentHash = keccak256(abi.encodePacked(hash, i));

             assembly {
                 // ECRECOVER input format: hash, v, r, s (all 32 bytes each)
                 mstore(add(input, 0x20), currentHash)
                 mstore(add(input, 0x40), v)
                 mstore(add(input, 0x60), r)
                 mstore(add(input, 0x80), s)

                 // Call ECRECOVER precompile
                 // Note: With varying hash, signature won't be valid, but forces full computation
                 success := call(50000, ECRECOVER_PRECOMPILE, 0, add(input, 32), 128, 0, 32)
                 recoveredAddr := mload(0) // Load result into memory
             }
             // Don't require success - invalid signatures still do computation work
        }
        // Use recoveredAddr to prevent optimization
        if (recoveredAddr == address(0)) { }

        uint256 gasUsed = gasStart - gasleft();
        emit PrecompileResult("ECRECOVER", gasUsed);
    }

    // KECCAK256 attack
    function executeKeccakAttack(uint256 iterations, uint256 dataSize) external {
        require(dataSize >= 32, "Data size must be at least 32 bytes");
        require(dataSize <= 4096, "Data size must not exceed 4096 bytes");
        
        uint256 gasStart = gasleft();
        
        // Pure Yul implementation to defeat optimizer
        assembly {
            // Use smaller memory buffers for large iteration counts
            let actualDataSize := dataSize
            
            // For large iteration counts, limit data size to reduce memory pressure
            if gt(iterations, 50000) {
                actualDataSize := 512
            }
            
            // Allocate memory for our data buffer
            let memPtr := mload(0x40)  // Get free memory pointer
            let dataPtr := add(memPtr, 32)  // Skip first 32 bytes for length
            
            // Update free memory pointer
            mstore(0x40, add(dataPtr, actualDataSize))
            
            // Initialize memory with non-zero data (only init the first 512 bytes to save gas)
            let i := 0
            for { } lt(i, 512) { i := add(i, 32) } {
                mstore(add(dataPtr, i), xor(i, timestamp()))
            }
            
            // Get block values for unpredictability
            let blockNum := number()
            let timeVal := timestamp()
            
            // Use accumulatedHash as starting point
            let runningHash := sload(accumulatedHash.slot)
            
            // Break into smaller batches of 5000 iterations to prevent stack/memory issues
            let batchSize := 5000
            let remainingIters := iterations
            
            // Batch processing loop
            for { } gt(remainingIters, 0) { } {
                // Calculate current batch
                let currentBatch := remainingIters
                if gt(currentBatch, batchSize) {
                    currentBatch := batchSize
                }
                
                // Store the current batch number in memory to influence calculations
                mstore(add(dataPtr, 64), remainingIters)
                
                // Inner loop for this batch
                for { i := 0 } lt(i, currentBatch) { i := add(i, 1) } {
                    // Change input based on counter & previous hash
                    mstore(dataPtr, xor(runningHash, xor(i, blockNum)))
                    mstore(add(dataPtr, 32), xor(i, timeVal))
                    
                    // Do the keccak operation and save result
                    runningHash := keccak256(dataPtr, actualDataSize)
                    
                    // Store back to influence next iteration
                    mstore(dataPtr, runningHash)
                    
                    // Every 500 iterations, update storage to prevent optimization
                    if eq(mod(i, 500), 499) {
                        sstore(accumulatedHash.slot, runningHash)
                    }
                }
                
                // Update remaining iterations
                remainingIters := sub(remainingIters, currentBatch)
                
                // Store intermediate result to storage after each batch
                sstore(accumulatedHash.slot, runningHash)
            }
            
            // Final storage of result
            sstore(accumulatedHash.slot, runningHash)
            
            // Log the final hash as a useful side effect
            log1(0, 0, runningHash)
        }
        
        uint256 gasUsed = gasStart - gasleft();
        emit OpcodeResult("KECCAK256", gasUsed);
    }

    // SHA256 attack
    function executeSha256Attack(uint256 iterations, uint256 dataSize) external {
        require(dataSize >= 32, "Data size must be at least 32 bytes");
        require(dataSize <= 4096, "Data size must not exceed 4096 bytes");
        
        uint256 gasStart = gasleft();
        
        // Pure Yul implementation to defeat optimizer
        assembly {
            // Use smaller memory buffers for large data and iterations
            let actualDataSize := dataSize
            
            // For large data sizes, limit size to reduce memory pressure
            if and(gt(iterations, 10000), gt(dataSize, 512)) {
                actualDataSize := 512
            }
            
            // Allocate memory for data and result
            let memPtr := mload(0x40)  // Get free memory pointer
            let dataPtr := add(memPtr, 32)  // Skip first 32 bytes for length
            let resultPtr := add(dataPtr, actualDataSize)  // Space for result after data
            
            // Update free memory pointer
            mstore(0x40, add(resultPtr, 32))  // 32 bytes for result
            
            // Initialize memory with non-zero data (only init the first 512 bytes to save gas)
            let i := 0
            for { } lt(i, 512) { i := add(i, 32) } {
                mstore(add(dataPtr, i), xor(i, timestamp()))
            }
            
            // Get block values for unpredictability
            let blockNum := number()
            let timeVal := timestamp()
            
            // Use accumulatedSha256Hash as starting point
            let runningHash := sload(accumulatedSha256Hash.slot)
            mstore(dataPtr, runningHash)
            
            // Track success status
            let success := 1
            
            // Adjust batch size based on data size to prevent out-of-gas errors
            let batchSize := 5000
            if gt(actualDataSize, 1024) {
                batchSize := 2000  // Smaller batches for larger data
            }
            if gt(actualDataSize, 2048) {
                batchSize := 1000  // Even smaller batches for 2048+ byte data
            }
            
            // Break into smaller batches to prevent stack/memory issues
            let remainingIters := iterations
            
            // Batch processing loop
            for { } gt(remainingIters, 0) { } {
                // Calculate current batch
                let currentBatch := remainingIters
                if gt(currentBatch, batchSize) {
                    currentBatch := batchSize
                }
                
                // Store the current batch number in memory to influence calculations
                mstore(add(dataPtr, 64), remainingIters)
                
                // Inner loop for this batch
                for { i := 0 } lt(i, currentBatch) { i := add(i, 1) } {
                    // Change input based on counter & previous hash to ensure uniqueness
                    mstore(dataPtr, xor(runningHash, xor(i, blockNum)))
                    mstore(add(dataPtr, 32), xor(i, timeVal))
                    
                    // Call SHA256 precompile
                    success := staticcall(gas(), SHA256_PRECOMPILE, dataPtr, actualDataSize, resultPtr, 32)
                    
                    // Check success and revert if needed
                    if iszero(success) {
                        mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000) // Error signature
                        mstore(4, 32)  // String offset
                        mstore(36, 27) // String length
                        mstore(68, "SHA256 precompile call failed") // Error message
                        revert(0, 100)
                    }
                    
                    // Get result and use for next iteration
                    runningHash := mload(resultPtr)
                    
                    // Store back to influence next iteration
                    mstore(dataPtr, runningHash)
                    
                    // Every 200 iterations, update storage to prevent optimization
                    // Do this more frequently with large data
                    if eq(mod(i, 200), 199) {
                        sstore(accumulatedSha256Hash.slot, runningHash)
                    }
                }
                
                // Update remaining iterations
                remainingIters := sub(remainingIters, currentBatch)
                
                // Store intermediate result to storage after each batch
                sstore(accumulatedSha256Hash.slot, runningHash)
            }
            
            // Final storage of result
            sstore(accumulatedSha256Hash.slot, runningHash)
            
            // Log the final hash as a useful side effect
            log1(0, 0, runningHash)
        }
        
        uint256 gasUsed = gasStart - gasleft();
        emit PrecompileResult("SHA256", gasUsed);
    }
}