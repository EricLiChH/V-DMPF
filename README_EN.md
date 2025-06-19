# V-DMPF: C Implementation of Big-State DMPF and Verified DPF

A C language implementation of Big-State DMPF (Distributed Multi-Point Function) based on Rust reference code.

## Overview

DMPF is a cryptographic primitive that enables secure function evaluation at multiple input points. This implementation uses the "big state" approach, which optimizes performance by maintaining larger state, particularly suitable for batch operations.

## Key Features

- **Big-State Architecture**: Based on `big_state.rs` implementation from Rust code
- **Batch Processing**: Optimized for bulk operations
- **Binary Tree Structure**: Uses trie structure for efficient input processing
- **Memory Safety**: Proper memory management and error handling

## Project Structure

```
├── include/
│   ├── common.h      # Common definitions and utilities
│   ├── dpf.h         # DPF definitions
│   ├── dmpf.h        # DMPF definitions
│   └── mmo.h         # MMO hash definitions
├── src/
│   ├── common.c      # Common function implementations
│   ├── dpf.c         # DPF implementation
│   ├── dmpf.c        # DMPF implementation
│   └── mmo.c         # MMO hash implementation
├── test_dmpf.c       # Test program
├── Makefile          # Build configuration
└── README.md         # Documentation
```

## Core Components

### Data Structures

- **Signs**: Maintains sign bits
- **SignsCW**: Correction word sign data structure
- **BinaryTrie**: Binary tree for input organization
- **CW**: Correction word structure
- **ConvCW**: Conversion correction word structure
- **BigStateDmpfKey**: DMPF key structure

### Main Functions

- `genBigStateDMPF()`: Generate DMPF key pair
- `evalBigStateDMPF()`: Evaluate DMPF at a single point
- `genDMPF()`: Standard DMPF interface (delegates to big state implementation)

## Build and Run

### Dependencies

- GCC compiler
- OpenSSL library (`libssl-dev`)

### Build

```bash
make
```

### Run Tests

```bash
make test
```

### Clean

```bash
make clean
```

## Usage Example

```c
#include "include/dmpf.h"

// Initialize OpenSSL context
uint8_t key[16] = {0};
EVP_CIPHER_CTX *ctx = getDPFContext(key);

// Define parameters
int domain_size = 8;
int data_size = 4;
uint64_t inputs[] = {10, 50, 200};  // Must be sorted
uint64_t num_inputs = 3;

// Allocate key space
uint8_t *k0 = malloc(1024);
uint8_t *k1 = malloc(1024);

// Generate DMPF
genDMPF(ctx, domain_size, data_size, inputs, num_inputs, k0, k1);

// Evaluate
uint8_t output0[4], output1[4];
evalBigStateDMPF(ctx, k0, 10, data_size, output0);
evalBigStateDMPF(ctx, k1, 10, data_size, output1);

// output0 XOR output1 should equal the data for input point 10
```

## Implementation Details

### Rust Code Correspondence

This C implementation directly corresponds to the following Rust components:

- `Signs` ↔ `big_state.rs::Signs`
- `SignsCW` ↔ `big_state.rs::SignsCW`
- `BinaryTrie` ↔ `trie.rs::BinaryTrie`
- `CW` ↔ `big_state.rs::CW`
- `ConvCW` ↔ `big_state.rs::ConvCW`

### Optimizations

- **Batch Processing**: Uses precomputed tables for bulk operations
- **Memory Layout**: Optimized memory layout for better cache performance
- **Tree Traversal**: Efficient binary tree traversal algorithms

## Security

- Uses OpenSSL's cryptographically secure PRG
- Proper random number generation
- Memory cleanup to prevent information leakage

## Limitations

- Inputs must be pre-sorted
- Current implementation is simplified and may need further optimization for production-level performance
- Key serialization format is simplified

## License

This implementation is based on the original V-DMPF project license. 