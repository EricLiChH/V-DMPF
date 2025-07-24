# V-DMPF: C & Go Implementation of Big-State DMPF and Verified DPF

A C & GoLang implementation of Big-State DMPF (Distributed Multi-Point Function) based on Elette Boyle's [IEEE S&P paper](https://github.com/MatanHamilis/dmpf/).
The V-DMPF also implements a Veryfied DPF referred to sachaservan's [vdpf code](https://github.com/sachaservan/vdpf).

## Overview

DMPF is a cryptographic primitive that enables secure function evaluation at multiple input points. This implementation uses the "big state" approach, which optimizes performance by maintaining larger state, particularly suitable for batch operations.

VDMPF (Verified Distributed Multiple Points Function) that extends the standard DMPF with verification capabilities. It allows parties to verify the correctness of DMPF evaluations without revealing the underlying function or input data. The verification is achieved through cryptographic commitments and zero-knowledge proof techniques.

## Key Features

- **Big-State Architecture**: Based on `big_state.rs` implementation from DMPF's Rust code
- **Memory Safety**: Proper memory management and error handling

## Project Structure

```
├── include/                    # Header files
│   ├── common.h               # Common definitions and utilities
│   ├── dpf.h                  # DPF (Distributed Point Function) definitions
│   ├── vdpf.h                 # VDPF (Verifiable DPF) definitions
│   ├── dmpf.h                 # DMPF (Distributed Multi-Point Function) definitions
│   ├── vdmpf.h                # VDMPF (Verifiable DMPF) definitions
│   ├── mmo.h                  # MMO hash definitions
│   └── sha256.h               # SHA256 hash definitions
├── src/                       # Source implementations
│   ├── test.c                 # C library test suite
│   ├── common.c               # Common utility functions
│   ├── dpf.c                  # DPF implementation
│   ├── vdpf.c                 # VDPF implementation
│   ├── dmpf.cc                # DMPF implementation (C++)
│   ├── vdmpf.cc               # VDMPF implementation (C++)
│   ├── big_state.cc           # Big-state optimization implementation
│   ├── mmo.c                  # MMO hash implementation
│   └── sha256.c               # SHA256 hash implementation
├── Go Bindings & Tests        # Go language interface
│   ├── wrapper.go             # CGO wrapper for C functions
│   ├── vdmpf.go               # Go type definitions and interfaces
│   └── vdmpf_test.go          # Comprehensive test suite and benchmarks
├── Build System
│   ├── Makefile               # Build configuration
│   ├── go.mod                 # Go module definition
│   └── LICENSE                # License file
└── README.md                  # Documentation
```

## Core Components

### Main Functions for VDPF
- `genVDPF`: Generate VDPF key pair with verification
- `evalVDPF`: Evaluate VDPF at a single point with verification
- `fullDomainVDPF`: Full domain evaluation for VDPF

### Main Functions for DMPF & VDMPF
- `gen(V)DMPF`: Standard (V)DMPF generation interface (delegates to big state implementation)
- `eval(V)DMPF`: Standard (V)DMPF evaluation interface for a specific point (delegates to big state implementation)
- `fulldomain(V)DMPF`: Standard (V)DMPF fulldomain evaluation interface for all points (delegates to big state implementation)

## Build and Run

> For `C` code:

### Dependencies

- GCC compiler
- OpenSSL library (`libssl-dev`)

### Build

```bash
make
```

### Run Tests

```bash
make test && ./test
```

### Clean

```bash
make clean
```

For `GoLang` code:

### Build

```bash
go mod tidy && go build .
```

### Run Tests

```bash
go test
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

## Reference
- [Improved Constructions for Distributed Multi-Point Functions](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a044/21B7Qx0bxLi)
- [Lightweight, Maliciously Secure Verifiable Function Secret Sharing](https://eprint.iacr.org/2021/580)
- [Function Secret Sharing: Improvements and Extensions](https://eprint.iacr.org/2018/707)