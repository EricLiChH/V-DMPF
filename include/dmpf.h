#pragma once

#include "mmo.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Bridge functions for calling big_state.cc functions from Go
    // These functions provide C-style interfaces to the C++ functions

    // Generate Big State DMPF keys
    // Parameters:
    //   ctx: EVP_CIPHER_CTX pointer for encryption context
    //   t: number of parties
    //   size: size parameter
    //   index: array of indices
    //   dataSize: size of data
    //   data: input data array
    //   k0: output key 0 (must be pre-allocated)
    //   k1: output key 1 (must be pre-allocated)
    void genDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
                 int dataSize, uint8_t *data, uint8_t *k0, uint8_t *k1);

    // Evaluate Big State DMPF
    // Parameters:
    //   ctx: EVP_CIPHER_CTX pointer for encryption context
    //   index: index to evaluate
    //   dataSize: size of data
    //   dataShare: output data share (must be pre-allocated)
    //   k: input key
    void evalDMPF(EVP_CIPHER_CTX *ctx, uint64_t index, int dataSize,
                  uint8_t *dataShare, uint8_t *k);

    // Full domain evaluation for Big State DMPF
    // Parameters:
    //   ctx: EVP_CIPHER_CTX pointer for encryption context
    //   k: input key
    //   dataSize: size of data
    //   out: output array (must be pre-allocated)
    void fullDomainDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, int dataSize, uint8_t *out);

    // Compress Big State DMPF keys
    // Parameters:
    //   ctx: EVP_CIPHER_CTX pointer for encryption context
    //   t: number of parties
    //   size: size parameter
    //   index: array of indices
    //   dataSize: size of data
    //   data: input data array
    //   key: output compressed key (must be pre-allocated)
    void compressDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
                      int dataSize, uint8_t *data, uint8_t *key);

    // Decompress Big State DMPF keys
    // Parameters:
    //   ctx: EVP_CIPHER_CTX pointer for encryption context
    //   key: input compressed key
    //   dataSize: size of data
    //   out: output array (must be pre-allocated)
    void decompressDMPF(EVP_CIPHER_CTX *ctx, uint8_t *key, int dataSize, uint8_t *out);

#ifdef __cplusplus
}
#endif