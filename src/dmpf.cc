#include "../include/dmpf.h"
#include <cstring>
#include <openssl/evp.h>

// Forward declarations of functions from big_state.cc
// These functions are now exported with C linkage
extern "C" {
void genBigStateDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
                     int dataSize, uint8_t *data, uint8_t *k0, uint8_t *k1);

void evalBigStateDMPF(EVP_CIPHER_CTX *ctx, uint64_t index, int dataSize,
                      uint8_t *dataShare, uint8_t *k);

void fullDomainBigStateDMPF(EVP_CIPHER_CTX *ctx, unsigned char *k, int dataSize,
                            uint8_t *out);

void BigStateCompress(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
                      int dataSize, uint8_t *data, uint8_t *key);

void BigStateDecompress(EVP_CIPHER_CTX *ctx, uint8_t *key, int dataSize,
                        uint8_t *out);
}

// Bridge function to generate Big State DMPF keys
void genDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
             int dataSize, uint8_t *data, uint8_t *k0, uint8_t *k1) {
  genBigStateDMPF(ctx, t, size, index, dataSize, data, k0, k1);
}

// Bridge function to evaluate Big State DMPF
void evalDMPF(EVP_CIPHER_CTX *ctx, uint64_t index, int dataSize,
              uint8_t *dataShare, uint8_t *k) {
  evalBigStateDMPF(ctx, index, dataSize, dataShare, k);
}

// Bridge function for full domain evaluation
void fullDomainDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, int dataSize,
                    uint8_t *out) {
  fullDomainBigStateDMPF(ctx, k, dataSize, out);
}

// Bridge function for compressing Big State DMPF keys
void compressDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index,
                  int dataSize, uint8_t *data, uint8_t *key) {
  BigStateCompress(ctx, t, size, index, dataSize, data, key);
}

// Bridge function for decompressing Big State DMPF keys
void decompressDMPF(EVP_CIPHER_CTX *ctx, uint8_t *key, int dataSize,
                    uint8_t *out) {
  BigStateDecompress(ctx, key, dataSize, out);
}
