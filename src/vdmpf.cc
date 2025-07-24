#include "../include/vdmpf.h"
#include <cstring>
#include <openssl/evp.h>

// Forward declarations of functions from big_state.cc
// These functions are now exported with C linkage
extern "C" {
void genBigStateVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int t, int size,
                      uint64_t *index, int dataSize, uint8_t *data, uint8_t *k0,
                      uint8_t *k1);
void evalBigStateVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                       struct Hash *mmo_hash2, uint64_t index, int dataSize,
                       uint8_t *dataShare, uint8_t *proof, uint8_t *k);
void fullDomainBigStateVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                             struct Hash *mmo_hash2, int dataSize, uint8_t *k,
                             uint8_t *out, uint8_t *proof);
}

void genVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int t, int size,
              uint64_t *index, int dataSize, uint8_t *data, uint8_t *k0,
              uint8_t *k1) {
  genBigStateVDMPF(ctx, hash, t, size, index, dataSize, data, k0, k1);
}

void evalVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
               struct Hash *mmo_hash2, uint64_t index, int dataSize,
               uint8_t *dataShare, uint8_t *proof, uint8_t *k) {
  evalBigStateVDMPF(ctx, mmo_hash1, mmo_hash2, index, dataSize, dataShare,
                    proof, k);
}

void fullDomainVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                     struct Hash *mmo_hash2, int dataSize, uint8_t *k,
                     uint8_t *out, uint8_t *proof) {
  fullDomainBigStateVDMPF(ctx, mmo_hash1, mmo_hash2, dataSize, k, out, proof);
}