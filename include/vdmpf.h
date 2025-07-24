#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#ifdef __cplusplus
extern "C" {
#endif

void genVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int t, int size,
              uint64_t *index, int dataSize, uint8_t *data, uint8_t *k0,
              uint8_t *k1);

void evalVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
               struct Hash *mmo_hash2, uint64_t index, int dataSize,
               uint8_t *dataShare, uint8_t *proof, uint8_t *k);

void fullDomainVDMPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                     struct Hash *mmo_hash2, int dataSize, uint8_t *k,
                     uint8_t *out, uint8_t *proof);

#ifdef __cplusplus
}
#endif
