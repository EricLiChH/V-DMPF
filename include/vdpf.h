#ifndef _VDPF
#define _VDPF

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct Hash hash;
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

extern void genVDPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int size, uint64_t index,  
                    uint8_t *data, int dataSize,unsigned char *k0, unsigned char *k1);
extern void batchEvalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1, struct Hash *mmo_hash2,
                        int dataSize, unsigned char *k, uint64_t *in, uint64_t inl, uint8_t *out, uint8_t *pi);
extern void fullDomainVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1, struct Hash *mmo_hash2,
                          int dataSize, unsigned char *k, uint8_t *out, uint8_t *proof);
extern void evalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                     struct Hash *mmo_hash2, int dataSize, uint8_t*k,
                     uint64_t index, uint8_t *out, uint8_t *proof);

#endif