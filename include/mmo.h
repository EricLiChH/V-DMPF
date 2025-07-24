#ifndef _MMO
#define _MMO

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Hash {
  EVP_CIPHER_CTX *mmoCtx;
  int outblocks;
};

// PRF cipher context
extern struct Hash *initMMOHash(uint8_t *seed, uint64_t outblocks);
extern void destroyMMOHash(struct Hash *hash);

// MMO functions
#ifdef __cplusplus
extern "C" {
#endif

void mmoHash2to4(struct Hash *hash, uint8_t *input, uint8_t *output);

#ifdef __cplusplus
}
#endif

extern void mmoHash4to4(struct Hash *hash, uint8_t *input, uint8_t *output);

#endif
