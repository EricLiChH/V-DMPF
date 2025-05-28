#include "../include/dpf.h"
#include "../include/mmo.h"
#include "../include/vdpf.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE (4)      // 域大小（比特数）
#define DATASIZE (16) // 每个点的数据字节数

// gcc -g test_dpf.c vdpf.c dpf.c sha256.c common.c mmo.c -I../include -lcrypto
// -o test_dpf

int main(int argc, char *argv[]) {
  unsigned char aeskey[16];
  if (!RAND_bytes(aeskey, sizeof(aeskey))) {
    printf("Failed to generate random AES key\n");
    return 1;
  }

  EVP_CIPHER_CTX *ctx = getDPFContext(aeskey);

  // 测试参数
  uint64_t index = 1; // 测试点
  uint8_t data[DATASIZE];
  for (int i = 0; i < DATASIZE; i++)
    data[i] = 'a';
  data[DATASIZE - 1] = '\0';
  printf("Test data: %s\n", data);
  unsigned char k0[(SIZE + 2) * 18 + DATASIZE]; // 预留足够空间
  unsigned char k1[(SIZE + 2) * 18 + DATASIZE];

  // 生成DPF密钥
  genDPF(ctx, SIZE, index, DATASIZE, data, k0, k1);

  // 测试evalDPF
  printf("Test[1]: evalDPF...\n");
  for (uint64_t x = 0; x < (1ULL << SIZE); x++) {
    uint8_t share0[DATASIZE], share1[DATASIZE];
    memset(share0, 0, DATASIZE);
    memset(share1, 0, DATASIZE);

    evalDPF(ctx, k0, x, DATASIZE, share0);
    evalDPF(ctx, k1, x, DATASIZE, share1);

    uint8_t result[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
      result[i] = share0[i] ^ share1[i];
    }
    if (x == index) {
      // 应等于原始data
      if (memcmp(result, data, DATASIZE) != 0) {
        printf("Test[1] failed at index %lu: output mismatch!\n", x);
        printf("Result: %s\n Expected: %s\n", result, data);
        return 1;
      }
    } else {
      for (int i = 0; i < DATASIZE; i++) {
        if (result[i] != 0) {
          printf("Test[1] failed at index %lu: output mismatch!\n", x);
          printf("Result: %s\n Expected: %s\n", result, "0");
          return 1;
        }
      }
    }
  }
  printf("Test[1] passed.\n");

  // 测试fullDomainDPF
  printf("Test[2]: fullDomainDPF...\n");
  int domainSize = 1 << SIZE;
  uint8_t *out0 = (uint8_t *)malloc(domainSize * DATASIZE);
  uint8_t *out1 = (uint8_t *)malloc(domainSize * DATASIZE);
  fullDomainDPF(ctx, SIZE, k0, DATASIZE, out0);
  fullDomainDPF(ctx, SIZE, k1, DATASIZE, out1);
  uint8_t result[DATASIZE];
  uint8_t all_zero[DATASIZE];
  memset(all_zero, 0, DATASIZE);
  for (int i = 0; i < domainSize; i++) {
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = out0[i * DATASIZE + j] ^ out1[i * DATASIZE + j];
    }
    if (i == index) {
      if (memcmp(result, data, DATASIZE) != 0) {
        printf("Test[2] failed at index %llu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[2] failed at index %llu: output mismatch!\n", i);
        return 1;
      }
    }
  }
  printf("Test[2] passed.\n");
  EVP_CIPHER_CTX_free(ctx);

  // Test VDPF
  // Test genVDPF
  printf("Test[3]: genVDPF & batchEvalVDPF...\n");
  EVP_CIPHER_CTX *ctx_vdpf = getDPFContext(aeskey);

  // Test genVDPF
  size_t outblocks = 4;
  uint128_t hashkey1;
  uint128_t hashkey2;
  RAND_bytes((uint8_t *)&hashkey1, sizeof(uint128_t));
  RAND_bytes((uint8_t *)&hashkey2, sizeof(uint128_t));
  struct Hash *mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  struct Hash *mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);

  printf("Testing genVDPF...\n");
  int keySize = CWSIZE * (SIZE + 1) + 16 * (outblocks) + DATASIZE;
  unsigned char k0_vdpf[keySize];
  unsigned char k1_vdpf[keySize];
  genVDPF(ctx_vdpf, mmo_hash1, SIZE, index, data, DATASIZE, k0_vdpf, k1_vdpf);
  destroyMMOHash(mmo_hash1);

  // prepare inputs
  uint64_t in[] = {0, 1}; // index = 1
  uint8_t *vout0 = (uint8_t *)malloc(DATASIZE * 2);
  uint8_t *vout1 = (uint8_t *)malloc(DATASIZE * 2);

  uint8_t pi0[32], pi1[32];

  // Test batchEvalVDPF
  // eval server 0
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, 2);
  batchEvalVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k0_vdpf, in, 2, vout0,
                pi0);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // eval server 1
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, 2);
  batchEvalVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k1_vdpf, in, 2, vout1,
                pi1);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // check pi0 == pi1
  if (memcmp(pi0, pi1, 32) != 0) {
    printf("Test[3] failed at index %llu: output hash mismatch!\n", 1);
    return 1;
  }

  // verify
  for (int i = 0; i < 2; i++) {
    // check vout0[i] ^ vout1[i] == data
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = vout0[i * DATASIZE + j] ^ vout1[i * DATASIZE + j];
    }
    if (1 == i) {
      if (memcmp(result, data, DATASIZE) != 0) {
        printf("Test[3] failed at index %llu: output mismatch!\n", 1);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[3] failed at index %llu: output mismatch!\n", 1);
        return 1;
      }
    }
  }
  printf("Test[3] passed.\n");

  printf("Test[4]: fullDomainVDPF...\n");
  // prepare outputs
  uint8_t *out0_vdpf = (uint8_t *)malloc(domainSize * DATASIZE);
  uint8_t *out1_vdpf = (uint8_t *)malloc(domainSize * DATASIZE);

  // eval server 0
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
  fullDomainVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k0_vdpf, out0_vdpf,
                 pi0);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // eval server 1
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
  fullDomainVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k1_vdpf, out1_vdpf,
                 pi1);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // verify
  // check pi0 == pi1
  if (memcmp(pi0, pi1, 32) != 0) {
    printf("Test[4] failed at index %llu: output hash mismatch!\n", 1);

    return 1;
  }

  for (int i = 0; i < domainSize; i++) {
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = out0_vdpf[i * DATASIZE + j] ^ out1_vdpf[i * DATASIZE + j];
    }
    if (i == index) {
      if (memcmp(result, data, DATASIZE) != 0) {
        printf("Test[4] failed at index %llu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[4] failed at index %llu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, all_zero);
        return 1;
      }
    }
  }
  printf("Test[4] passed.\n");

  // Test evalVDPF
  printf("Test[5]: evalVDPF...\n");

  for (int i = 0; i < domainSize; i++) {
    // prepare outputs
    uint8_t *vout0 = (uint8_t *)malloc(DATASIZE);
    uint8_t *vout1 = (uint8_t *)malloc(DATASIZE);
    memset(vout0, 0, DATASIZE);
    memset(vout1, 0, DATASIZE);
    // eval server 0
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
    evalVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k0_vdpf, i, vout0, pi0);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    // eval server 1
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
    evalVDPF(ctx_vdpf, mmo_hash1, mmo_hash2, DATASIZE, k1_vdpf, i, vout1, pi1);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    // check pi0 == pi1
    if (memcmp(pi0, pi1, 32) != 0) {
      printf("Test[5] failed at index %llu: output hash mismatch!\n", i);
      return 1;
    }

    // check vout0 ^ vout1 == data
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = vout0[j] ^ vout1[j];
    }
    if (i == index) {
      if (memcmp(result, data, DATASIZE) != 0) {
        printf("Test[5] failed at index %llu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[5] failed at index %d: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, all_zero);
        return 1;
      }
    }
  }
  printf("Test[5] passed.\n");
  printf("All tests passed :)\n");
  return 0;
}