#include "../include/dmpf.h"
#include "../include/dpf.h"
#include "../include/mmo.h"
#include "../include/vdmpf.h"
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

  // Test DMPF
  printf("Test[6]: genDMPF & evalDMPF...\n");
  EVP_CIPHER_CTX *ctx_dmpf = getDPFContext(aeskey);
  // Test genDMPF
  int t = 4;
  unsigned char k0_dmpf[19 + SIZE * t * 24 + DATASIZE * t];
  unsigned char k1_dmpf[19 + SIZE * t * 24 + DATASIZE * t];
  uint64_t index_dmpf[] = {1, 2, 3, 4};
  uint8_t data_dmpf[DATASIZE * t + 1]; // +1 for null terminator
  for (int i = 0; i < DATASIZE * t; i++)
    data_dmpf[i] = 'a';
  data_dmpf[DATASIZE * t] = '\0';
  genDMPF(ctx_dmpf, t, SIZE, index_dmpf, DATASIZE, data_dmpf, k0_dmpf, k1_dmpf);

  for (uint64_t x = 0; x < t + 1; x++) {
    uint8_t share0[DATASIZE * t], share1[DATASIZE * t];
    memset(share0, 0, DATASIZE * t);
    memset(share1, 0, DATASIZE * t);
    evalDMPF(ctx_dmpf, x, DATASIZE, share0, k0_dmpf);
    evalDMPF(ctx_dmpf, x, DATASIZE, share1, k1_dmpf);
    uint8_t result[DATASIZE * t];
    for (int i = 0; i < DATASIZE * t; i++)
      result[i] = share0[i] ^ share1[i];
    if (x != 0) {
      if (memcmp(result, data_dmpf, DATASIZE) != 0) {
        printf("Test[6] failed at index %lu: output mismatch!\n", x);
        printf("Result: %s\n Expected: %s\n", result, data_dmpf);
        return 1;
      }
    } else {
      for (int i = 0; i < DATASIZE; i++) {
        if (result[i] != 0) {
          printf("Test[6] failed at index %lu: output mismatch!\n", x);
          printf("Result: %s\n Expected: %s\n", result, "0");
          return 1;
        }
      }
    }
  }
  printf("Test[6] passed.\n");

  // Test fullDomainDMPF
  printf("Test[7]: fullDomainDMPF...\n");
  uint8_t *out0_dmpf = (uint8_t *)malloc(domainSize * DATASIZE);
  uint8_t *out1_dmpf = (uint8_t *)malloc(domainSize * DATASIZE);
  fullDomainDMPF(ctx_dmpf, k0_dmpf, DATASIZE, out0_dmpf);
  fullDomainDMPF(ctx_dmpf, k1_dmpf, DATASIZE, out1_dmpf);
  for (int i = 0; i < domainSize; i++) {
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = out0_dmpf[i * DATASIZE + j] ^ out1_dmpf[i * DATASIZE + j];
    }
    if (i >= 1 && i <= 4) {
      if (memcmp(result, data_dmpf, DATASIZE) != 0) {
        printf("Test[7] failed at index %lu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data_dmpf);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[7] failed at index %lu: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, all_zero);
        return 1;
      }
    }
  }
  printf("Test[7] passed.\n");

  // Test compress and decompress
  printf("Test[8]: compress and decompress...\n");
  // prepare inputs
  int t_big = 2;
  int size_big = SIZE;
  int domainSize_big = 1 << size_big;
  uint64_t index_big[2] = {2, 5};
  uint8_t data_big[2 * DATASIZE];
  for (int i = 0; i < 2 * DATASIZE; i++)
    data_big[i] = (uint8_t)(rand() & 0xFF);

  // calculate compressed key size
  int compressedKeySize = 34 + size_big * t_big * 24 + t_big * DATASIZE;
  uint8_t *compressedKey = (uint8_t *)malloc(compressedKeySize);

  EVP_CIPHER_CTX *ctx_big = getDPFContext(aeskey);
  // compress
  compressDMPF(ctx_big, t_big, size_big, index_big, DATASIZE, data_big,
               compressedKey);

  // decompress
  uint8_t *decompressed = (uint8_t *)malloc(domainSize_big * DATASIZE);
  decompressDMPF(ctx_big, compressedKey, DATASIZE, decompressed);

  // verify
  int ok = 1;
  for (int i = 0; i < domainSize_big; i++) {
    int is_target = (i == index_big[0] || i == index_big[1]);
    uint8_t *expected = NULL;
    if (i == index_big[0])
      expected = &data_big[0 * DATASIZE];
    else if (i == index_big[1])
      expected = &data_big[1 * DATASIZE];
    else {
      uint8_t all0[DATASIZE];
      memset(all0, 0, DATASIZE);
      expected = all0;
    }
    if (memcmp(&decompressed[i * DATASIZE], expected, DATASIZE) != 0) {
      printf("Test[8] failed at index %d\n", i);
      ok = 0;
    }
  }
  if (ok)
    printf("Test[8] passed.\n");
  free(compressedKey);
  free(decompressed);
  destroyContext(ctx_big);

  // Test VDMPF
  printf("Test[9]: genVDMPF & evalVDMPF...\n");
  EVP_CIPHER_CTX *ctx_vdmpf = getDPFContext(aeskey);
  outblocks = 4;
  RAND_bytes((uint8_t *)&hashkey1, sizeof(uint128_t));
  RAND_bytes((uint8_t *)&hashkey2, sizeof(uint128_t));
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
  // Test genVDMPF
  t = 4;
  int keySize_vdmpf = 19 + SIZE * t * 24 + DATASIZE * t + 16 * outblocks * t;
  unsigned char k0_vdmpf[keySize_vdmpf];
  unsigned char k1_vdmpf[keySize_vdmpf];
  uint64_t index_vdmpf[] = {1, 2, 3, 4};
  uint8_t data_vdmpf[DATASIZE * t + 1]; // +1 for null terminator
  for (int i = 0; i < DATASIZE * t; i++)
    data_vdmpf[i] = 'a';
  data_vdmpf[DATASIZE * t] = '\0';

  genVDMPF(ctx_vdmpf, mmo_hash1, t, SIZE, index_vdmpf, DATASIZE, data_vdmpf,
           k0_vdmpf, k1_vdmpf);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // Test evalVDMPF

  ok = true;
  for (int i = 0; i < t + 1; i++) {
    uint8_t vdmpf_pi0[32], vdmpf_pi1[32];
    memset(vout0, 0, DATASIZE);
    memset(vout1, 0, DATASIZE);

    // eval server 0
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, 2);
    evalVDMPF(ctx_vdmpf, mmo_hash1, mmo_hash2, i, DATASIZE, vout0, vdmpf_pi0,
              k0_vdmpf);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    // eval server 1
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, 2);
    evalVDMPF(ctx_vdmpf, mmo_hash1, mmo_hash2, i, DATASIZE, vout1, vdmpf_pi1,
              k1_vdmpf);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    // check pi0 == pi1
    if (memcmp(vdmpf_pi0, vdmpf_pi1, 32) != 0) {
      printf("Test[9] failed at index %d: output hash mismatch!\n", i);
      return 1;
    }

    // check vout0 ^ vout1 == data
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = vout0[j] ^ vout1[j];
    }
    if (i != 0) {
      if (memcmp(result, data_vdmpf, DATASIZE) != 0) {
        printf("Test[9] failed at index %d: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data_vdmpf);
        ok = false;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[9] failed at index %d: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, all_zero);
        ok = false;
      }
    }
  }
  if (!ok) {
    printf("Test[9] failed.\n");
    return 1;
  }

  printf("Test[9] passed.\n");

  // Test fullDomainVDMPF
  printf("Test[10]: fullDomainVDMPF...\n");
  uint8_t *out0_vdmpf = (uint8_t *)malloc(domainSize * DATASIZE);
  uint8_t *out1_vdmpf = (uint8_t *)malloc(domainSize * DATASIZE);

  // server 0
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
  fullDomainVDMPF(ctx_vdmpf, mmo_hash1, mmo_hash2, DATASIZE, k0_vdmpf,
                  out0_vdmpf, pi0);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // server 1
  mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
  mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
  fullDomainVDMPF(ctx_vdmpf, mmo_hash1, mmo_hash2, DATASIZE, k1_vdmpf,
                  out1_vdmpf, pi1);
  destroyMMOHash(mmo_hash1);
  destroyMMOHash(mmo_hash2);

  // check pi0 == pi1
  if (memcmp(pi0, pi1, 32) != 0) {
    printf("Test[10] failed: output hash mismatch!\n");
    return 1;
  }

  // verify
  for (int i = 0; i < domainSize; i++) {
    for (int j = 0; j < DATASIZE; j++) {
      result[j] = out0_vdmpf[i * DATASIZE + j] ^ out1_vdmpf[i * DATASIZE + j];
    }
    if (i == 1 || i == 2 || i == 3 || i == 4) {
      if (memcmp(result, data_vdmpf, DATASIZE) != 0) {
        printf("Test[10] failed at index %d: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, data_vdmpf);
        return 1;
      }
    } else {
      if (memcmp(result, all_zero, DATASIZE) != 0) {
        printf("Test[10] failed at index %d: output mismatch!\n", i);
        printf("Result: %s\n Expected: %s\n", result, all_zero);
        return 1;
      }
    }
  }

  printf("All tests passed :)\n");
  return 0;
}