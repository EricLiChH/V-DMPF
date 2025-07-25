// This is the 2-party FSS for *verifiable* point functions from:
// "Lightweight, Maliciously Secure Verifiable Function Secret Sharing."
// by de Castro, Leo, and Polychroniadou, Antigoni.
// Annual International Conference on the Theory and Applications
// of Cryptographic Techniques. Springer, Cham, 2022
// ePrint: https://eprint.iacr.org/2021/580

#include "../include/common.h"
#include "../include/dpf.h"
#include "../include/mmo.h"
#include "../include/sha256.h"
#include <openssl/rand.h>
#include <stdint.h>

extern struct Sha_256 sha_256;

void genVDPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int size, uint64_t index,
             uint8_t *data, int dataSize, unsigned char *k0,
             unsigned char *k1) {

  int didFinish = false;
  while (!didFinish) {
    uint128_t seeds0[size + 1];
    uint128_t seeds1[size + 1];
    int bits0[size + 1];
    int bits1[size + 1];

    uint128_t sCW[size];
    int tCW0[size];
    int tCW1[size];

    seeds0[0] = getRandomBlock();
    seeds1[0] = getRandomBlock();
    bits0[0] = 0;
    bits1[0] = 1;

    uint128_t s0[2], s1[2]; // 0=L,1=R
    int t0[2], t1[2];
    for (int i = 1; i <= size; i++) {
      dpfPRG(ctx, seeds0[i - 1], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
      dpfPRG(ctx, seeds1[i - 1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

      int keep, lose;
      int indexBit = getbit(index, size, i);
      if (indexBit == 0) {
        keep = LEFT;
        lose = RIGHT;
      } else {
        keep = RIGHT;
        lose = LEFT;
      }

      sCW[i - 1] = s0[lose] ^ s1[lose];

      tCW0[i - 1] = t0[LEFT] ^ t1[LEFT] ^ indexBit ^ 1;
      tCW1[i - 1] = t0[RIGHT] ^ t1[RIGHT] ^ indexBit;

      if (bits0[i - 1] == 1) {
        seeds0[i] = s0[keep] ^ sCW[i - 1];
        if (keep == 0)
          bits0[i] = t0[keep] ^ tCW0[i - 1];
        else
          bits0[i] = t0[keep] ^ tCW1[i - 1];
      } else {
        seeds0[i] = s0[keep];
        bits0[i] = t0[keep];
      }

      if (bits1[i - 1] == 1) {
        seeds1[i] = s1[keep] ^ sCW[i - 1];
        if (keep == 0)
          bits1[i] = t1[keep] ^ tCW0[i - 1];
        else
          bits1[i] = t1[keep] ^ tCW1[i - 1];
      } else {
        seeds1[i] = s1[keep];
        bits1[i] = t1[keep];
      }
    }

    // *********************************
    // START: verification code
    // *********************************
    uint128_t pi0[hash->outblocks];
    uint128_t pi1[hash->outblocks];

    uint128_t hashinput[2];
    hashinput[0] = index;
    hashinput[1] = seeds0[size];

    mmoHash2to4(hash, (uint8_t *)&hashinput[0], (uint8_t *)&pi0);

    hashinput[0] = index;
    hashinput[1] = seeds1[size];
    mmoHash2to4(hash, (uint8_t *)&hashinput[0], (uint8_t *)&pi1);

    uint128_t cs[4];
    cs[0] = pi0[0] ^ pi1[0];
    cs[1] = pi0[1] ^ pi1[1];
    cs[2] = pi0[2] ^ pi1[2];
    cs[3] = pi0[3] ^ pi1[3];

    int bit0 = seed_lsb(seeds0[size]);
    int bit1 = seed_lsb(seeds1[size]);

    if (bit0 != bit1)
      didFinish = true;
    else
      continue;
    // *********************************
    // END: DPF verification code
    // *********************************

    // Allocate memory for data conversion
    uint8_t *lastCW = (uint8_t *)malloc(dataSize);
    uint8_t *convert0 = (uint8_t *)malloc(dataSize + 16);
    uint8_t *convert1 = (uint8_t *)malloc(dataSize + 16);
    uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
    memset(zeros, 0, dataSize + 16);
    memcpy(lastCW, data, dataSize);
    // printf("lastCW: %s\n", lastCW);
    //  Use CTR mode encryption to generate PRG output
    EVP_CIPHER_CTX *seedCtx0;
    EVP_CIPHER_CTX *seedCtx1;
    int len = 0;

    if (!(seedCtx0 = EVP_CIPHER_CTX_new()))
      printf("errors occurred in creating context\n");
    if (!(seedCtx1 = EVP_CIPHER_CTX_new()))
      printf("errors occurred in creating context\n");

    if (1 != EVP_EncryptInit_ex(seedCtx0, EVP_aes_128_ctr(), NULL,
                                (uint8_t *)&seeds0[size], NULL))
      printf("errors occurred in init of dpf gen\n");
    if (1 != EVP_EncryptInit_ex(seedCtx1, EVP_aes_128_ctr(), NULL,
                                (uint8_t *)&seeds1[size], NULL))
      printf("errors occurred in init of dpf gen\n");

    if (1 != EVP_EncryptUpdate(seedCtx0, convert0, &len, zeros, dataSize))
      printf("errors occurred in encrypt\n");
    if (1 != EVP_EncryptUpdate(seedCtx1, convert1, &len, zeros, dataSize))
      printf("errors occurred in encrypt\n");

    // Calculate final lastCW
    for (int i = 0; i < dataSize; i++) {
      lastCW[i] =
          lastCW[i] ^ ((uint8_t *)convert0)[i] ^ ((uint8_t *)convert1)[i];
    }

    // Modify key format to include data
    k0[0] = size;
    memcpy(&k0[1], seeds0, 16);
    k0[CWSIZE - 1] = bits0[0];
    for (int i = 1; i <= size; i++) {
      memcpy(&k0[18 * i], &sCW[i - 1], 16);
      k0[CWSIZE * i + CWSIZE - 2] = tCW0[i - 1];
      k0[CWSIZE * i + CWSIZE - 1] = tCW1[i - 1];
    }
    memcpy(&k0[INDEX_LASTCW], lastCW, dataSize);
    memcpy(&k0[INDEX_LASTCW + dataSize], cs, 16 * (hash->outblocks));

    memcpy(k1, k0, INDEX_LASTCW + dataSize + 16 * (hash->outblocks));
    memcpy(&k1[1], seeds1, 16); // only value that is different from k0
    k1[0] = size;
    k1[CWSIZE - 1] = bits1[0];

    // Cleanup
    free(lastCW);
    free(convert0);
    free(convert1);
    free(zeros);
    EVP_CIPHER_CTX_free(seedCtx0);
    EVP_CIPHER_CTX_free(seedCtx1);
  }
}

// Follows implementation of https://eprint.iacr.org/2021/580.pdf (Figure 1)
// mmo_hash1 = H, mmo_hash2 = H'; pi is the verification output
// (pi should be equal on both servers)
void batchEvalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                   struct Hash *mmo_hash2, int dataSize, unsigned char *k,
                   uint64_t *in, uint64_t inl, uint8_t *out, uint8_t *proof) {

  // parse the key
  int size = k[0];
  uint128_t seeds[size + 1];
  int bits[size + 1];
  uint128_t sCW[size + 1];
  int tCW0[size];
  int tCW1[size];
  uint128_t cs[4];
  uint128_t pi[4];

  memcpy(&seeds[0], &k[1], 16);
  bits[0] = k[CWSIZE - 1];

  for (int i = 1; i <= size; i++) {
    memcpy(&sCW[i - 1], &k[18 * i], 16);
    tCW0[i - 1] = k[CWSIZE * i + CWSIZE - 2];
    tCW1[i - 1] = k[CWSIZE * i + CWSIZE - 1];
  }

  memcpy(cs, &k[INDEX_LASTCW + dataSize], 16 * (mmo_hash1->outblocks));
  memcpy(pi, &k[INDEX_LASTCW + dataSize],
         16 * (mmo_hash1->outblocks)); // pi = cs

  uint128_t hashinput[mmo_hash1->outblocks];
  uint128_t tpi[mmo_hash1->outblocks];
  uint128_t cpi[mmo_hash1->outblocks];
  uint128_t sL, sR;
  int tL, tR;

  // outter loop: iterate over all evaluation points
  for (int l = 0; l < inl; l++) {
    for (int i = 1; i <= size; i++) {
      dpfPRG(ctx, seeds[i - 1], &sL, &sR, &tL, &tR);

      if (bits[i - 1] == 1) {
        sL = sL ^ sCW[i - 1];
        sR = sR ^ sCW[i - 1];
        tL = tL ^ tCW0[i - 1];
        tR = tR ^ tCW1[i - 1];
      }

      int xbit = getbit(in[l], size, i);

      seeds[i] = (1 - xbit) * sL + xbit * sR;
      bits[i] = (1 - xbit) * tL + xbit * tR;
    }

    // *********************************
    // START: DPF verification code
    // *********************************
    int bit = seed_lsb(seeds[size]);

    hashinput[0] = in[l];
    hashinput[1] = seeds[size];
    hashinput[2] = 0;
    hashinput[3] = 0;
    // step 1: H(seeds[size]||X[l])
    mmoHash2to4(mmo_hash1, (uint8_t *)&hashinput[0], (uint8_t *)&tpi[0]);
    // step 2: pi^correct(tpi, cs, bit)
    hashinput[0] = pi[0] ^ correct(tpi[0], cs[0], bit);
    hashinput[1] = pi[1] ^ correct(tpi[1], cs[1], bit);
    hashinput[2] = pi[2] ^ correct(tpi[2], cs[2], bit);
    hashinput[3] = pi[3] ^ correct(tpi[3], cs[3], bit);

    // step 3: comptue pi^H'(pi^tpi)
    mmoHash4to4(mmo_hash2, (uint8_t *)&hashinput[0], (uint8_t *)&cpi[0]);

    pi[0] ^= cpi[0];
    pi[1] ^= cpi[1];
    pi[2] ^= cpi[2];
    pi[3] ^= cpi[3];
    // *********************************
    // END: DPF verification code
    // *********************************
    // Generate dataShare using PRG with the final seed
    int len = 0;
    uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
    memset(zeros, 0, dataSize + 16);

    EVP_CIPHER_CTX *seedCtx;
    if (!(seedCtx = EVP_CIPHER_CTX_new()))
      printf("errors occurred in creating context\n");
    if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                                (uint8_t *)&seeds[size], NULL))
      printf("errors occurred in init of dpf eval\n");
    if (1 !=
        EVP_EncryptUpdate(seedCtx, out + l * dataSize, &len, zeros, dataSize))
      printf("errors occurred in encrypt\n");

    // If bits[size] == 1, xor in the correction word (lastCW) from the key
    if (bits[size] == 1) {
      // The correction word is at the end of the key: offset = 18 * n + 18
      for (int i = 0; i < dataSize; i++) {
        out[l * dataSize + i] ^= k[18 * size + 18 + i];
      }
    }
  }

  // VDPF output hash (just SHA256 of pi)
  uint8_t hash[32];
  sha_256_init(&sha_256, hash);
  sha_256_write(&sha_256, (uint8_t *)&pi[0], sizeof(uint128_t) * 4);
  sha_256_close(&sha_256);
  memcpy(proof, hash, 32);
}

void fullDomainVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
                    struct Hash *mmo_hash2, int dataSize, unsigned char *k,
                    uint8_t *out, uint8_t *proof) {

  int size = k[0];
  int numLeaves = 1 << size;
  int maxLayer = size;

  int currLevel = 0;
  int levelIndex = 0;
  int numIndexesInLevel = 2;

  int treeSize = 2 * numLeaves - 1;

  // treeSize too big to allocate on stack
  uint128_t *seeds = malloc(sizeof(uint128_t) * treeSize);
  int *bits = malloc(sizeof(int) * treeSize);
  uint128_t sCW[maxLayer + 1];
  int tCW0[maxLayer + 1];
  int tCW1[maxLayer + 1];
  uint128_t cs[4];
  uint128_t pi[4];

  uint128_t hashinput[4];
  uint128_t tpi[4];
  uint128_t cpi[4];

  memcpy(seeds, &k[1], 16);
  bits[0] = k[CWSIZE - 1];
  for (int i = 1; i <= maxLayer; i++) {
    memcpy(&sCW[i - 1], &k[18 * i], 16);
    tCW0[i - 1] = k[CWSIZE * i + CWSIZE - 2];
    tCW1[i - 1] = k[CWSIZE * i + CWSIZE - 1];
  }

  memcpy(cs, &k[INDEX_LASTCW + 16], 16 * (mmo_hash1->outblocks));
  memcpy(pi, &k[INDEX_LASTCW + 16], 16 * (mmo_hash1->outblocks)); // pi = cs

  uint128_t sL, sR;
  int tL, tR;
  for (int i = 1; i < treeSize; i += 2) {
    int parentIndex = 0;
    if (i > 1) {
      parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
    }

    dpfPRG(ctx, seeds[parentIndex], &sL, &sR, &tL, &tR);

    if (bits[parentIndex] == 1) {
      sL = sL ^ sCW[currLevel];
      sR = sR ^ sCW[currLevel];
      tL = tL ^ tCW0[currLevel];
      tR = tR ^ tCW1[currLevel];
    }

    int lIndex = i;
    int rIndex = i + 1;
    seeds[lIndex] = sL;
    bits[lIndex] = tL;
    seeds[rIndex] = sR;
    bits[rIndex] = tR;

    levelIndex += 2;
    if (levelIndex == numIndexesInLevel) {
      currLevel++;
      numIndexesInLevel *= 2;
      levelIndex = 0;
    }
  }

  uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
  memset(zeros, 0, dataSize + 16);

  EVP_CIPHER_CTX *seedCtx;
  if (!(seedCtx = EVP_CIPHER_CTX_new()))
    printf("errors occurred in creating context\n");

  for (int i = 0; i < numLeaves; i++) {
    int len = 0;
    int index = treeSize - numLeaves + i;

    if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                                (uint8_t *)&seeds[index], NULL))
      printf("errors occurred in init of dpf eval\n");
    if (1 !=
        EVP_EncryptUpdate(seedCtx, out + i * dataSize, &len, zeros, dataSize))
      printf("errors occurred in encrypt\n");

    if (bits[index] == 1) {
      for (int j = 0; j < dataSize; j++) {
        out[i * dataSize + j] ^= k[18 * size + 18 + j];
      }
    }

    // *********************************
    // START: DPF verification code
    // *********************************
    int bit = seed_lsb(seeds[index]);

    hashinput[0] = index;
    hashinput[1] = seeds[index];
    hashinput[2] = 0;
    hashinput[3] = 0;

    // step 1: H(seeds[size]||X[l])
    mmoHash2to4(mmo_hash1, (uint8_t *)&hashinput[0], (uint8_t *)&tpi[0]);

    // step 2: pi^correct(tpi, cs, bit)
    hashinput[0] = pi[0] ^ correct(tpi[0], cs[0], bit);
    hashinput[1] = pi[1] ^ correct(tpi[1], cs[1], bit);
    hashinput[2] = pi[2] ^ correct(tpi[2], cs[2], bit);
    hashinput[3] = pi[3] ^ correct(tpi[3], cs[3], bit);

    // step 3: comptue pi^H'(pi^tpi)
    mmoHash4to4(mmo_hash2, (uint8_t *)&hashinput[0], (uint8_t *)&cpi[0]);

    pi[0] ^= cpi[0];
    pi[1] ^= cpi[1];
    pi[2] ^= cpi[2];
    pi[3] ^= cpi[3];
    // *********************************
    // END: DPF verification code
    // *********************************
  }

  // VDPF output hash
  uint8_t hash[32];
  sha_256_init(&sha_256, hash);
  sha_256_write(&sha_256, (uint8_t *)&pi[0], sizeof(uint128_t) * 4);
  sha_256_close(&sha_256);
  memcpy(proof, hash, sizeof(uint8_t) * 32);

  free(bits);
  free(seeds);
}

void evalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1,
              struct Hash *mmo_hash2, int dataSize, uint8_t *k, uint64_t index,
              uint8_t *out, uint8_t *proof) {
  // parse the key
  int size = k[0];
  uint128_t seeds[size + 1];
  int bits[size + 1];
  uint128_t sCW[size + 1];
  int tCW0[size];
  int tCW1[size];
  uint128_t cs[4];
  uint128_t pi[4];

  memcpy(&seeds[0], &k[1], 16);
  bits[0] = k[CWSIZE - 1];

  for (int i = 1; i <= size; i++) {
    memcpy(&sCW[i - 1], &k[18 * i], 16);
    tCW0[i - 1] = k[CWSIZE * i + CWSIZE - 2];
    tCW1[i - 1] = k[CWSIZE * i + CWSIZE - 1];
  }

  memcpy(cs, &k[INDEX_LASTCW + dataSize], 16 * (mmo_hash1->outblocks));
  memcpy(pi, &k[INDEX_LASTCW + dataSize],
         16 * (mmo_hash1->outblocks)); // pi = cs

  uint128_t hashinput[mmo_hash1->outblocks];
  uint128_t tpi[mmo_hash1->outblocks];
  uint128_t cpi[mmo_hash1->outblocks];
  uint128_t sL, sR;
  int tL, tR;

  for (int i = 1; i <= size; i++) {
    dpfPRG(ctx, seeds[i - 1], &sL, &sR, &tL, &tR);

    if (bits[i - 1] == 1) {
      sL = sL ^ sCW[i - 1];
      sR = sR ^ sCW[i - 1];
      tL = tL ^ tCW0[i - 1];
      tR = tR ^ tCW1[i - 1];
    }

    int xbit = getbit(index, size, i);

    seeds[i] = (1 - xbit) * sL + xbit * sR;
    bits[i] = (1 - xbit) * tL + xbit * tR;
  }

  // *********************************
  // START: DPF verification code
  // *********************************
  int bit = seed_lsb(seeds[size]);

  hashinput[0] = index;
  hashinput[1] = seeds[size];
  hashinput[2] = 0;
  hashinput[3] = 0;

  mmoHash2to4(mmo_hash1, (uint8_t *)&hashinput[0], (uint8_t *)&tpi[0]);

  hashinput[0] = pi[0] ^ correct(tpi[0], cs[0], bit);
  hashinput[1] = pi[1] ^ correct(tpi[1], cs[1], bit);
  hashinput[2] = pi[2] ^ correct(tpi[2], cs[2], bit);
  hashinput[3] = pi[3] ^ correct(tpi[3], cs[3], bit);

  mmoHash4to4(mmo_hash2, (uint8_t *)&hashinput[0], (uint8_t *)&cpi[0]);

  pi[0] ^= cpi[0];
  pi[1] ^= cpi[1];
  pi[2] ^= cpi[2];
  pi[3] ^= cpi[3];

  // *********************************
  // END: DPF verification code
  // *********************************

  // Generate dataShare using PRG with the final seed
  int len = 0;
  uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
  memset(zeros, 0, dataSize + 16);

  EVP_CIPHER_CTX *seedCtx;
  if (!(seedCtx = EVP_CIPHER_CTX_new()))
    printf("errors occurred in creating context\n");
  if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                              (uint8_t *)&seeds[size], NULL))
    printf("errors occurred in init of dpf eval\n");
  if (1 != EVP_EncryptUpdate(seedCtx, out, &len, zeros, dataSize))
    printf("errors occurred in encrypt\n");

  // If bits[size] == 1, xor in the correction word (lastCW) from the key
  if (bits[size] == 1) {
    for (int i = 0; i < dataSize; i++) {
      out[i] ^= k[18 * size + 18 + i];
    }
  }

  // VDPF output hash (just SHA256 of pi)
  uint8_t hash[32];
  sha_256_init(&sha_256, hash);
  sha_256_write(&sha_256, (uint8_t *)&pi[0], sizeof(uint128_t) * 4);
  sha_256_close(&sha_256);
  memcpy(proof, hash, sizeof(uint8_t) * 32);
}
