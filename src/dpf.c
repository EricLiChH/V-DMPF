// This is the 2-party FSS for point functions from:
// "Function Secret Sharing: Improvements and Extensions."
// by Boyle, Elette, Niv Gilboa, and Yuval Ishai.
// Proceedings of the 2016 ACM SIGSAC Conference on Computer and
// Communications Security. ACM, 2016.

// Implementation is partially based on:
// - https://github.com/SabaEskandarian/Express/tree/master/v2
// - https://github.com/ucbrise/dory/blob/master/src/c/dpf.h
// - https://github.com/sachaservan/private-ann/tree/main/pir/dpfc

#include "../include/common.h"
#include "../include/dpf.h"
#include "../include/mmo.h"
#include <openssl/rand.h>

/**
  @brief Generates a DPF for a given bit
  @param ctx: the context for the PRG
  @param size: the size of the domain
  @param index: the index to be evaluated
  @param dataSize: the size of the data to be evaluated
  @param data: the data to be evaluated
  @param k0: the key for the server A
  @param k1: the key for the server B
  @return: void
*/
void genDPF(EVP_CIPHER_CTX *ctx, int size, uint64_t index, int dataSize,
            uint8_t *data, unsigned char *k0, unsigned char *k1) {
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

  // Allocate memory for data conversion
  uint8_t *lastCW = (uint8_t *)malloc(dataSize);
  uint8_t *convert0 = (uint8_t *)malloc(dataSize + 16);
  uint8_t *convert1 = (uint8_t *)malloc(dataSize + 16);
  uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
  memset(zeros, 0, dataSize + 16);
  memcpy(lastCW, data, dataSize);

  // Use CTR mode encryption to generate PRG output
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
    lastCW[i] = lastCW[i] ^ ((uint8_t *)convert0)[i] ^ ((uint8_t *)convert1)[i];
  }

  // Modify key format to include data
  k0[0] = size;
  memcpy(&k0[1], seeds0, 16);
  k0[CWSIZE - 1] = bits0[0];
  for (int i = 1; i <= size; i++) {
    memcpy(&k0[CWSIZE * i], &sCW[i - 1], 16);
    k0[CWSIZE * i + CWSIZE - 2] = tCW0[i - 1];
    k0[CWSIZE * i + CWSIZE - 1] = tCW1[i - 1];
  }
  memcpy(&k0[CWSIZE * size + CWSIZE], lastCW, dataSize);

  // Copy k0 to k1 and modify necessary values
  memcpy(k1, k0, CWSIZE * size + CWSIZE + dataSize);
  memcpy(&k1[1], seeds1, 16);
  k1[0] = size;
  k1[17] = bits1[0];

  // Cleanup
  free(lastCW);
  free(convert0);
  free(convert1);
  free(zeros);
  EVP_CIPHER_CTX_free(seedCtx0);
  EVP_CIPHER_CTX_free(seedCtx1);
}

/**
  @brief Evaluates a DPF for a given bit
  @param ctx: the context for the PRG
  @param k: the key for the DPF
  @param x: the bit to be evaluated
  @param dataSize: the size of the data to be evaluated
  @param dataShare: the output of the DPF
  @return: void
*/
void evalDPF(EVP_CIPHER_CTX *ctx, unsigned char *k, uint64_t x, int dataSize,
             uint8_t *dataShare) {
  // NOTE: if dataSize is not a multiple of 16, the size of dataShare should be
  // the next multiple of 16 after dataSize or else there is a memory bug.
  // Thanks to Emma Dauterman for pointing this out.

  // dataShare is of size dataSize

  int n = k[0];
  int maxLayer = n;

  uint128_t s[maxLayer + 1];
  int t[maxLayer + 1];
  uint128_t sCW[maxLayer];
  int tCW[maxLayer][2];

  memcpy(&s[0], &k[1], 16);
  t[0] = k[17];

  for (int i = 1; i <= maxLayer; i++) {
    memcpy(&sCW[i - 1], &k[18 * i], 16);
    tCW[i - 1][0] = k[18 * i + 16];
    tCW[i - 1][1] = k[18 * i + 17];
  }

  uint128_t sL, sR;
  int tL, tR;
  for (int i = 1; i <= maxLayer; i++) {
    dpfPRG(ctx, s[i - 1], &sL, &sR, &tL, &tR);

    if (t[i - 1] == 1) {
      sL = sL ^ sCW[i - 1];
      sR = sR ^ sCW[i - 1];
      tL = tL ^ tCW[i - 1][0];
      tR = tR ^ tCW[i - 1][1];
    }

    int xbit = getbit(x, n, i);
    if (xbit == 0) {
      s[i] = sL;
      t[i] = tL;
    } else {
      s[i] = sR;
      t[i] = tR;
    }
  }

  // Generate dataShare using PRG with the final seed
  int len = 0;
  uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
  memset(zeros, 0, dataSize + 16);

  EVP_CIPHER_CTX *seedCtx;
  if (!(seedCtx = EVP_CIPHER_CTX_new()))
    printf("errors occurred in creating context\n");
  if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                              (uint8_t *)&s[maxLayer], NULL))
    printf("errors occurred in init of dpf eval\n");
  if (1 != EVP_EncryptUpdate(seedCtx, dataShare, &len, zeros, dataSize))
    printf("errors occurred in encrypt\n");

  // If t[maxLayer] == 1, xor in the correction word (lastCW) from the key
  if (t[maxLayer] == 1) {
    // The correction word is at the end of the key: offset = 18 * n + 18
    for (int i = 0; i < dataSize; i++) {
      dataShare[i] ^= k[18 * n + 18 + i];
    }
  }

  free(zeros);
  EVP_CIPHER_CTX_free(seedCtx);
}

/**
  @brief Generates a full domain DPF for a given bit
  @param ctx: the context for the PRG
  @param size: the size of the domain
  @param b: the bit to be evaluated
  @param k: the key for the DPF
  @param dataSize: the size of the data to be evaluated
  @param out: the output of the DPF
  @return: void
*/
void fullDomainDPF(EVP_CIPHER_CTX *ctx, int size, unsigned char *k,
                   int dataSize, uint8_t *out) {
  // out must have at least (1 << size) * dataSize bytes

  int numLeaves = 1 << size;
  int n = size;
  int maxLayer = n;

  int currLevel = 0;
  int levelIndex = 0;
  int numIndexesInLevel = 2;

  int treeSize = 2 * numLeaves - 1;

  uint128_t *s = malloc(sizeof(uint128_t) * treeSize);
  int *t = malloc(sizeof(int) * treeSize);
  uint128_t sCW[maxLayer + 1];
  int tCW[maxLayer + 1][2];

  memcpy(&s[0], &k[1], 16);
  t[0] = k[17];

  for (int i = 1; i <= maxLayer; i++) {
    memcpy(&sCW[i - 1], &k[18 * i], 16);
    tCW[i - 1][0] = k[18 * i + 16];
    tCW[i - 1][1] = k[18 * i + 17];
  }

  uint128_t sL, sR;
  int tL, tR;
  for (int i = 1; i < treeSize; i += 2) {
    int parentIndex = 0;
    if (i > 1) {
      parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
    }

    dpfPRG(ctx, s[parentIndex], &sL, &sR, &tL, &tR);

    if (t[parentIndex] == 1) {
      sL = sL ^ sCW[currLevel];
      sR = sR ^ sCW[currLevel];
      tL = tL ^ tCW[currLevel][0];
      tR = tR ^ tCW[currLevel][1];
    }

    int lIndex = i;
    int rIndex = i + 1;
    s[lIndex] = sL;
    t[lIndex] = tL;
    s[rIndex] = sR;
    t[rIndex] = tR;

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
                                (uint8_t *)&s[index], NULL))
      printf("errors occurred in init of dpf eval\n");
    if (1 !=
        EVP_EncryptUpdate(seedCtx, out + i * dataSize, &len, zeros, dataSize))
      printf("errors occurred in encrypt\n");
    // Apply correction word if needed
    if (t[index] == 1) {
      for (int j = 0; j < dataSize; j++) {
        out[i * dataSize + j] ^= k[18 * n + 18 + j];
      }
    }
  }

  free(zeros);
  EVP_CIPHER_CTX_free(seedCtx);
}
