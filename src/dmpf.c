#include "../include/common.h"
#include "../include/dpf.h"
#include "../include/mmo.h"
#include <openssl/rand.h>
#include <stdint.h>

/**
 * @brief Generate a DMPF for a given set of inputs
 *        The global security parameter lambda is 128 bits.
 * @param ctx: the context for the PRG
 * @param size: the domain size of the DMPF
 * @param dataSize: the size of the data to be evaluated
 * @param in: the inputs to the DMPF
 * @param inl: the length of the inputs
 * @param k0: the key for the server A
 * @param k1: the key for the server B
 * @return: void
 * @result: 2 dmpf keys
 *          k0: the key for the server A
 *          k1: the key for the server B
 */
void genDMPF(EVP_CIPHER_CTX *ctx, int size, int dataSize, uint64_t *in,
             uint64_t inl, uint8_t *k0, uint8_t *k1) {
  // make sure inputs are well-sorted
  for (int i = 0; i < inl - 1; i++) {
    if (in[i] > in[i + 1]) {
      printf("Inputs are not well-sorted\n");
      exit(1);
    }
  }

  // allocate memory for signs
  uint128_t *signs0 = (uint128_t *)malloc(2 * sizeof(uint128_t) * inl);
  uint128_t *signs1 = (uint128_t *)malloc(2 * sizeof(uint128_t) * inl);

  // allocate memory for seeds
  uint128_t *seeds0 = (uint128_t *)malloc(inl * (size + 1) * sizeof(uint128_t));
  uint128_t *seeds1 = (uint128_t *)malloc(inl * (size + 1) * sizeof(uint128_t));

  for (int i = 0; i < inl; i++) {
    seeds0[i * (size + 1)] = getRandomBlock();
  }
}