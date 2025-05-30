#include "../include/dmpf.h"
#include "../include/common.h"
#include "../include/dpf.h"
#include "../include/mmo.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ================= Helper Functions for Signs =================

Signs *createSigns(size_t t) {
  Signs *signs = malloc(sizeof(Signs));
  signs->nodes_per_sign = (t + 127) / 128;
  signs->capacity = signs->nodes_per_sign;
  signs->count = t;
  signs->nodes = malloc(sizeof(uint128_t) * signs->capacity);
  memset(signs->nodes, 0, sizeof(uint128_t) * signs->capacity);
  return signs;
}

void destroySigns(Signs *signs) {
  if (signs) {
    free(signs->nodes);
    free(signs);
  }
}

void setSignBit(Signs *signs, size_t bit_idx, bool value) {
  size_t node_idx = bit_idx / 128;
  size_t in_node_idx = bit_idx % 128;
  uint128_t mask = (uint128_t)1 << in_node_idx;
  if (value) {
    signs->nodes[node_idx] |= mask;
  } else {
    signs->nodes[node_idx] &= ~mask;
  }
}

bool getSignBit(Signs *signs, size_t bit_idx) {
  size_t node_idx = bit_idx / 128;
  size_t in_node_idx = bit_idx % 128;
  uint128_t mask = (uint128_t)1 << in_node_idx;
  return (signs->nodes[node_idx] & mask) != 0;
}

void zeroSigns(Signs *signs) {
  memset(signs->nodes, 0, sizeof(uint128_t) * signs->capacity);
}

void fillSignsWithSeed(Signs *signs, uint128_t seed, int direction,
                       EVP_CIPHER_CTX *ctx) {
  // Use PRG to fill signs based on seed and direction
  uint128_t current_seed = seed;
  for (size_t i = 0; i < signs->nodes_per_sign; i++) {
    uint128_t left, right;
    int t_left, t_right;
    dpfPRG(ctx, current_seed, &left, &right, &t_left, &t_right);
    signs->nodes[i] = direction ? right : left;
    current_seed = left ^ right; // Simple progression
  }
}

void xorSigns(Signs *dest, Signs *a, Signs *b) {
  for (size_t i = 0; i < dest->nodes_per_sign; i++) {
    dest->nodes[i] = a->nodes[i] ^ b->nodes[i];
  }
}

// ================= Helper Functions for SignsCW =================

SignsCW *createSignsCW(size_t t, size_t depth) {
  SignsCW *signs_cw = malloc(sizeof(SignsCW));
  signs_cw->t = t;
  size_t min = (t < (1ULL << depth)) ? t : (1ULL << depth);
  signs_cw->nodes_per_point_per_direction = (t + 127) / 128;
  size_t total_nodes = 2 * min * signs_cw->nodes_per_point_per_direction;
  signs_cw->nodes = malloc(sizeof(uint128_t) * total_nodes);

  // Initialize with random values
  for (size_t i = 0; i < total_nodes; i++) {
    signs_cw->nodes[i] = getRandomBlock();
  }

  return signs_cw;
}

void destroySignsCW(SignsCW *signs_cw) {
  if (signs_cw) {
    free(signs_cw->nodes);
    free(signs_cw);
  }
}

// ================= Binary Trie Implementation =================

BinaryTrie *createBinaryTrie(uint64_t *words, size_t word_count,
                             size_t bit_length) {
  BinaryTrie *trie = malloc(sizeof(BinaryTrie));
  trie->words = malloc(sizeof(uint64_t) * word_count);
  memcpy(trie->words, words, sizeof(uint64_t) * word_count);
  trie->word_count = word_count;
  trie->bit_length = bit_length;

  // Allocate arrays for each depth level
  trie->level_counts = malloc(sizeof(size_t) * (bit_length + 1));
  trie->has_left = malloc(sizeof(bool *) * (bit_length + 1));
  trie->has_right = malloc(sizeof(bool *) * (bit_length + 1));

  // Build the trie structure
  for (size_t depth = 0; depth <= bit_length; depth++) {
    size_t max_nodes =
        (word_count < (1ULL << depth)) ? word_count : (1ULL << depth);
    trie->level_counts[depth] = max_nodes;
    trie->has_left[depth] = malloc(sizeof(bool) * max_nodes);
    trie->has_right[depth] = malloc(sizeof(bool) * max_nodes);

    // Initialize
    memset(trie->has_left[depth], 0, sizeof(bool) * max_nodes);
    memset(trie->has_right[depth], 0, sizeof(bool) * max_nodes);

    if (depth < bit_length) {
      // Check which nodes have children
      for (size_t i = 0; i < word_count; i++) {
        uint64_t prefix = words[i] >> (bit_length - depth);
        if (prefix < max_nodes) {
          int bit =
              getbit(words[i] << (64 - bit_length), bit_length, depth + 1);
          if (bit == 0) {
            trie->has_left[depth][prefix] = true;
          } else {
            trie->has_right[depth][prefix] = true;
          }
        }
      }
    }
  }

  return trie;
}

void destroyBinaryTrie(BinaryTrie *trie) {
  if (trie) {
    free(trie->words);
    for (size_t i = 0; i <= trie->bit_length; i++) {
      free(trie->has_left[i]);
      free(trie->has_right[i]);
    }
    free(trie->has_left);
    free(trie->has_right);
    free(trie->level_counts);
    free(trie);
  }
}

bool trieHasSon(BinaryTrie *trie, size_t node_idx, size_t depth,
                bool direction) {
  if (depth >= trie->bit_length || node_idx >= trie->level_counts[depth]) {
    return false;
  }
  return direction ? trie->has_right[depth][node_idx]
                   : trie->has_left[depth][node_idx];
}

// ================= Correction Word Implementation =================

CW *createCW(BinaryTrie *trie, SignsCW *signs, uint128_t *seeds,
             size_t seed_count, size_t depth, size_t batch_size) {
  CW *cw = malloc(sizeof(CW));
  cw->seed_count = seed_count;
  cw->batch_size = batch_size;
  cw->signs = signs;

  // Copy seeds
  cw->seeds = malloc(sizeof(uint128_t) * seed_count);
  memcpy(cw->seeds, seeds, sizeof(uint128_t) * seed_count);

  // Precompute seeds for batching
  size_t num_batches = (seed_count + batch_size - 1) / batch_size;
  cw->precomputed_seeds = malloc(sizeof(uint128_t *) * num_batches);
  cw->precomputed_batch_sizes = malloc(sizeof(size_t) * num_batches);

  for (size_t batch = 0; batch < num_batches; batch++) {
    size_t batch_start = batch * batch_size;
    size_t current_batch_size = (batch_start + batch_size > seed_count)
                                    ? (seed_count - batch_start)
                                    : batch_size;
    cw->precomputed_batch_sizes[batch] = current_batch_size;

    size_t precomp_size = 1ULL << current_batch_size;
    cw->precomputed_seeds[batch] = malloc(sizeof(uint128_t) * precomp_size);

    // Initialize with zero
    cw->precomputed_seeds[batch][0] = 0;

    // Build precomputed table
    for (size_t i = 0; i < current_batch_size; i++) {
      uint128_t seed_val = seeds[batch_start + i];
      size_t step = 1ULL << i;
      for (size_t j = 0; j < step; j++) {
        cw->precomputed_seeds[batch][j + step] =
            cw->precomputed_seeds[batch][j] ^ seed_val;
      }
    }
  }

  return cw;
}

void destroyCW(CW *cw) {
  if (cw) {
    free(cw->seeds);
    if (cw->precomputed_seeds) {
      size_t num_batches =
          (cw->seed_count + cw->batch_size - 1) / cw->batch_size;
      for (size_t i = 0; i < num_batches; i++) {
        free(cw->precomputed_seeds[i]);
      }
      free(cw->precomputed_seeds);
    }
    free(cw->precomputed_batch_sizes);
    free(cw);
  }
}

uint128_t correctCW(CW *cw, Signs *input_signs, bool has_left, bool has_right,
                    Signs *output_left, Signs *output_right) {
  uint128_t correct_node = 0;

  // Simple correction logic (simplified from Rust version)
  for (size_t i = 0; i < cw->seed_count && i < input_signs->count; i++) {
    if (getSignBit(input_signs, i)) {
      correct_node ^= cw->seeds[i];
    }
  }

  return correct_node;
}

// ================= Conversion CW Implementation =================

ConvCW *createConvCW(uint64_t *inputs, uint8_t *data, uint128_t *seed_0,
                     uint128_t *seed_1, Signs *sign_0, size_t count,
                     size_t data_size, size_t batch_size) {
  ConvCW *conv_cw = malloc(sizeof(ConvCW));
  conv_cw->conv_count = count;
  conv_cw->data_size = data_size;
  conv_cw->batch_size = batch_size;

  conv_cw->conv_values = malloc(sizeof(uint8_t *) * count);
  for (size_t i = 0; i < count; i++) {
    conv_cw->conv_values[i] = malloc(data_size);
    // Data for input i starts at data + (i * data_size)
    memcpy(conv_cw->conv_values[i], &data[i * data_size], data_size);

    // Simple XOR with seed conversion (placeholder)
    for (size_t j = 0; j < data_size && j < 16; j++) {
      conv_cw->conv_values[i][j] ^=
          ((uint8_t *)&seed_0[i])[j] ^ ((uint8_t *)&seed_1[i])[j];
    }

    // Apply sign correction
    if (getSignBit(sign_0, i)) {
      for (size_t j = 0; j < data_size; j++) {
        conv_cw->conv_values[i][j] = ~conv_cw->conv_values[i][j];
      }
    }
  }

  conv_cw->precomputed_conv = NULL; // Simplified
  conv_cw->batch_sizes = NULL;

  return conv_cw;
}

void destroyConvCW(ConvCW *conv_cw) {
  if (conv_cw) {
    if (conv_cw->conv_values) {
      for (size_t i = 0; i < conv_cw->conv_count; i++) {
        free(conv_cw->conv_values[i]);
      }
      free(conv_cw->conv_values);
    }
    free(conv_cw);
  }
}

void convCorrect(ConvCW *conv_cw, Signs *signs, uint8_t *output,
                 size_t data_size) {
  memset(output, 0, data_size);

  // Simple summation of correction values based on signs
  for (size_t i = 0; i < conv_cw->conv_count; i++) {
    if (getSignBit(signs, i)) {
      for (size_t j = 0; j < data_size && j < conv_cw->data_size; j++) {
        output[j] ^= conv_cw->conv_values[i][j];
      }
    }
  }
}

// ================= Main DMPF Implementation =================

/**
 * @brief Generate a DMPF for a given set of inputs using big state approach
 * @param ctx: the context for the PRG
 * @param size: the domain size of the DMPF (log of domain size)
 * @param dataSize: the size of the data to be evaluated
 * @param in: the inputs to the DMPF (must be sorted)
 * @param inl: the length of the inputs
 * @param data: array of data values corresponding to inputs (continuous memory)
 * @param batch_size: batching parameter for optimization
 * @param k0: the key for the server A
 * @param k1: the key for the server B
 * @return: void
 */
void genBigStateDMPF(EVP_CIPHER_CTX *ctx, int size, int dataSize, uint64_t *in,
                     uint64_t inl, uint8_t *data, size_t batch_size,
                     uint8_t *k0, uint8_t *k1) {
  // Verify inputs are sorted
  for (uint64_t i = 0; i < inl - 1; i++) {
    if (in[i] >= in[i + 1]) {
      printf("Error: Inputs are not properly sorted\n");
      exit(1);
    }
  }

  // Convert inputs to trie format
  uint64_t *trie_words = malloc(sizeof(uint64_t) * inl);
  for (uint64_t i = 0; i < inl; i++) {
    trie_words[i] = in[i] >> (64 - size);
  }

  BinaryTrie *trie = createBinaryTrie(trie_words, inl, size);

  // Initialize state
  size_t t = inl;
  Signs *signs_0 = createSigns(t);
  Signs *signs_1 = createSigns(t);
  Signs *next_signs_0 = createSigns(t);
  Signs *next_signs_1 = createSigns(t);

  uint128_t *seed_0 = malloc(sizeof(uint128_t) * t);
  uint128_t *seed_1 = malloc(sizeof(uint128_t) * t);
  uint128_t *next_seed_0 = malloc(sizeof(uint128_t) * t);
  uint128_t *next_seed_1 = malloc(sizeof(uint128_t) * t);

  // Initialize roots
  uint128_t root_0 = getRandomBlock();
  uint128_t root_1 = getRandomBlock();
  seed_0[0] = root_0;
  seed_1[0] = root_1;

  // Set initial signs
  setSignBit(signs_1, 0, true);

  CW **cws = malloc(sizeof(CW *) * size);

  // Main generation loop
  for (int depth = 0; depth < size; depth++) {
    size_t min_nodes = (t < (1ULL << depth)) ? t : (1ULL << depth);

    SignsCW *sign_cw = createSignsCW(t, depth);
    uint128_t *cw_seeds = malloc(sizeof(uint128_t) * min_nodes);

    // Generate correction words for this depth
    for (size_t idx = 0; idx < min_nodes; idx++) {
      bool has_left = trieHasSon(trie, idx, depth, false);
      bool has_right = trieHasSon(trie, idx, depth, true);

      if (!has_left && !has_right) {
        cw_seeds[idx] = 0;
        continue;
      }

      uint128_t current_seed_0 = seed_0[idx];
      uint128_t current_seed_1 = seed_1[idx];

      uint128_t seed_left_0, seed_right_0;
      uint128_t seed_left_1, seed_right_1;
      int t_left_0, t_right_0, t_left_1, t_right_1;

      dpfPRG(ctx, current_seed_0, &seed_left_0, &seed_right_0, &t_left_0,
             &t_right_0);
      dpfPRG(ctx, current_seed_1, &seed_left_1, &seed_right_1, &t_left_1,
             &t_right_1);

      uint128_t delta_seed_left = seed_left_0 ^ seed_left_1;
      uint128_t delta_seed_right = seed_right_0 ^ seed_right_1;

      if (has_left && has_right) {
        cw_seeds[idx] = getRandomBlock();
      } else if (has_left) {
        cw_seeds[idx] = delta_seed_right;
      } else {
        cw_seeds[idx] = delta_seed_left;
      }
    }

    cws[depth] =
        createCW(trie, sign_cw, cw_seeds, min_nodes, depth, batch_size);

    // Update state for next level
    size_t next_position = 0;
    for (size_t idx = 0; idx < min_nodes; idx++) {
      bool has_left = trieHasSon(trie, idx, depth, false);
      bool has_right = trieHasSon(trie, idx, depth, true);

      if (!has_left && !has_right)
        continue;

      uint128_t current_seed_0 = seed_0[idx];
      uint128_t current_seed_1 = seed_1[idx];

      uint128_t seed_left_0, seed_right_0;
      uint128_t seed_left_1, seed_right_1;
      int t_left_0, t_right_0, t_left_1, t_right_1;

      dpfPRG(ctx, current_seed_0, &seed_left_0, &seed_right_0, &t_left_0,
             &t_right_0);
      dpfPRG(ctx, current_seed_1, &seed_left_1, &seed_right_1, &t_left_1,
             &t_right_1);

      uint128_t correction = cw_seeds[idx];

      if (has_left) {
        next_seed_0[next_position] =
            seed_left_0 ^ (getSignBit(signs_0, idx) ? correction : 0);
        next_seed_1[next_position] =
            seed_left_1 ^ (getSignBit(signs_1, idx) ? correction : 0);
        // Update signs for next level
        fillSignsWithSeed(next_signs_0, next_seed_0[next_position], 0, ctx);
        fillSignsWithSeed(next_signs_1, next_seed_1[next_position], 0, ctx);
        next_position++;
      }
      if (has_right) {
        next_seed_0[next_position] =
            seed_right_0 ^ (getSignBit(signs_0, idx) ? correction : 0);
        next_seed_1[next_position] =
            seed_right_1 ^ (getSignBit(signs_1, idx) ? correction : 0);
        // Update signs for next level
        fillSignsWithSeed(next_signs_0, next_seed_0[next_position], 1, ctx);
        fillSignsWithSeed(next_signs_1, next_seed_1[next_position], 1, ctx);
        next_position++;
      }
    }

    // Swap state
    Signs *temp_signs;
    temp_signs = signs_0;
    signs_0 = next_signs_0;
    next_signs_0 = temp_signs;
    temp_signs = signs_1;
    signs_1 = next_signs_1;
    next_signs_1 = temp_signs;

    uint128_t *temp_seeds;
    temp_seeds = seed_0;
    seed_0 = next_seed_0;
    next_seed_0 = temp_seeds;
    temp_seeds = seed_1;
    seed_1 = next_seed_1;
    next_seed_1 = temp_seeds;

    free(cw_seeds);
  }

  // Generate conversion correction word
  ConvCW *conv_cw = createConvCW(in, data, seed_0, seed_1, signs_0, inl,
                                 dataSize, batch_size);

  // Pack keys (simplified serialization)
  // Key format: [root(16)] [sign(1)] [input_length(4)] [point_count(8)]
  // [cws_data] [conv_cw_data]
  memcpy(k0, &root_0, 16);
  k0[16] = 0; // sign for key 0
  memcpy(&k0[17], &size, 4);
  memcpy(&k0[21], &inl, 8);

  memcpy(k1, &root_1, 16);
  k1[16] = 1; // sign for key 1
  memcpy(&k1[17], &size, 4);
  memcpy(&k1[21], &inl, 8);

  // Cleanup
  destroyBinaryTrie(trie);
  destroySigns(signs_0);
  destroySigns(signs_1);
  destroySigns(next_signs_0);
  destroySigns(next_signs_1);

  for (int i = 0; i < size; i++) {
    destroyCW(cws[i]);
  }
  free(cws);
  destroyConvCW(conv_cw);

  free(trie_words);
  free(seed_0);
  free(seed_1);
  free(next_seed_0);
  free(next_seed_1);
}

/**
 * @brief Evaluate big state DMPF at a single point
 * @param ctx: the context for the PRG
 * @param k: the DMPF key
 * @param x: the input to evaluate
 * @param dataSize: the size of the output data
 * @param dataShare: the output share
 */
void evalBigStateDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, uint64_t x, int dataSize,
                      uint8_t *dataShare) {
  // Initialize output to zero
  memset(dataShare, 0, dataSize);

  // Read number of points
  uint64_t num_points;
  memcpy(&num_points, k, 8);

  size_t offset = 8;

  // Calculate DPF key size (from DPF implementation)
  // Each DPF key has format: [size(1)] [root(16)] [sign(1)] [cws...] [lastCW]
  // For each level: 18 bytes (16 for sCW + 2 for tCW)
  // Plus final correction word of dataSize

  for (uint64_t i = 0; i < num_points; i++) {
    // Read the input point for this DPF
    uint64_t point;
    memcpy(&point, &k[offset], 8);
    offset += 8;

    // Extract the DPF key
    uint8_t *dpf_key = &k[offset];

    // Get the size from the DPF key
    int dpf_size = dpf_key[0];
    size_t dpf_key_size = 18 * dpf_size + 18 + dataSize;

    // Evaluate this DPF at point x
    uint8_t *dpf_output = malloc(dataSize);
    evalDPF(ctx, dpf_key, x, dataSize, dpf_output);

    // Add to the total output (XOR for additive sharing)
    for (int j = 0; j < dataSize; j++) {
      dataShare[j] ^= dpf_output[j];
    }

    free(dpf_output);
    offset += dpf_key_size;
  }
}

/**
 * @brief Generate a DMPF for a given set of inputs
 *        The global security parameter lambda is 128 bits.
 * @param ctx: the context for the PRG
 * @param size: the domain size of the DMPF
 * @param dataSize: the size of the data to be evaluated
 * @param in: the inputs to the DMPF
 * @param inl: the length of the inputs
 * @param data: array of data values corresponding to inputs (continuous memory)
 * @param k0: the key for the server A
 * @param k1: the key for the server B
 * @return: void
 * @result: 2 dmpf keys
 *          k0: the key for the server A
 *          k1: the key for the server B
 */
void genDMPF(EVP_CIPHER_CTX *ctx, int size, int dataSize, uint64_t *in,
             uint64_t inl, uint8_t *data, uint8_t *k0, uint8_t *k1) {
  // make sure inputs are well-sorted
  for (int i = 0; i < inl - 1; i++) {
    if (in[i] > in[i + 1]) {
      printf("Inputs are not well-sorted\n");
      exit(1);
    }
  }

  // For simplicity, implement DMPF as multiple DPFs
  // Key format: [num_points(8)] [point1(8)] [dpf_key1] [point2(8)] [dpf_key2]
  // ...

  // Write number of points
  memcpy(k0, &inl, 8);
  memcpy(k1, &inl, 8);

  size_t offset = 8;

  for (uint64_t i = 0; i < inl; i++) {
    // Write the input point
    memcpy(&k0[offset], &in[i], 8);
    memcpy(&k1[offset], &in[i], 8);
    offset += 8;

    // Generate DPF for this point using the provided data
    // Data for input i starts at data + (i * dataSize)
    size_t dpf_key_size = 18 * size + 18 + dataSize;
    genDPF(ctx, size, in[i], dataSize, &data[i * dataSize], &k0[offset],
           &k1[offset]);
    offset += dpf_key_size;
  }
}

/**
 * @brief Evaluate big state DMPF over the full domain
 * @param ctx: the context for the PRG
 * @param k: the DMPF key
 * @param dataSize: the size of the output data
 * @param out: the output array (must be pre-allocated with size domain_size *
 * dataSize)
 */
void fullDomainBigStateDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, int dataSize,
                            uint8_t *out) {
  // Read number of points
  uint64_t num_points;
  memcpy(&num_points, k, 8);

  size_t offset = 8;

  // Calculate domain size from the first DPF key
  if (num_points == 0) {
    return; // No points to evaluate
  }

  // Read the first point and extract domain size from DPF key
  uint64_t first_point;
  memcpy(&first_point, &k[offset], 8);
  offset += 8;

  uint8_t *dpf_key = &k[offset];
  int domain_bits = dpf_key[0]; // First byte is the domain size
  size_t domain_size = 1ULL << domain_bits;

  // Initialize output to all zeros
  memset(out, 0, domain_size * dataSize);

  // Reset offset to start processing all DPF keys
  offset = 8;

  // For each DPF, evaluate over the full domain and accumulate results
  for (uint64_t i = 0; i < num_points; i++) {
    // Skip the input point (8 bytes)
    offset += 8;

    // Extract the DPF key
    uint8_t *current_dpf_key = &k[offset];
    size_t dpf_key_size = 18 * domain_bits + 18 + dataSize;

    // Evaluate this DPF over the full domain
    uint8_t *dpf_output = malloc(domain_size * dataSize);
    fullDomainDPF(ctx, domain_bits, current_dpf_key, dataSize, dpf_output);

    // Add to the total output (XOR for additive sharing)
    for (size_t j = 0; j < domain_size * dataSize; j++) {
      out[j] ^= dpf_output[j];
    }

    free(dpf_output);
    offset += dpf_key_size;
  }
}
