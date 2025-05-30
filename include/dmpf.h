#ifndef _DMPF
#define _DMPF

#include "common.h"
#include "dpf.h"
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>

// DMPF structures based on Rust big_state implementation

typedef struct {
    uint128_t *nodes;
    size_t capacity;
    size_t count;
    size_t nodes_per_sign;
} Signs;

typedef struct {
    size_t t;
    uint128_t *nodes;
    size_t nodes_per_point_per_direction;
} SignsCW;

typedef struct {
    uint128_t *seeds;
    SignsCW *signs;
    uint128_t **precomputed_seeds;
    size_t *precomputed_batch_sizes;
    size_t seed_count;
    size_t batch_size;
} CW;

typedef struct {
    uint8_t **conv_values;
    uint8_t **precomputed_conv;
    size_t *batch_sizes;
    size_t conv_count;
    size_t batch_size;
    size_t data_size;
} ConvCW;

typedef struct {
    uint64_t *words;
    size_t word_count;
    size_t bit_length;
    size_t *level_counts;
    bool **has_left;
    bool **has_right;
} BinaryTrie;

typedef struct {
    uint128_t root;
    bool sign;
    CW *cws;
    ConvCW *conv_cw;
    size_t input_length;
    size_t point_count;
} BigStateDmpfKey;

// Main DMPF functions
extern void genBigStateDMPF(EVP_CIPHER_CTX *ctx, int size, int dataSize, 
                           uint64_t *in, uint64_t inl, uint8_t *data,
                           size_t batch_size, uint8_t *k0, uint8_t *k1);
extern void evalBigStateDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, uint64_t x, 
                            int dataSize, uint8_t *dataShare);
extern void fullDomainBigStateDMPF(EVP_CIPHER_CTX *ctx, uint8_t *k, 
                                   int dataSize, uint8_t *out);

// Original DMPF interface - delegates to big state implementation
extern void genDMPF(EVP_CIPHER_CTX *ctx, int size, int dataSize, uint64_t *in,
                   uint64_t inl, uint8_t *data, uint8_t *k0, uint8_t *k1);

// Helper functions for Signs
extern Signs* createSigns(size_t t);
extern void destroySigns(Signs* signs);
extern void setSignBit(Signs* signs, size_t bit_idx, bool value);
extern bool getSignBit(Signs* signs, size_t bit_idx);
extern void zeroSigns(Signs* signs);
extern void fillSignsWithSeed(Signs* signs, uint128_t seed, int direction, EVP_CIPHER_CTX* ctx);
extern void xorSigns(Signs* dest, Signs* a, Signs* b);

// Helper functions for SignsCW
extern SignsCW* createSignsCW(size_t t, size_t depth);
extern void destroySignsCW(SignsCW* signs_cw);

// Helper functions for BinaryTrie
extern BinaryTrie* createBinaryTrie(uint64_t *words, size_t word_count, size_t bit_length);
extern void destroyBinaryTrie(BinaryTrie* trie);
extern bool trieHasSon(BinaryTrie* trie, size_t node_idx, size_t depth, bool direction);

// Helper functions for CW (Correction Words)
extern CW* createCW(BinaryTrie* trie, SignsCW* signs, uint128_t* seeds, 
                   size_t seed_count, size_t depth, size_t batch_size);
extern void destroyCW(CW* cw);
extern uint128_t correctCW(CW* cw, Signs* input_signs, bool has_left, bool has_right,
                          Signs* output_left, Signs* output_right);

// Helper functions for ConvCW (Conversion Correction Words)
extern ConvCW* createConvCW(uint64_t* inputs, uint8_t* data, uint128_t* seed_0, 
                           uint128_t* seed_1, Signs* sign_0, size_t count, 
                           size_t data_size, size_t batch_size);
extern void destroyConvCW(ConvCW* conv_cw);
extern void convCorrect(ConvCW* conv_cw, Signs* signs, uint8_t* output, size_t data_size);

#endif 