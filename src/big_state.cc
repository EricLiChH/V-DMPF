// g++ -Wall -Wextra -O2 -std=c++17 -Iinclude src/big_state.cc obj/dpf.o obj/common.o obj/mmo.o -o big_state -lssl -lcrypto
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdint.h>
#include <vector>
#include <set>
#include <openssl/rand.h>

#include "../include/common.h"
#include "../include/mmo.h"
#include "../include/dpf.h"

using CW = std::tuple<uint128_t, int, int>;

const int HEAD_SIZE = 19;
const int DMPF_CW_SIZE = 24;

// Export these functions with C linkage so they can be called from C code
extern "C" {
    void genBigStateDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index, int dataSize,
                         uint8_t *data, uint8_t *k0, uint8_t *k1);
    
    void evalBigStateDMPF(EVP_CIPHER_CTX *ctx, uint64_t index, int dataSize, uint8_t *dataShare,
                          uint8_t *k);
    
    void fullDomainBigStateDMPF(EVP_CIPHER_CTX *ctx, unsigned char *k, int dataSize, uint8_t *out);
}

CW bigStateCorrect(const int &t, const int &index, const std::vector<CW> &CWs)
{
    uint128_t sCW = 0;
    int tCW0 = 0, tCW1 = 0;
    int cnt = 1;

    for (const auto &cw : CWs)
    {
        if (cnt > t)
        {
            std::cerr << "Error: Counter exceeds the number of correction words" << std::endl;
            exit(EXIT_FAILURE);
        }
        uint128_t s = std::get<0>(cw);
        int t0 = std::get<1>(cw);
        int t1 = std::get<2>(cw);

        int bit = getbit(index, t, cnt++);

        if (bit == 1)
        {
            sCW ^= s;
            tCW0 ^= t0;
            tCW1 ^= t1;
        }
    }

    return std::make_tuple(sCW, tCW0, tCW1);
}

// this is the PRG used for the DPF
void dmpfPRG(EVP_CIPHER_CTX *ctx, int t, uint128_t input, uint128_t *output1, uint128_t *output2, int *bit1, int *bit2)
{
    input = set_lsb_zero(input);

    uint128_t stashin[2];
    stashin[0] = input;
    stashin[1] = reverse_lsb(input);

    int len = 0;
    uint128_t stash[2] = {0, 0};

    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)&stash[0], &len, (uint8_t *)&stashin[0], 32))
        printf("errors occured in encrypt\n");

    stash[0] = stash[0] ^ input;
    stash[1] = stash[1] ^ input;
    stash[1] = reverse_lsb(stash[1]);

    // Extract t bits from stash[0] and stash[1] instead of just the LSB
    // Use the lower t bits of each stash value
    *bit1 = stash[0] & ((1 << t) - 1);
    *bit2 = stash[1] & ((1 << t) - 1);

    *output1 = set_lsb_zero(stash[0]);
    *output2 = set_lsb_zero(stash[1]);
}

void genBigStateDMPF(EVP_CIPHER_CTX *ctx, int t, int size, uint64_t *index, int dataSize,
                     uint8_t *data, uint8_t *k0, uint8_t *k1)
{
    // Initialize seeds and bits
    for (int i = 0; i < t - 1; i++)
    {
        if (index[i] >= index[i + 1])
        {
            std::cerr << "Error: index[" << i << "] >= index[" << i + 1 << "]" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // construct sorted index
    std::vector<std::set<uint64_t>> sortedIndex(size + 1);
    for (int i = 1; i <= size; i++)
    {
        for (int j = 0; j < t; j++)
        {
            // get the first i bits of index[j]
            auto prefix = index[j] >> (size - i);
            sortedIndex[i].insert(prefix);
        }
    }
    // empty string in the first layer
    sortedIndex[0].insert(0);
    std::vector<uint128_t> seeds0(t);
    std::vector<uint128_t> seeds1(t);
    auto root0 = getRandomBlock();
    auto root1 = getRandomBlock();

    seeds0[0] = root0; // L
    seeds1[0] = root1; // R

    std::vector<int> bits0(t);
    std::vector<int> bits1(t);
    bits0[0] = 0;            // L
    bits1[0] = 1 << (t - 1); // R

    uint128_t s0[2], s1[2]; // 0=L,1=R
    int t0[2], t1[2];

    uint128_t sCW;
    int tCW0, tCW1;

    // n * t CWs
    std::vector<std::vector<CW>> CWs(size);
    for (int i = 0; i < size; i++)
    {
        CWs[i].resize(t);
    }

    for (int i = 1; i <= size; i++)
    {
        // std::cout << "Processing layer " << i << " with " << sortedIndex[i].size() << " prefixes." << std::endl;
        auto it = sortedIndex[i - 1].begin();
        std::vector<uint128_t> nextSeeds0(t), nextSeeds1(t);
        std::vector<int> nextBits0(t), nextBits1(t);

        std::vector<uint128_t> s0Left(t), s0Right(t), s1Left(t), s1Right(t);
        std::vector<int> t0Left(t), t0Right(t), t1Left(t), t1Right(t);

        for (size_t j = 0; j < sortedIndex[i - 1].size(); j++)
        {
            // current prefix
            uint64_t prefix = *it;
            it++;

            dmpfPRG(ctx, t, seeds0[j], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
            dmpfPRG(ctx, t, seeds1[j], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

            // store tmp prg value
            s0Left[j] = s0[LEFT];
            s0Right[j] = s0[RIGHT];
            s1Left[j] = s1[LEFT];
            s1Right[j] = s1[RIGHT];
            t0Left[j] = t0[LEFT];
            t0Right[j] = t0[RIGHT];
            t1Left[j] = t1[LEFT];
            t1Right[j] = t1[RIGHT];

            tCW0 = t0[LEFT] ^ t1[LEFT];
            tCW1 = t0[RIGHT] ^ t1[RIGHT];

            auto leftIt = sortedIndex[i].find(prefix << 1);
            auto rightIt = sortedIndex[i].find((prefix << 1) + 1);
            bool hasLeft = leftIt != sortedIndex[i].end();
            bool hasRight = rightIt != sortedIndex[i].end();

            if (hasLeft and hasRight)
            {
                sCW = getRandomBlock();
                // get the index of the left child
                int d = std::distance(sortedIndex[i].begin(), leftIt);
                tCW0 = tCW0 ^ (1 << (t - 1 - d));
                tCW1 = tCW1 ^ (1 << (t - 2 - d));
                CWs[i - 1][j] = std::make_tuple(sCW, tCW0, tCW1);
            }
            else if (hasLeft)
            {
                // right is lose
                sCW = s0[RIGHT] ^ s1[RIGHT];
                int d = std::distance(sortedIndex[i].begin(), leftIt);
                tCW0 = tCW0 ^ (1 << (t - 1 - d));
                CWs[i - 1][j] = std::make_tuple(sCW, tCW0, tCW1);
            }
            else if (hasRight)
            {
                // left is lose
                sCW = s0[LEFT] ^ s1[LEFT];
                int d = std::distance(sortedIndex[i].begin(), rightIt);
                tCW1 = tCW1 ^ (1 << (t - 1 - d));
                CWs[i - 1][j] = std::make_tuple(sCW, tCW0, tCW1);
            }
            else
            {
                std::cerr << "Error: Neither left nor right child found for prefix " << prefix << std::endl;
                std::cerr << "Left child: " << (prefix << 1) << std::endl;
                std::cerr << "Right child: " << ((prefix << 1) + 1) << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        it = sortedIndex[i - 1].begin();
        for (size_t j = 0; j < sortedIndex[i - 1].size(); j++)
        {
            uint64_t prefix = *it;
            it++;

            s0[LEFT] = s0Left[j];
            s0[RIGHT] = s0Right[j];
            s1[LEFT] = s1Left[j];
            s1[RIGHT] = s1Right[j];
            t0[LEFT] = t0Left[j];
            t0[RIGHT] = t0Right[j];
            t1[LEFT] = t1Left[j];
            t1[RIGHT] = t1Right[j];

            auto [sCW0, tCW0Left, tCW0Right] = bigStateCorrect(t, bits0[j], CWs[i - 1]);
            auto [sCW1, tCW1Left, tCW1Right] = bigStateCorrect(t, bits1[j], CWs[i - 1]);

            bool hasLeft = sortedIndex[i].find(prefix << 1) != sortedIndex[i].end();
            bool hasRight = sortedIndex[i].find((prefix << 1) + 1) != sortedIndex[i].end();

            if (hasLeft)
            {
                auto leftIt = sortedIndex[i].find(prefix << 1);
                int leftIdx = std::distance(sortedIndex[i].begin(), leftIt);
                nextSeeds0[leftIdx] = s0[LEFT] ^ sCW0;
                nextSeeds1[leftIdx] = s1[LEFT] ^ sCW1;
                nextBits0[leftIdx] = t0[LEFT] ^ tCW0Left;
                nextBits1[leftIdx] = t1[LEFT] ^ tCW1Left;
            }

            if (hasRight)
            {
                auto rightIt = sortedIndex[i].find((prefix << 1) + 1);
                int rightIdx = std::distance(sortedIndex[i].begin(), rightIt);
                nextSeeds0[rightIdx] = (s0[RIGHT] ^ sCW0);
                nextSeeds1[rightIdx] = (s1[RIGHT] ^ sCW1);
                nextBits0[rightIdx] = (t0[RIGHT] ^ tCW0Right);
                nextBits1[rightIdx] = (t1[RIGHT] ^ tCW1Right);
            }
        }

        // Update seeds and bits for the next iteration
        seeds0 = std::move(nextSeeds0);
        seeds1 = std::move(nextSeeds1);
        bits0 = std::move(nextBits0);
        bits1 = std::move(nextBits1);
    }

    for (int i = 0; i < t; i++)
    {
        // Use CTR mode encryption to generate PRG output
        EVP_CIPHER_CTX *seedCtx0;
        EVP_CIPHER_CTX *seedCtx1;
        int len = 0;
        if (!(seedCtx0 = EVP_CIPHER_CTX_new()))
            printf("errors occurred in creating context\n");
        if (!(seedCtx1 = EVP_CIPHER_CTX_new()))
            printf("errors occurred in creating context\n");

        // generate lastCW
        // Allocate memory for data conversion
        uint8_t *lastCW = (uint8_t *)malloc(dataSize);
        uint8_t *convert0 = (uint8_t *)malloc(dataSize + 16);
        uint8_t *convert1 = (uint8_t *)malloc(dataSize + 16);
        uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
        memset(zeros, 0, dataSize + 16);
        memcpy(lastCW, data + i * dataSize, dataSize);

        if (1 != EVP_EncryptInit_ex(seedCtx0, EVP_aes_128_ctr(), NULL,
                                    (uint8_t *)&seeds0[i], NULL))
            printf("errors occurred in init of dpf gen\n");
        if (1 != EVP_EncryptInit_ex(seedCtx1, EVP_aes_128_ctr(), NULL,
                                    (uint8_t *)&seeds1[i], NULL))
            printf("errors occurred in init of dpf gen\n");
        if (1 != EVP_EncryptUpdate(seedCtx0, convert0, &len, zeros, dataSize))
            printf("errors occurred in encrypt\n");
        if (1 != EVP_EncryptUpdate(seedCtx1, convert1, &len, zeros, dataSize))
            printf("errors occurred in encrypt\n");

        // Calculate final lastCW_i
        for (int j = 0; j < dataSize; j++)
        {
            lastCW[j] = lastCW[j] ^ ((uint8_t *)convert0)[j] ^ ((uint8_t *)convert1)[j];
        }

        memcpy(k0 + HEAD_SIZE + size * t * DMPF_CW_SIZE + i * dataSize, lastCW, dataSize);
        EVP_CIPHER_CTX_free(seedCtx0);
        EVP_CIPHER_CTX_free(seedCtx1);

        // cleanup
        free(zeros);
        free(convert0);
        free(convert1);
        free(lastCW);
    }

    // Prepare k0 and k1
    // k0 and k1 are of size HEAD_SIZE + size * t * DMP
    k0[0] = size;
    k0[1] = t;
    k0[HEAD_SIZE - 1] = 0;
    memcpy(&k0[2], &root0, 16);
    // copy CWs to k0
    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < t; j++)
        {
            uint128_t sCW = std::get<0>(CWs[i][j]);
            int tCW0 = std::get<1>(CWs[i][j]);
            int tCW1 = std::get<2>(CWs[i][j]);

            memcpy(&k0[HEAD_SIZE + (i * t + j) * DMPF_CW_SIZE], &sCW, 16);
            memcpy(&k0[HEAD_SIZE + (i * t + j) * DMPF_CW_SIZE + 16], &tCW0, 4);
            memcpy(&k0[HEAD_SIZE + (i * t + j) * DMPF_CW_SIZE + 20], &tCW1, 4);
        }
    }

    // copy k1
    memcpy(k1, k0, HEAD_SIZE + size * t * DMPF_CW_SIZE + t * dataSize);
    k1[0] = size;
    k1[1] = t;
    k1[HEAD_SIZE - 1] = 1;
    memcpy(&k1[2], &root1, 16);
}

void evalBigStateDMPF(EVP_CIPHER_CTX *ctx, uint64_t index, int dataSize, uint8_t *dataShare,
                      uint8_t *k)
{
    // parse the key
    int size = k[0];
    int t = k[1];
    int bit = 0;
    uint128_t seed;
    memcpy(&seed, &k[2], 16);
    if (k[HEAD_SIZE - 1] == 1)
    {
        bit = 1 << (t - 1);
    }

    std::vector<CW> CWs(t);
    uint128_t sCW;
    int tCW0, tCW1;

    uint128_t sL, sR;
    int tL, tR;

    for (int i = 1; i <= size; i++)
    {
        CWs.clear();
        CWs.resize(t);
        for (int j = 0; j < t; j++)
        {
            memcpy(&sCW, &k[HEAD_SIZE + ((i - 1) * t + j) * DMPF_CW_SIZE], 16);
            memcpy(&tCW0, &k[HEAD_SIZE + ((i - 1) * t + j) * DMPF_CW_SIZE + 16], 4);
            memcpy(&tCW1, &k[HEAD_SIZE + ((i - 1) * t + j) * DMPF_CW_SIZE + 20], 4);
            CWs[j] = std::make_tuple(sCW, tCW0, tCW1);
        }
        auto [sCW, tCW0, tCW1] = bigStateCorrect(t, bit, CWs);
        dmpfPRG(ctx, t, seed, &sL, &sR, &tL, &tR);
        int indexBit = getbit(index, size, i);

        if (indexBit == 0)
        {
            seed = sL ^ sCW;
            bit = tL ^ tCW0;
        }
        else
        {
            seed = sR ^ sCW;
            bit = tR ^ tCW1;
        }
    }

    // Generate dataShare using PRG with the final seed
    int len = 0;
    uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
    if (!zeros)
    {
        std::cerr << "Failed to allocate memory for zeros" << std::endl;
        return;
    }
    memset(zeros, 0, dataSize + 16);
    memset(dataShare, 0, dataSize); // Initialize dataShare with zeros, only dataSize bytes
    EVP_CIPHER_CTX *seedCtx;
    if (!(seedCtx = EVP_CIPHER_CTX_new()))
    {
        printf("errors occurred in creating context\n");
        free(zeros);
        return;
    }
    if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                                (uint8_t *)&seed, NULL))
    {
        printf("errors occurred in init of dpf eval\n");
        EVP_CIPHER_CTX_free(seedCtx);
        free(zeros);
        return;
    }
    if (1 != EVP_EncryptUpdate(seedCtx, dataShare, &len, zeros, dataSize))
    {
        printf("errors occurred in encrypt\n");
        EVP_CIPHER_CTX_free(seedCtx);
        free(zeros);
        return;
    }

    for (int i = 0; i < t; i++)
    {
        if (getbit(bit, t, i + 1) == 1)
        {
            // If t[i] == 1, xor in the correction word (lastCW) from the key
            // The correction word is at the end of the key: offset = HEAD_SIZE + size * t * DMPF_CW_SIZE + i * dataSize
            for (int j = 0; j < dataSize; j++)
            {
                dataShare[j] ^= k[HEAD_SIZE + size * t * DMPF_CW_SIZE + i * dataSize + j];
            }
        }
    }
    EVP_CIPHER_CTX_free(seedCtx);
    free(zeros);
}

void fullDomainBigStateDMPF(EVP_CIPHER_CTX *ctx, unsigned char *k, int dataSize, uint8_t *out)
{
    // parse the key
    int size = k[0];
    int t = k[1];
    int bit = 0;
    uint128_t root;
    memcpy(&root, &k[2], 16);
    if (k[HEAD_SIZE - 1] == 1)
    {
        bit = 1 << (t - 1);
    }
    
    // Pre-calculate constants
    int domainSize = 1 << size;
    int cwOffset = HEAD_SIZE + size * t * DMPF_CW_SIZE;
    
    // Pre-allocate vectors with exact size to avoid reallocation
    std::vector<uint128_t> seeds(domainSize);
    std::vector<int> bits(domainSize);
    seeds[0] = root; // root seed
    bits[0] = bit;   // root bit

    // Pre-allocate CWs vector once and reuse
    std::vector<CW> CWs(t);
    uint128_t sCW;
    int tCW0, tCW1;

    uint128_t sL, sR;
    int tL, tR;

    // Pre-allocate next vectors to avoid repeated allocation
    std::vector<uint128_t> nextSeeds(domainSize);
    std::vector<int> nextBits(domainSize);

    for (int i = 1; i <= size; i++)
    {
        // Load CWs for this layer - reuse the same vector
        for (int j = 0; j < t; j++)
        {
            int offset = HEAD_SIZE + ((i - 1) * t + j) * DMPF_CW_SIZE;
            memcpy(&sCW, &k[offset], 16);
            memcpy(&tCW0, &k[offset + 16], 4);
            memcpy(&tCW1, &k[offset + 20], 4);
            CWs[j] = std::make_tuple(sCW, tCW0, tCW1);
        }

        int prevLayerSize = 1 << (i - 1);
        for (int j = 0; j < prevLayerSize; j++)
        {
            dmpfPRG(ctx, t, seeds[j], &sL, &sR, &tL, &tR);
            auto [sCW, tCW0, tCW1] = bigStateCorrect(t, bits[j], CWs);

            nextSeeds[2 * j] = sL ^ sCW;
            nextSeeds[2 * j + 1] = sR ^ sCW;
            nextBits[2 * j] = tL ^ tCW0;
            nextBits[2 * j + 1] = tR ^ tCW1;
        }

        // Swap vectors instead of move to avoid deallocation
        seeds.swap(nextSeeds);
        bits.swap(nextBits);
    }

    // Pre-allocate zeros buffer once
    uint8_t *zeros = (uint8_t *)malloc(dataSize + 16);
    if (!zeros)
    {
        std::cerr << "Failed to allocate memory for zeros" << std::endl;
        return;
    }
    memset(zeros, 0, dataSize + 16);
    memset(out, 0, domainSize * dataSize); // Initialize out with zeros

    // Pre-allocate a single EVP_CIPHER_CTX and reuse it
    EVP_CIPHER_CTX *seedCtx = EVP_CIPHER_CTX_new();
    if (!seedCtx)
    {
        printf("errors occurred in creating context\n");
        free(zeros);
        return;
    }

    int len = 0;
    for (int i = 0; i < domainSize; i++)
    {
        // Reset context for each iteration instead of creating new one
        EVP_CIPHER_CTX_reset(seedCtx);
        
        if (1 != EVP_EncryptInit_ex(seedCtx, EVP_aes_128_ctr(), NULL,
                                    (uint8_t *)&seeds[i], NULL))
        {
            printf("errors occurred in init of dpf eval\n");
            EVP_CIPHER_CTX_free(seedCtx);
            free(zeros);
            return;
        }
        if (1 != EVP_EncryptUpdate(seedCtx, out + i * dataSize, &len, zeros, dataSize))
        {
            printf("errors occurred in encrypt\n");
            EVP_CIPHER_CTX_free(seedCtx);
            free(zeros);
            return;
        }

        // Apply correction words - cache the offset calculation
        uint8_t *outPtr = out + i * dataSize;
        for (int j = 0; j < t; j++)
        {
            if (getbit(bits[i], t, j + 1) == 1)
            {
                uint8_t *cwPtr = k + cwOffset + j * dataSize;
                for (int l = 0; l < dataSize; l++)
                {
                    outPtr[l] ^= cwPtr[l];
                }
            }
        }
    }

    EVP_CIPHER_CTX_free(seedCtx);
    free(zeros);
}
