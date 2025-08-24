#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h> 
#include <stdio.h>  

// ++++++++++++++++ PRNG 結構體定義 ++++++++++++++++
struct Xoshiro256StarStar {
    uint64_t s[4];
};

static inline uint64_t rotl(const uint64_t x, int k) { 
    return (x << k) | (x >> (64 - k)); 
}

// 產生器核心
static inline uint64_t xoshiro_next(struct Xoshiro256StarStar* gen) {
    const uint64_t result = rotl(gen->s[1] * 5, 7) * 9;
    const uint64_t t = gen->s[1] << 17;
    gen->s[2] ^= gen->s[0]; 
    gen->s[3] ^= gen->s[1]; 
    gen->s[1] ^= gen->s[2]; 
    gen->s[0] ^= gen->s[3];
    gen->s[2] ^= t; 
    gen->s[3] = rotl(gen->s[3], 45);
    return result;
}

// PRNG 初始化函數
static inline void xoshiro_init(struct Xoshiro256StarStar* gen, uint64_t seed[4]) {
    gen->s[0] = seed[0];
    gen->s[1] = seed[1];
    gen->s[2] = seed[2];
    gen->s[3] = seed[3];
    
    if (gen->s[0] == 0 && gen->s[1] == 0 && gen->s[2] == 0 && gen->s[3] == 0) {
        gen->s[0] = 0x9E3779B97F4A7C15;
        gen->s[1] = 0xF39CC0605CEDC834;
        gen->s[2] = 0x1082276BF3A27251;
        gen->s[3] = 0x86F4E4F2590D0B07;
    }
    
    for (int i = 0; i < 4; i++) {
        xoshiro_next(gen);
    }
}

static inline uint32_t fast_map_to_range_64(uint64_t rand64, uint32_t range) {
    unsigned __int128 product = (unsigned __int128)rand64 * range;
    return (uint32_t)(product >> 64);
}

static inline uint32_t fast_map_to_range_32(uint32_t rand32, uint32_t range) {
    uint64_t product = (uint64_t)rand32 * range;
    return (uint32_t)(product >> 32);
}

#define fast_map_to_range fast_map_to_range_64

static inline uint32_t map_to_range_unbiased(struct Xoshiro256StarStar* gen, uint32_t range) {
    if (range == 0) return 0;
    uint64_t product = (uint64_t)(uint32_t)xoshiro_next(gen) * range;
    uint32_t low = (uint32_t)product;
    if (low < range) {
        uint32_t threshold = -range % range;
        while (low < threshold) {
            product = (uint64_t)(uint32_t)xoshiro_next(gen) * range;
            low = (uint32_t)product;
        }
    }
    return product >> 32;
}


// ++++++++++++++++ 其他函數原型  ++++++++++++++++
// PRNG 種子函數
void xoshiro_seed(struct Xoshiro256StarStar* gen, uint64_t seed);
// 十六進制轉換
void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_str);
void bytes_to_hex_fast(const uint8_t* bytes, size_t len, char* hex_str); 
int hex_to_bytes(const char *hex_str, size_t hex_len, uint8_t *byte_array, size_t max_bytes);

// SHA256 填充
void sha256_pad_block(uint8_t block[64], const char* msg, size_t len);

#endif // UTILS_H
