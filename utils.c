// utils.c
/*
 * Copyright [2024] [8891689]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * https://github.com/8891689
 */
#include <string.h>
#include <stdio.h>
#include "utils.h"

void xoshiro_seed(struct Xoshiro256StarStar* gen, uint64_t seed) {
    for (int i = 0; i < 4; ++i) {
        uint64_t x = seed += 0x9e3779b97f4a7c15;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        gen->s[i] = x ^ (x >> 31);
    }
}

void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

void bytes_to_hex_fast(const uint8_t* bytes, size_t len, char* hex_str) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        uint8_t b = bytes[i];
        *hex_str++ = hex_chars[b >> 4];  // 高 4 位
        *hex_str++ = hex_chars[b & 0x0F]; // 低 4 位
    }
    *hex_str = '\0';
}


void sha256_pad_block(uint8_t block[64], const char* msg, size_t len) {
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bit_len = __builtin_bswap64(len * 8);
    memcpy(block + 56, &bit_len, sizeof(bit_len));
}

// --- 高性能 hex_to_bytes 实现 ---
int hex_to_bytes(const char *hex_str, size_t hex_len, uint8_t *byte_array, size_t max_bytes) {
    static const signed char hex_map[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1, // '0'..'9'
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 'A'..'F'
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 'a'..'f'
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    size_t byte_len = hex_len / 2;
    if (hex_len % 2 != 0 || byte_len > max_bytes) {
        return -1;
    }

    for (size_t i = 0; i < byte_len; ++i) {
        unsigned char c1 = hex_str[i*2];
        unsigned char c2 = hex_str[i*2 + 1];

        signed char v1 = hex_map[c1];
        signed char v2 = hex_map[c2];

        if (v1 == -1 || v2 == -1) {
            return -1; // 无效的十六进制字符
        }
        byte_array[i] = (uint8_t)((v1 << 4) | v2);
    }
    return (int)byte_len;
}
