/* Apache License, Version 2.0
   Copyright [2025] [8891689]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   Author: 8891689 (https://github.com/8891689)
*/
#ifndef SM3_AVX2_H
#define SM3_AVX2_H

#include <stdint.h>  
#include <stddef.h>  
#include <immintrin.h> 

// --- 单通道 SM3 上下文和函数 ---
// 定义 SM3 单通道的上下文结构体
typedef struct {
    uint32_t state[8]; 
} sm3_context;

// 单通道 SM3 函数声明
void sm3_starts(sm3_context *ctx);
void sm3_compress(uint32_t state[8], const unsigned char block[64]);
void sm3_single(const unsigned char *input, size_t ilen, unsigned char *output);


// --- 8 通道 AVX2 SM3 上下文和函数 ---
// 定义 SM3 8 通道 AVX2 的上下文结构体
typedef struct {
    __m256i state[8];  
    __m256i active_mask; 
} sm3_8x_context;

// 8 通道 SM3 函数声明 (公共接口)
void sm3_8x_starts(sm3_8x_context *ctx);
void sm3_8x_compress(sm3_8x_context *ctx, const unsigned char blocks[8][64]);
void sm3_8x_final(sm3_8x_context *ctx, unsigned char outputs[8][32]);
void sm3_8x(const unsigned char *inputs[8], size_t ilens[8], unsigned char outputs[8][32]);

#endif // SM3_AVX2_H
