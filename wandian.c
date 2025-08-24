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

#include "HashNyx_thread.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ==================== 向量 (Vector) 实现 ====================
void vector_init(VectorU128* vec) {
    vec->data = NULL;
    vec->size = 0;
    vec->capacity = 0;
}

void vector_push_back(VectorU128* vec, u128 value) {
    if (vec->size >= vec->capacity) {
        size_t new_capacity = (vec->capacity == 0) ? 8 : vec->capacity * 2;
        u128* new_data = (u128*)realloc(vec->data, new_capacity * sizeof(u128));
        if (!new_data) {
            perror("realloc failed in vector_push_back");
            exit(EXIT_FAILURE);
        }
        vec->data = new_data;
        vec->capacity = new_capacity;
    }
    vec->data[vec->size++] = value;
}

void vector_free(VectorU128* vec) {
    if (vec && vec->data) {
        free(vec->data);
        vec->data = NULL;
        vec->size = 0;
        vec->capacity = 0;
    }
}

// ==================== 字符集 (Charset) 定义 ====================
const Charset CHARSETS[] = {
    {"d", "0123456789"},
    {"u", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"l", "abcdefghijklmnopqrstuvwxyz"},    
    {"s", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
    {"k", "0123456789abcdef"},
    {"all", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/~"}
};
const int NUM_CHARSETS = sizeof(CHARSETS) / sizeof(CHARSETS[0]);

// ==================== 128位整数 (u128) 辅助函数 ====================

u128 int_pow128(int base, int exp) {
    u128 result = 1;
    for(int i = 0; i < exp; i++) {
        u128 temp_res;
        if (__builtin_mul_overflow(result, base, &temp_res)) return 0; // Overflow check
        result = temp_res;
    }
    return result;
}

void print_u128(u128 n) {
    if (n == 0) {
        printf("0");
        return;
    }
    char buf[40]; 
    int i = sizeof(buf) - 1;
    buf[i] = '\0';

    while (n > 0) {
        i--;
        buf[i] = (n % 10) + '0';
        n /= 10;
    }
    //printf("%s", &buf[i]);
}

// ==================== 命令行参数解析辅助函数 ====================

void parseLengthRange(char *range, int *minLength, int *maxLength) {
    char *dashPos = strchr(range, '-');
    if(dashPos) { 
        *dashPos = '\0'; 
        *minLength = atoi(range); 
        *maxLength = atoi(dashPos + 1); 
    } 
    else { 
        *minLength = *maxLength = atoi(range); 
    }
}

