// wandian.h 
#ifndef WANDIAN_H
#define WANDIAN_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h> 

#ifdef __cplusplus
extern "C" {
#endif

// ==================== 共享类型定义 ====================
#define MAX_PASSWORD_LENGTH 256
typedef unsigned __int128 u128;

typedef struct {
    u128* data;
    size_t size;
    size_t capacity;
} VectorU128;

typedef struct {
    const char *identifier;
    const char *characters;
} Charset;

// ==================== 全局变量声明 ====================
extern const Charset CHARSETS[];
extern const int NUM_CHARSETS;

// ==================== 库函数声明 ====================
// --- Vector 工具函数 ---
void vector_init(VectorU128* vec);
void vector_push_back(VectorU128* vec, u128 value);
void vector_free(VectorU128* vec);

// --- u128 工具函数 ---
u128 int_pow128(int base, int exp);
void print_u128(u128 n);

// --- 参数解析工具函数 ---
void parseLengthRange(char *range, int *minLength, int *maxLength);

#ifdef __cplusplus
}
#endif

#endif // WANDIAN_H
