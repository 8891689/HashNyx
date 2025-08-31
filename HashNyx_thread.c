// cracker_thread.c 
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
#include "utils.h"
#include "md5_avx2.h"
#include "sha1_avx2.h"
#include "ripemd160_avx2.h"
#include "keccak_avx2.h"
#include "sha2_avx2.h" 
#include "sha3_avx2.h"
#include "sm3_avx2.h"

#include "wandian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// ++++++++++++++++++++++++ 验证者线程 (消费者)  ++++++++++++++++++++++

void* verification_thread_worker(void* arg) {
    ThreadData *data = (ThreadData *)arg;
    SharedQueue* q = data->shared_queue;
    char hex_hash[MAX_HASH_SIZE * 2 + 1];

    while (1) {
        VerificationTask task = queue_dequeue(q);
        
        if (task.password[0] == '\0' && atomic_load(&q->shutdown)) {
            break;
        }

        bytes_to_hex_fast(task.hash, task.hash_len, hex_hash);
        
        if (hash_set_contains(data->target_hashes, hex_hash)) {
            pthread_mutex_lock(data->mutex);
            fprintf(stderr, "\r[!] Password: %s, Hash: %s\n", task.password, hex_hash);
            fprintf(data->output_file, "Password: %s, Hash: %s\n", task.password, hex_hash);
            fflush(data->output_file);
            pthread_mutex_unlock(data->mutex);
        }
    }
    return NULL;
}

static inline void sha512_pad_block(uint8_t padded_block[128], const char* input, size_t len) {
    memcpy(padded_block, input, len);
    padded_block[len] = 0x80;
    memset(padded_block + len + 1, 0, 128 - len - 1);
    // 將長度（以位元為單位）寫入區塊的最後 16 個位元組（大端序）
    uint64_t bit_len = len * 8;
    padded_block[127] = (uint8_t)(bit_len);
    padded_block[126] = (uint8_t)(bit_len >> 8);
    padded_block[125] = (uint8_t)(bit_len >> 16);
    padded_block[124] = (uint8_t)(bit_len >> 24);
    padded_block[123] = (uint8_t)(bit_len >> 32);
    padded_block[122] = (uint8_t)(bit_len >> 40);
    padded_block[121] = (uint8_t)(bit_len >> 48);
    padded_block[120] = (uint8_t)(bit_len >> 56);
}

// ++++++++++++++++++++++++ 全新高性能宏，模式的输出逻辑 ++++++++++++++++++++++++

#define CHECK_AND_OUTPUT(hash_array, hash_len_val, password_source, count) \
do { \
    /* 模式零：Debug 模式 (-bug)，拥有最高优先级 */ \
    if (data->debug_mode) { \
        char hex_hash_debug[MAX_HASH_SIZE * 2 + 1]; \
        for (int i = 0; i < count; ++i) { \
            bytes_to_hex_fast(hash_array[i], hash_len_val, hex_hash_debug); \
            pthread_mutex_lock(data->mutex); \
            fprintf(stderr, "%s:%s\n", password_source[i], hex_hash_debug); \
            pthread_mutex_unlock(data->mutex); \
        } \
        break; /* Debug 模式执行后，直接跳出宏 */ \
    } \
    \
    /* 模式一：单目标模式 (-a) */ \
    if (data->single_target_bin) { \
        if (hash_len_val != data->single_target_len) break; \
        for (int i = 0; i < count; ++i) { \
            if (memcmp(hash_array[i], data->single_target_bin, hash_len_val) == 0) { \
                pthread_mutex_lock(data->mutex); \
                char hex_hash_found[MAX_HASH_SIZE * 2 + 1]; \
                bytes_to_hex_fast(hash_array[i], hash_len_val, hex_hash_found); \
                fprintf(stderr, "\r[!] Password: %s, Hash: %s\n", password_source[i], hex_hash_found); \
                fprintf(data->output_file, "Password: %s, Hash: %s\n", password_source[i], hex_hash_found); \
                fflush(data->output_file); \
                pthread_mutex_unlock(data->mutex); \
            } \
        } \
    } \
    /* 模式二：多目标模式 (-b 和/或 -f) */ \
    else if (data->target_hashes) { /* 关键修正：只有在需要最终验证时才进入此逻辑 */ \
        for (int i = 0; i < count; ++i) { \
            /* 步骤 1: 初筛。如果无布隆，则所有哈希都视为通过初筛 */ \
            if (data->bloom_filter && !bloom_check_nolock(data->bloom_filter, hash_array[i], hash_len_val)) { \
                continue; \
            } \
            \
            /* 步骤 2: 将通过初筛的哈希交由消费者线程进行精确验证 */ \
            /* 此时 data->shared_queue 必然存在，因为 data->target_hashes 存在 */ \
            VerificationTask task; \
            strncpy(task.password, password_source[i], MAX_PASSWORD_LENGTH); \
            task.password[MAX_PASSWORD_LENGTH] = '\0'; \
            memcpy(task.hash, hash_array[i], hash_len_val); \
            task.hash_len = hash_len_val; \
            queue_enqueue(data->shared_queue, task); \
        } \
    } \
    /* 模式三：只有布隆过滤器 (-b) 但没有精确哈希文件 (-f) 的情况 */ \
    /* 在这种情况下，我们什么都不做，因为我们无法确认命中，打印会产生误报 */ \
    /* 模式四：无目标模式，也什么都不做 */ \
    \
} while (0)


void* cracker_thread_worker(void* arg) {
    ThreadData *data = (ThreadData *)arg;

    // --- 初始化哈希上下文 ---
    #define BATCH_SIZE 8
    int total_threads = data->state->thread_count;

    SHA2_x8_CTX* sha224_handle = (data->hash_mode == MODE_SHA224) ? sha224_x8_create() : NULL;
    SHA2_x8_CTX* sha256_handle = (data->hash_mode == MODE_SHA256 || data->hash_mode == MODE_HASH160) ? sha256_x8_create() : NULL;
    SHA2_x8_CTX* sha384_handle = (data->hash_mode == MODE_SHA384) ? sha384_x8_create() : NULL;
    SHA2_x8_CTX* sha512_handle = (data->hash_mode == MODE_SHA512) ? sha512_x8_create() : NULL;

    // ========================================================================
    // ============================ 公鑰模式 (Public Key Mode) =================
    // ========================================================================
    if (data->pubkey_mode) {
        char hex_passwords[BATCH_SIZE][MAX_PASSWORD_LENGTH + 1];
        const uint8_t* password_ptrs[BATCH_SIZE];
        uint8_t binary_pubkeys[BATCH_SIZE][33];

        for (int i = 0; i < BATCH_SIZE; ++i) {
            password_ptrs[i] = binary_pubkeys[i];
        }

        if (data->random) {
            // --- 隨機公鑰模式 ---
            struct Xoshiro256StarStar gen;
            pthread_mutex_lock(data->state->mutex);
            static struct Xoshiro256StarStar master_gen;
            static bool master_gen_initialized = false;
            if (!master_gen_initialized) {
                struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t initial_seed = (uint64_t)ts.tv_sec * 1000000007ULL + (uint64_t)ts.tv_nsec;
                xoshiro_seed(&master_gen, initial_seed); master_gen_initialized = true;
            }
            gen.s[0] = xoshiro_next(&master_gen); gen.s[1] = xoshiro_next(&master_gen);
            gen.s[2] = xoshiro_next(&master_gen); gen.s[3] = xoshiro_next(&master_gen);
            pthread_mutex_unlock(data->state->mutex);

            long long total_count_ll = data->infinite ? -1 : (long long)(data->endIndex - data->startIndex);
            for (long long current_proc = 0; total_count_ll == -1 || current_proc < total_count_ll; current_proc += BATCH_SIZE) {
                for (int i = 0; i < BATCH_SIZE; ++i) {
                    binary_pubkeys[i][0] = (xoshiro_next(&gen) & 1) ? 0x03 : 0x02;
                    for (int j = 1; j < 33; ++j) { binary_pubkeys[i][j] = (uint8_t)xoshiro_next(&gen); }
                    bytes_to_hex_fast(binary_pubkeys[i], 33, hex_passwords[i]);
                }
                
                switch (data->hash_mode) {
                    case MODE_HASH160: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32)));
                        uint8_t sha256_results[BATCH_SIZE][32] __attribute__((aligned(32)));
                        uint8_t h160_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        const uint8_t* sha256_ptrs[BATCH_SIZE];
                        size_t sha256_lens_static[BATCH_SIZE];
                        for(int i = 0; i < BATCH_SIZE; ++i) {
                            sha256_pad_block(padded_blocks[i], (const char*)password_ptrs[i], 33);
                            sha256_ptrs[i] = sha256_results[i];
                            sha256_lens_static[i] = 32;
                        }
                        sha256_x8_init(sha256_handle);
                        sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                        sha256_x8_final(sha256_handle, sha256_results);
                        ripemd160_multi_oneshot(sha256_ptrs, sha256_lens_static, h160_hashes);
                        CHECK_AND_OUTPUT(h160_hashes, 20, hex_passwords, BATCH_SIZE);
                        break;
                    }
                    default: break;
                }
                data->local_passwords_checked += BATCH_SIZE;
            }
        } else {
            // --- 循序公鑰模式 (無限遞增) ---
            u256 current_key = { {1, 0, 0, 0} }; 
            
            u128 offset = data->thread_id;
            u256_add_u128(&current_key, offset);

            while(true) {
                int batch_count = 0;
                for (int j = 0; j < BATCH_SIZE; ++j) {
                    binary_pubkeys[j][0] = 0x02;
                    u256_to_bytes_big_endian(&current_key, &binary_pubkeys[j][1]);
                    bytes_to_hex_fast(binary_pubkeys[j], 33, hex_passwords[j]);

                    for(int t = 0; t < total_threads; ++t) {
                        u256_increment(&current_key);
                    }
                    batch_count++;
                }
                
                if (batch_count > 0) {
                     switch (data->hash_mode) {
                        case MODE_HASH160: {
                            uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32)));
                            uint8_t sha256_results[BATCH_SIZE][32] __attribute__((aligned(32)));
                            uint8_t h160_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                            const uint8_t* sha256_ptrs[BATCH_SIZE];
                            size_t sha256_lens_static[BATCH_SIZE];
                            for(int i = 0; i < BATCH_SIZE; ++i) {
                                sha256_pad_block(padded_blocks[i], (const char*)password_ptrs[i], 33);
                                sha256_ptrs[i] = sha256_results[i];
                                sha256_lens_static[i] = 32;
                            }
                            sha256_x8_init(sha256_handle);
                            sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                            sha256_x8_final(sha256_handle, sha256_results);
                            ripemd160_multi_oneshot(sha256_ptrs, sha256_lens_static, h160_hashes);
                            CHECK_AND_OUTPUT(h160_hashes, 20, hex_passwords, batch_count);
                            break;
                        }
                        default: break;
                    }
                    data->local_passwords_checked += batch_count;
                }
            }
        }
    } else {
        // ========================================================================
        // ============================ 普通密碼模式 ============================
        // ========================================================================
        if (data->random) {
            char passwords[BATCH_SIZE][MAX_PASSWORD_LENGTH + 1];
            const uint8_t* password_ptrs[BATCH_SIZE];
            size_t password_lens[BATCH_SIZE];
            for (int i = 0; i < BATCH_SIZE; ++i) {
                password_ptrs[i] = (const uint8_t*)passwords[i];
            }

            struct Xoshiro256StarStar gen;
            pthread_mutex_lock(data->state->mutex);
            static struct Xoshiro256StarStar master_gen;
            static bool master_gen_initialized = false;
            if (!master_gen_initialized) {
                struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t initial_seed = (uint64_t)ts.tv_sec * 1000000007ULL + (uint64_t)ts.tv_nsec;
                xoshiro_seed(&master_gen, initial_seed); master_gen_initialized = true;
            }
            gen.s[0] = xoshiro_next(&master_gen); gen.s[1] = xoshiro_next(&master_gen);
            gen.s[2] = xoshiro_next(&master_gen); gen.s[3] = xoshiro_next(&master_gen);
            pthread_mutex_unlock(data->state->mutex);

            unsigned char* hashes_out_ptrs[BATCH_SIZE];
            
            long long total_count_ll = data->infinite ? -1 : (long long)(data->endIndex - data->startIndex);

            for (long long current_proc = 0; total_count_ll == -1 || current_proc < total_count_ll; current_proc += BATCH_SIZE) {
                // --- 普通隨機密碼邏輯 ---
                bool is_power_of_two = (data->charsetLength > 0) && ((data->charsetLength & (data->charsetLength - 1)) == 0);
                if (is_power_of_two) {
                    const uint32_t mask = data->charsetLength - 1;
                    for (int i = 0; i < BATCH_SIZE; ++i) {
                        int password_len = data->minLength;
                        if (data->maxLength > data->minLength) { password_len += map_to_range_unbiased(&gen, data->maxLength - data->minLength + 1); }
                        password_lens[i] = password_len;
                        for (int j = 0; j < password_len; j += 2) {
                            uint64_t r = xoshiro_next(&gen);
                            passwords[i][j] = data->charset[(uint32_t)r & mask];
                            if (j + 1 < password_len) { passwords[i][j + 1] = data->charset[(uint32_t)(r >> 32) & mask]; }
                        }
                        passwords[i][password_len] = '\0';
                    }
                } else {
                    for (int i = 0; i < BATCH_SIZE; ++i) {
                        int password_len = data->minLength;
                        if (data->maxLength > data->minLength) { password_len += map_to_range_unbiased(&gen, data->maxLength - data->minLength + 1); }
                        password_lens[i] = password_len;
                        for (int j = 0; j < password_len; ++j) { passwords[i][j] = data->charset[map_to_range_unbiased(&gen, data->charsetLength)]; }
                        passwords[i][password_len] = '\0';
                    }
                }
                
                // --- 哈希計算 (隨機模式) ---
                switch (data->hash_mode) {
                    case MODE_MD5: {
                        uint8_t md5_hashes[BATCH_SIZE][16] __attribute__((aligned(32)));
                        MD5BatchOneShot(password_ptrs, password_lens, md5_hashes);
                        CHECK_AND_OUTPUT(md5_hashes, 16, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA1: {
                        uint8_t sha1_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        SHA1BatchOneShot(password_ptrs, password_lens, sha1_hashes);
                        CHECK_AND_OUTPUT(sha1_hashes, 20, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_RIPEMD160: {
                        uint8_t r_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        ripemd160_multi_oneshot((const uint8_t **)password_ptrs, password_lens, r_hashes);
                        CHECK_AND_OUTPUT(r_hashes, 20, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA224: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32)));
                        uint8_t sha224_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for(int i = 0; i < BATCH_SIZE; ++i) { sha256_pad_block(padded_blocks[i], (const char*)password_ptrs[i], password_lens[i]); }
                        sha224_x8_init(sha224_handle);
                        sha224_x8_update(sha224_handle, (const uint8_t(*)[64])padded_blocks);
                        sha224_x8_final(sha224_handle, sha224_hashes);
                        CHECK_AND_OUTPUT(sha224_hashes, 28, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA256: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32)));
                        uint8_t sha256_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for(int i = 0; i < BATCH_SIZE; ++i) { sha256_pad_block(padded_blocks[i], (const char*)password_ptrs[i], password_lens[i]); }
                        sha256_x8_init(sha256_handle);
                        sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                        sha256_x8_final(sha256_handle, sha256_hashes);
                        CHECK_AND_OUTPUT(sha256_hashes, 32, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA384: {
                        uint8_t padded_blocks[BATCH_SIZE][128] __attribute__((aligned(32)));
                        uint8_t sha384_hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for(int i = 0; i < BATCH_SIZE; ++i) { sha512_pad_block(padded_blocks[i], (const char*)password_ptrs[i], password_lens[i]); }
                        sha384_x8_init(sha384_handle);
                        sha384_x8_update(sha384_handle, (const uint8_t(*)[128])padded_blocks);
                        sha384_x8_final(sha384_handle, sha384_hashes);
                        CHECK_AND_OUTPUT(sha384_hashes, 48, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA512: {
                        uint8_t padded_blocks[BATCH_SIZE][128] __attribute__((aligned(32)));
                        uint8_t sha512_hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for(int i = 0; i < BATCH_SIZE; ++i) { sha512_pad_block(padded_blocks[i], (const char*)password_ptrs[i], password_lens[i]); }
                        sha512_x8_init(sha512_handle);
                        sha512_x8_update(sha512_handle, (const uint8_t(*)[128])padded_blocks);
                        sha512_x8_final(sha512_handle, sha512_hashes);
                        CHECK_AND_OUTPUT(sha512_hashes, 64, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SM3: {
                        uint8_t sm3_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        sm3_8x((const unsigned char**)password_ptrs, password_lens, sm3_hashes);
                        CHECK_AND_OUTPUT(sm3_hashes, 32, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA3_224: {
                        uint8_t hashes[BATCH_SIZE][28] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_224((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 28, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA3_256: {
                        uint8_t hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_256((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 32, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA3_384: {
                        uint8_t hashes[BATCH_SIZE][48] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_384((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 48, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_SHA3_512: {
                        uint8_t hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_512((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 64, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_KECCAK224: {
                        uint8_t hashes[BATCH_SIZE][28] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_224((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 28, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_KECCAK256: {
                        uint8_t hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_256((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 32, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_KECCAK384: {
                        uint8_t hashes[BATCH_SIZE][48] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_384((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 48, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_KECCAK512: {
                        uint8_t hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_512((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 64, passwords, BATCH_SIZE);
                        break;
                    }
                    case MODE_HASH160: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32)));
                        uint8_t sha256_results[BATCH_SIZE][32] __attribute__((aligned(32)));
                        uint8_t h160_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        const uint8_t* sha256_ptrs[BATCH_SIZE];
                        size_t sha256_lens[BATCH_SIZE];

                        for(int i = 0; i < BATCH_SIZE; ++i) { 
                            sha256_pad_block(padded_blocks[i], (const char*)password_ptrs[i], password_lens[i]);
                            sha256_ptrs[i] = sha256_results[i];
                            sha256_lens[i] = 32;
                        }
                        sha256_x8_init(sha256_handle);
                        sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                        sha256_x8_final(sha256_handle, sha256_results);
                        
                        ripemd160_multi_oneshot(sha256_ptrs, sha256_lens, h160_hashes);
                        CHECK_AND_OUTPUT(h160_hashes, 20, passwords, BATCH_SIZE);
                        break;
                    }
                }
                data->local_passwords_checked += BATCH_SIZE;
            }
        } else {
            // --- 循序字元集模式 ---
            const VectorU128* start_indices = (const VectorU128*)data->start_indices_per_length;
            const char* charset = data->charset;
            const int charsetLength = data->charsetLength;
            size_t low = 0, high = start_indices->size, mid;
            while(low < high) { mid = low + (high - low) / 2; if (data->startIndex >= start_indices->data[mid]) low = mid + 1; else high = mid; }
            int current_len_offset = low > 0 ? low - 1 : 0;
            int current_len = data->minLength + current_len_offset;
            u128 local_idx = data->startIndex - start_indices->data[current_len_offset];
            int indices[MAX_PASSWORD_LENGTH] = {0}; 
            u128 temp_idx = local_idx;
            for (int pos = current_len - 1; pos >= 0; --pos) { indices[pos] = (int)(temp_idx % charsetLength); temp_idx /= charsetLength; }
            
            u128 passwords_to_generate = data->endIndex - data->startIndex;
            
            char password_batch[BATCH_SIZE][MAX_PASSWORD_LENGTH + 1];
            const uint8_t* password_ptrs[BATCH_SIZE];
            size_t password_lens[BATCH_SIZE];
            for(int k=0; k < BATCH_SIZE; ++k) {
                password_ptrs[k] = (const uint8_t*)password_batch[k];
            }

            unsigned char* hashes_out_ptrs[BATCH_SIZE];
            static const char* empty_string = "";

            for (u128 i = 0; i < passwords_to_generate; ) {
                int batch_count = 0;
                for (int j = 0; j < BATCH_SIZE && i < passwords_to_generate; ++j, ++i) {
                    for (int k = 0; k < current_len; ++k) { password_batch[j][k] = charset[indices[k]]; }
                    password_batch[j][current_len] = '\0';
                    password_lens[j] = current_len;

                    for (int pos = current_len - 1; pos >= 0; --pos) {
                        indices[pos]++;
                        if (indices[pos] < charsetLength) break;
                        indices[pos] = 0;
                        if (pos == 0) { current_len++; }
                    }
                    batch_count++;
                }

                if (batch_count == 0) break;
                
                if (batch_count < BATCH_SIZE) {
                    for (int k = batch_count; k < BATCH_SIZE; ++k) {
                        password_ptrs[k] = (const uint8_t*)empty_string;
                        password_lens[k] = 0;
                    }
                }

                // --- 哈希計算 (順序模式) ---
                switch (data->hash_mode) {
                    case MODE_MD5: {
                        uint8_t md5_hashes[BATCH_SIZE][16] __attribute__((aligned(32)));
                        MD5BatchOneShot(password_ptrs, password_lens, md5_hashes);
                        CHECK_AND_OUTPUT(md5_hashes, 16, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA1: {
                        uint8_t sha1_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        SHA1BatchOneShot(password_ptrs, password_lens, sha1_hashes);
                        CHECK_AND_OUTPUT(sha1_hashes, 20, password_batch, batch_count);
                        break;
                    }
                    case MODE_RIPEMD160: {
                        uint8_t r_hashes[BATCH_SIZE][20] __attribute__((aligned(32)));
                        ripemd160_multi_oneshot((const uint8_t **)password_ptrs, password_lens, r_hashes);
                        CHECK_AND_OUTPUT(r_hashes, 20, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA224: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32))) = {0};
                        uint8_t sha224_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for(int k = 0; k < batch_count; ++k) { sha256_pad_block(padded_blocks[k], (const char*)password_ptrs[k], password_lens[k]); }
                        sha224_x8_init(sha224_handle);
                        sha224_x8_update(sha224_handle, (const uint8_t(*)[64])padded_blocks);
                        sha224_x8_final(sha224_handle, sha224_hashes);
                        CHECK_AND_OUTPUT(sha224_hashes, 28, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA256: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32))) = {0};
                        uint8_t sha256_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for(int k = 0; k < batch_count; ++k) { sha256_pad_block(padded_blocks[k], (const char*)password_ptrs[k], password_lens[k]); }
                        sha256_x8_init(sha256_handle);
                        sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                        sha256_x8_final(sha256_handle, sha256_hashes);
                        CHECK_AND_OUTPUT(sha256_hashes, 32, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA384: {
                        uint8_t padded_blocks[BATCH_SIZE][128] __attribute__((aligned(32))) = {0};
                        uint8_t sha384_hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for(int k = 0; k < batch_count; ++k) { sha512_pad_block(padded_blocks[k], (const char*)password_ptrs[k], password_lens[k]); }
                        sha384_x8_init(sha384_handle);
                        sha384_x8_update(sha384_handle, (const uint8_t(*)[128])padded_blocks);
                        sha384_x8_final(sha384_handle, sha384_hashes);
                        CHECK_AND_OUTPUT(sha384_hashes, 48, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA512: {
                        uint8_t padded_blocks[BATCH_SIZE][128] __attribute__((aligned(32))) = {0};
                        uint8_t sha512_hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for(int k = 0; k < batch_count; ++k) { sha512_pad_block(padded_blocks[k], (const char*)password_ptrs[k], password_lens[k]); }
                        sha512_x8_init(sha512_handle);
                        sha512_x8_update(sha512_handle, (const uint8_t(*)[128])padded_blocks);
                        sha512_x8_final(sha512_handle, sha512_hashes);
                        CHECK_AND_OUTPUT(sha512_hashes, 64, password_batch, batch_count);
                        break;
                    }
                    case MODE_SM3: {
                        uint8_t sm3_hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        sm3_8x((const unsigned char**)password_ptrs, password_lens, sm3_hashes);
                        CHECK_AND_OUTPUT(sm3_hashes, 32, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA3_224: {
                        uint8_t hashes[BATCH_SIZE][28] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_224((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 28, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA3_256: {
                        uint8_t hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_256((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 32, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA3_384: {
                        uint8_t hashes[BATCH_SIZE][48] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_384((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 48, password_batch, batch_count);
                        break;
                    }
                    case MODE_SHA3_512: {
                        uint8_t hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        sha3_8x_512((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 64, password_batch, batch_count);
                        break;
                    }
                    case MODE_KECCAK224: {
                        uint8_t hashes[BATCH_SIZE][28] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_224((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 28, password_batch, batch_count);
                        break;
                    }
                    case MODE_KECCAK256: {
                        uint8_t hashes[BATCH_SIZE][32] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_256((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 32, password_batch, batch_count);
                        break;
                    }
                    case MODE_KECCAK384: {
                        uint8_t hashes[BATCH_SIZE][48] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_384((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 48, password_batch, batch_count);
                        break;
                    }
                    case MODE_KECCAK512: {
                        uint8_t hashes[BATCH_SIZE][64] __attribute__((aligned(32)));
                        for (int i = 0; i < BATCH_SIZE; ++i) hashes_out_ptrs[i] = hashes[i];
                        keccak_8x_512((const unsigned char**)password_ptrs, password_lens, hashes_out_ptrs);
                        CHECK_AND_OUTPUT(hashes, 64, password_batch, batch_count);
                        break;
                    }
                    case MODE_HASH160: {
                        uint8_t padded_blocks[BATCH_SIZE][64] __attribute__((aligned(32))) = {0};
                        uint8_t sha256_results[BATCH_SIZE][32] __attribute__((aligned(32)));
                        uint8_t h160_hash[BATCH_SIZE][20] __attribute__((aligned(32)));
                        const uint8_t* sha256_ptrs[BATCH_SIZE];
                        size_t sha256_lens[BATCH_SIZE];

                        for(int k = 0; k < batch_count; ++k) { 
                            sha256_pad_block(padded_blocks[k], (const char*)password_ptrs[k], password_lens[k]); 
                            sha256_ptrs[k] = sha256_results[k];
                            sha256_lens[k] = 32;
                        }
                        for (int k = batch_count; k < BATCH_SIZE; ++k) {
                            sha256_ptrs[k] = (const uint8_t*)""; // Empty string for padding
                            sha256_lens[k] = 0;
                        }

                        sha256_x8_init(sha256_handle);
                        sha256_x8_update(sha256_handle, (const uint8_t(*)[64])padded_blocks);
                        sha256_x8_final(sha256_handle, sha256_results);
                        
                        ripemd160_multi_oneshot(sha256_ptrs, sha256_lens, h160_hash);
                        CHECK_AND_OUTPUT(h160_hash, 20, password_batch, batch_count);
                        break;
                    }
                }
                data->local_passwords_checked += batch_count;
            }
        }
    }


    // --- 清理 ---
    if (sha224_handle) sha224_x8_destroy(sha224_handle);
    if (sha256_handle) sha256_x8_destroy(sha256_handle);
    if (sha384_handle) sha384_x8_destroy(sha384_handle);
    if (sha512_handle) sha512_x8_destroy(sha512_handle);

    return NULL;
}
