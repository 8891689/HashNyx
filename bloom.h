/* bloom.h 
Author: 8891689
https://github.com/8891689
Assist in creation ：ChatGPT 
*/ 
#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/** BloomFilter 结构体 **/
typedef struct {
    uint64_t  bit_count;   
    uint64_t  byte_count;   
    uint64_t  hash_count;   
    uint8_t *filter;    
    bool      mmaped;       
    pthread_rwlock_t lock;  
} BloomFilter;

/** 初始化/销毁 **/
BloomFilter *bloom_init(uint64_t expected_entries,
                        double false_positive_rate);
void          bloom_free(BloomFilter *bf);

/** 核心操作 **/
void          bloom_add(BloomFilter *bf,
                        const void *data, size_t len);
                        
int           bloom_check_nolock(const BloomFilter *bf, const void *data, size_t len);
void          bloom_reset(BloomFilter *bf);

/** 文件持久化 **/
int           bloom_save(const BloomFilter *bf,
                         const char *filename);
BloomFilter  *bloom_load(const char *filename);

/** mmap 加载（只读） **/
BloomFilter  *bloom_mmap_load(const char *filename);
int           bloom_mmap_unload(BloomFilter *bf);

/** 十六进制字符串接口 **/
int           bloom_add_hex(BloomFilter *bf,
                            const char *hexstr);
int           bloom_check_hex(const BloomFilter *bf,
                              const char *hexstr);

/**
 * @brief 将十六进制字符串转换为字节数组。
 * @note  這個函數的實現預期由使用庫的應用程序提供。
 */
int hex_to_bytes(const char *hexstr, size_t hex_len, uint8_t *out_bytes, size_t out_size);
BloomFilter* bloom_init_optimal(uint64_t bit_count, int hash_count);
#ifdef __cplusplus
}
#endif

#endif /* BLOOM_H */

