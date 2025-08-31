// HashNyx_thread.h 

#ifndef HashNyx_thread_H
#define HashNyx_thread_H

#include "wandian.h"
#include "bloom.h"
#include "hash_set.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#define MAX_HASH_SIZE 64
#define QUEUE_CAPACITY 8192

// 验证任务
typedef struct {
    char password[MAX_PASSWORD_LENGTH + 1];
    uint8_t hash[MAX_HASH_SIZE]; 
    int hash_len;
} VerificationTask;

// 线程安全队列
typedef struct {
    VerificationTask *tasks;
    int head;
    int tail;
    int count;
    int capacity;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    atomic_bool shutdown;
} SharedQueue;
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// HashMode 和 GlobalState 的定义
typedef enum {
    MODE_MD5,
    MODE_SHA1,
    MODE_RIPEMD160,
    MODE_HASH160,
    // SHA-2 Family
    MODE_SHA224,
    MODE_SHA256,
    MODE_SHA384,
    MODE_SHA512,
    // SHA-3 Family
    MODE_SHA3_224,
    MODE_SHA3_256,
    MODE_SHA3_384,
    MODE_SHA3_512,
    // Keccak Family
    MODE_KECCAK224,
    MODE_KECCAK256,
    MODE_KECCAK384,
    MODE_KECCAK512,
    // SM3
    MODE_SM3
} HashMode;


typedef struct {
    atomic_ullong passwords_checked;
    atomic_bool running;
    pthread_mutex_t *mutex;
    int thread_count; 
} GlobalState;


// 扩展的线程数据结构
typedef struct {
    // --- 生产者和消费者共享的字段 ---
    FILE *output_file;
    pthread_mutex_t *mutex;
    HashSet *target_hashes;     
    SharedQueue *shared_queue;

    // --- 仅生产者使用的字段 ---
    u128 startIndex;
    u128 endIndex;
    int minLength;
    int maxLength;
    bool random;
    const char *charset;
    int charsetLength;
    bool infinite;
    const void* start_indices_per_length;
    HashMode hash_mode;
    BloomFilter *bloom_filter;
    bool debug_mode;
    int thread_id;
    GlobalState *state;
    const char* hash_filename; 
    
    bool pubkey_mode; 
    const uint8_t* single_target_bin; 
    int single_target_len;            
    uint64_t prng_seed[4];
    unsigned long long local_passwords_checked; 
     
} ThreadData;

// 线程工作函数
void* cracker_thread_worker(void* arg);
void* verification_thread_worker(void* arg);

// 队列函数原型
SharedQueue* queue_init(int capacity);
void queue_destroy(SharedQueue *q);
void queue_enqueue(SharedQueue *q, VerificationTask task);
VerificationTask queue_dequeue(SharedQueue *q);
void queue_shutdown(SharedQueue* q);

#endif // CRACKER_H
