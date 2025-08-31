// HashNyx.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include "HashNyx_thread.h"
#include "wandian.h"
#include "utils.h"
#include "hash_set.h"

typedef struct {
    GlobalState* state;
    ThreadData* thread_data_array;
    int thread_count;
} StatusThreadArgs;

// ++++++++++++++++++++++++ 队列实现 ++++++++++++++++++++++++
SharedQueue* queue_init(int capacity) {
    SharedQueue *q = (SharedQueue*)malloc(sizeof(SharedQueue));
    if (!q) return NULL;
    q->tasks = (VerificationTask*)malloc(sizeof(VerificationTask) * capacity);
    if (!q->tasks) { free(q); return NULL; }

    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->capacity = capacity;
    atomic_init(&q->shutdown, false);
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    return q;
}

void queue_destroy(SharedQueue *q) {
    if (!q) return;
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    free(q->tasks);
    free(q);
}

void queue_enqueue(SharedQueue *q, VerificationTask task) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == q->capacity && !atomic_load(&q->shutdown)) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }
    if (atomic_load(&q->shutdown)) {
        pthread_mutex_unlock(&q->mutex);
        return;
    }
    q->tasks[q->tail] = task;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

VerificationTask queue_dequeue(SharedQueue *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !atomic_load(&q->shutdown)) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    if (q->count == 0 && atomic_load(&q->shutdown)) {
        pthread_mutex_unlock(&q->mutex);
        VerificationTask empty_task = {{0}, {0}, 0};
        return empty_task;
    }
    VerificationTask task = q->tasks[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return task;
}

void queue_shutdown(SharedQueue* q) {
    pthread_mutex_lock(&q->mutex);
    atomic_store(&q->shutdown, true);
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
}

void* status_thread_worker(void* arg) {
    StatusThreadArgs* args = (StatusThreadArgs*)arg;
    unsigned long long last_checked = 0;
    struct timespec start_time, current_time;
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    while (atomic_load(&args->state->running)) {

        sleep(1);

        clock_gettime(CLOCK_MONOTONIC, &current_time);
        
        unsigned long long current_checked = 0;
        for (int i = 0; i < args->thread_count; ++i) {
            current_checked += args->thread_data_array[i].local_passwords_checked;
        }

        double elapsed_since_start = (current_time.tv_sec - start_time.tv_sec) + 
                                     (current_time.tv_nsec - start_time.tv_nsec) / 1e9;

        double speed_m_per_s = (elapsed_since_start > 0) ? ((double)(current_checked - last_checked) / 1000000.0) : 0.0;
        last_checked = current_checked;
        
        fprintf(stderr, "\r[+] [%.1fs] Checked: %-12llu | Speed: %-7.2f M/s",
                elapsed_since_start, current_checked, speed_m_per_s);
    }
    //fprintf(stderr, "\n");
    return NULL;
}

// 打印帮助信息
void printHelp() {
    printf("Usage: HashNyx [options]\n\n");
    printf("Author: 8891689 (https://github.com/8891689)\n\n");
    printf("Password Generation Options:\n");
    printf("  -l <range>      Password length range (e.g., 8-10 or 8).\n");
    printf("  -c <sets>       Charset, comma-separated (d,u,l,s,k,all,pkc).\n");
    printf("                  d:digits, u:upper, l:lower, s:special, k:hex, all:all\n");
    printf("                  pkc: public key mode (delegates to generator)\n");
    printf("  -R              Enable random generation mode (default: sequential).\n");
    printf("  -n <number>     Total number of passwords to generate in random mode (-R).\n");
    printf("  -pub            Shortcut for public key generation mode.\n\n");
    printf("Matching Options:\n");
    printf("  -m <type>       Hash algorithm. Supports:\n");
    printf("                  md5, sha1, ripemd160, hash160, sm3\n");
    printf("                  sha224, sha256, sha384, sha512\n");
    printf("                  sha3-224, sha3-256, sha3-384, sha3-512\n");
    printf("                  keccak224, keccak256, keccak384, keccak512\n");
    printf("                  (default: sha256)\n");
    printf("  -a              Load a single hash value into the core for high-speed pre-screening.\n");
    printf("  -b <file>       Load Bloom filter file for high-speed pre-screening.\n");
    printf("  -f <file>       Load hash file for final (exact) check.\n\n");
    printf("Output & Performance:\n");
    printf("  -o <file>       Output found matches to a file (default: stdout).\n");
    printf("  -t <num>        Number of cracker threads (producers) to use (default: 1).\n");
    printf("  -bug            Debug mode, prints every generated hash.\n\n");
    printf("Help:\n");
    printf("  -h, --help      Show this help message.\n");
}

int main(int argc, char *argv[]) {
    int minLength = 8, maxLength = 8;
    int threads = 1;
    bool random = false, n_specified = false;
    char *outputFile = NULL;
    const char* defaultOutputFile = "found.txt";
    char selectedCharsets[1024] = {0};
    bool pubkey_mode = false;
    bool debug_mode = false;
    char* bloomFile = NULL;
    char* hashFile = NULL;
    HashMode hash_mode = MODE_SHA256;
    BloomFilter* bf = NULL;
    HashSet* target_hashes = NULL;
    long long numPasswords_ll_for_n = -1;

    char* single_target_hex = NULL;
    uint8_t single_target_bin[MAX_HASH_SIZE];
    int single_target_len = 0;

    pthread_t *threadIds = NULL, *verifier_threads = NULL, status_thread;
    ThreadData *threadData = NULL, *verifier_data = NULL;
    SharedQueue* verification_queue = NULL;
    
    GlobalState state;
    state.thread_count = threads; 

    if (argc == 1) {
        printHelp();
        return 0;
    }

    // --- 參數解析 ---
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-R") == 0) random = true;
        else if(strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
            state.thread_count = threads; 
        }
        else if(strcmp(argv[i], "-n") == 0 && i + 1 < argc) { numPasswords_ll_for_n = atoll(argv[++i]); n_specified = true; }
        else if(strcmp(argv[i], "-o") == 0 && i + 1 < argc) outputFile = argv[++i];
        else if(strcmp(argv[i], "-l") == 0 && i + 1 < argc) parseLengthRange(argv[++i], &minLength, &maxLength);
        else if(strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
             strncpy(selectedCharsets, argv[++i], sizeof(selectedCharsets) - 1);
             if (strstr(selectedCharsets, "pkc") != NULL) { pubkey_mode = true; }
        }
        else if(strcmp(argv[i], "-pub") == 0) pubkey_mode = true;
        else if(strcmp(argv[i], "-bug") == 0) debug_mode = true;
        else if(strcmp(argv[i], "-b") == 0 && i + 1 < argc) bloomFile = argv[++i];
        else if(strcmp(argv[i], "-f") == 0 && i + 1 < argc) hashFile = argv[++i];
        else if(strcmp(argv[i], "-a") == 0 && i + 1 < argc) single_target_hex = argv[++i];
        else if(strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            char* mode_str = argv[++i];
            if (strcmp(mode_str, "md5") == 0) hash_mode = MODE_MD5;
            else if (strcmp(mode_str, "sha1") == 0) hash_mode = MODE_SHA1;
            else if (strcmp(mode_str, "ripemd160") == 0) hash_mode = MODE_RIPEMD160;
            else if (strcmp(mode_str, "hash160") == 0) hash_mode = MODE_HASH160;
            else if (strcmp(mode_str, "sm3") == 0) hash_mode = MODE_SM3;
            else if (strcmp(mode_str, "sha224") == 0) hash_mode = MODE_SHA224;
            else if (strcmp(mode_str, "sha256") == 0) hash_mode = MODE_SHA256;
            else if (strcmp(mode_str, "sha384") == 0) hash_mode = MODE_SHA384;
            else if (strcmp(mode_str, "sha512") == 0) hash_mode = MODE_SHA512;
            else if (strcmp(mode_str, "sha3-224") == 0) hash_mode = MODE_SHA3_224;
            else if (strcmp(mode_str, "sha3-256") == 0) hash_mode = MODE_SHA3_256;
            else if (strcmp(mode_str, "sha3-384") == 0) hash_mode = MODE_SHA3_384;
            else if (strcmp(mode_str, "sha3-512") == 0) hash_mode = MODE_SHA3_512;
            else if (strcmp(mode_str, "keccak224") == 0) hash_mode = MODE_KECCAK224;
            else if (strcmp(mode_str, "keccak256") == 0) hash_mode = MODE_KECCAK256;
            else if (strcmp(mode_str, "keccak384") == 0) hash_mode = MODE_KECCAK384;
            else if (strcmp(mode_str, "keccak512") == 0) hash_mode = MODE_KECCAK512;
            else { fprintf(stderr, "[-] Error: Unknown hash mode '%s'\n", mode_str); return 1; }
        }
        else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { printHelp(); return 0; }
        else { fprintf(stderr, "[-] Error: Unknown or missing argument for '%s'\n", argv[i]); printHelp(); return 1; }
    }

    // --- 文件和逻辑准备 ---
    FILE *output_handle = NULL;
    if (outputFile) {
        output_handle = fopen(outputFile, "w");
        if (!output_handle) {
            perror("[-] Error opening specified output file");
            return 1;
        }
        fprintf(stderr, "[+] Found matches will be written to: %s\n", outputFile);
    } else {
        output_handle = fopen(defaultOutputFile, "a");
        if (!output_handle) {
            perror("[-] Error opening default output file (found.txt)");
            return 1;
        }
        fprintf(stderr, "[+] Found matches will be written to default file: %s\n", defaultOutputFile);
    }

    if (single_target_hex) {
        if (bloomFile || hashFile) {
            fprintf(stderr, "[!] Warning: Single target hash (-a) is specified, ignoring Bloom filter (-b) and hash file (-f) options.\n");
        }
        size_t hex_len = strlen(single_target_hex);
        single_target_len = hex_to_bytes(single_target_hex, hex_len, single_target_bin, MAX_HASH_SIZE);
        if (single_target_len <= 0) {
            fprintf(stderr, "[-] Error: Invalid target hash provided with -a: %s\n", single_target_hex);
            fclose(output_handle);
            return 1;
        }
        fprintf(stderr, "[+] Single Target Mode enabled. Target hash: %s (%d bytes)\n", single_target_hex, single_target_len);
    }
    
    if (pubkey_mode) {
        fprintf(stderr, "[+] Info: Public Key Generation Mode enabled.\n");
        strcpy(selectedCharsets, "k");
        minLength = 66;
        maxLength = 66;
    }

    if(threads <= 0) { fprintf(stderr, "[-] Error: Number of threads must be greater than 0.\n"); return 1; }
    if(strlen(selectedCharsets) == 0) strcpy(selectedCharsets, "all");

    // --- 文件和过滤器加载 ---
    if (!single_target_hex) {
        if (bloomFile) {
        #ifdef _WIN32
            fprintf(stderr, "[+] Loading Bloom filter using standard I/O for Windows...\n");
            bf = bloom_load(bloomFile);
        #else
            bf = bloom_mmap_load(bloomFile);
        #endif
            if (!bf) { 
                fprintf(stderr, "[-] Error: Failed to load Bloom filter file '%s'.\n", bloomFile); 
                goto cleanup; 
            }
            fprintf(stderr, "[+] Bloom filter loaded: %llu bits, %llu hashes.\n", (unsigned long long)bf->bit_count, (unsigned long long)bf->hash_count);
        }
        if (hashFile) {
            target_hashes = hash_set_load_from_file(hashFile);
            if (!target_hashes) { fprintf(stderr, "[-] Error: Failed to load target hashes from '%s'.\n", hashFile); goto cleanup; }
            fprintf(stderr, "[+] Loaded %zu hashes for final verification.\n", hash_set_get_count(target_hashes));
        }
    }

    int num_verifiers = 0;
    if (target_hashes && !single_target_hex) {
        num_verifiers = 1;
        verification_queue = queue_init(QUEUE_CAPACITY);
        if (!verification_queue) { perror("[-] Failed to create verification queue"); goto cleanup; }
        fprintf(stderr, "[+] Starting 1 verification thread (consumer).\n");
    }

    // --- 准备字符集等 ---
    char combinedCharset[4096] = {0}, uniqueCharset[4096] = {0};
    if (!pubkey_mode) {
        char tempCharsets[1024]; strncpy(tempCharsets, selectedCharsets, sizeof(tempCharsets)-1);
        char *token = strtok(tempCharsets, ",");
        while(token != NULL) {
            bool matched = false;
            for(int j = 0; j < NUM_CHARSETS; j++) { if(strcmp(token, CHARSETS[j].identifier) == 0) { strcat(combinedCharset, CHARSETS[j].characters); matched = true; break; } }
            if(!matched && strcmp(token, "pkc") != 0) { fprintf(stderr, "[-] Error: Invalid charset identifier: %s\n", token); return 1; }
            token = strtok(NULL, ",");
        }
        bool seen[256] = {false}; int k = 0;
        for(size_t i = 0; i < strlen(combinedCharset); i++) { if (!seen[(unsigned char)combinedCharset[i]]) { seen[(unsigned char)combinedCharset[i]] = true; uniqueCharset[k++] = combinedCharset[i]; } }
        uniqueCharset[k] = '\0';
    }
    const char* finalCharset = uniqueCharset; int finalCharsetLength = strlen(finalCharset);

    // --- 初始化线程和状态 ---
    threadIds = (pthread_t*)malloc(threads * sizeof(pthread_t));
    threadData = (ThreadData*)malloc(threads * sizeof(ThreadData));
    if (!threadIds || !threadData) { perror("[-] Error allocating memory for cracker threads"); goto cleanup; }
    
    pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
    atomic_init(&state.passwords_checked, 0);
    atomic_init(&state.running, true);
    state.mutex = &output_mutex; 
    VectorU128 start_indices_per_length;
    vector_init(&start_indices_per_length);

    fprintf(stderr, "[+] Starting cracker with %d producer threads\n", threads);
    fprintf(stderr, "[+] Generator: %s\n", random ? "random" : "sequential");

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // --- 任务分配 ---
    if (!random && pubkey_mode) {
        fprintf(stderr, "[+] Public Key Sequential Mode enabled.\n");
        if (n_specified) {
            fprintf(stderr, "[+] Target count (-n) is used for progress display but run is infinite.\n");
        } else {
            fprintf(stderr, "[+] Total keys to generate: Infinite\n");
        }
        
        for(int i = 0; i < threads; ++i) {
            threadData[i].start_indices_per_length = NULL;
            threadData[i].startIndex = i; // thread_id
            threadData[i].endIndex = 0; // Not used in this mode
        }
    } else if (random) {
        if (n_specified && numPasswords_ll_for_n <= 0) {
             fprintf(stderr, "[-] Error: Number of passwords (-n) must be positive.\n"); goto cleanup;
        }
        u128 passwordsPerThread = n_specified ? (u128)numPasswords_ll_for_n / threads : 0;
        u128 remainder = n_specified ? (u128)numPasswords_ll_for_n % threads : 0;
        u128 current_start = 0;
        for(int i = 0; i < threads; ++i) {
            if (n_specified) {
                u128 chunk_size = passwordsPerThread + ((u128)i < remainder ? 1 : 0);
                threadData[i].startIndex = current_start;
                threadData[i].endIndex = current_start + chunk_size;
                current_start += chunk_size;
            } else { threadData[i].startIndex = 0; threadData[i].endIndex = 1; }
            threadData[i].start_indices_per_length = NULL;
        }
    } else {
        u128 totalPasswords = 0;
        for (int len = minLength; len <= maxLength; ++len) {
            u128 count_for_len = int_pow128(finalCharsetLength, len);
            if (count_for_len == 0 && (finalCharsetLength > 1 || len > 0)) { fprintf(stderr, "[-] Error: Combination count for length %d overflowed.\n", len); goto cleanup; }
            vector_push_back(&start_indices_per_length, totalPasswords);
            u128 temp_total;
            if (__builtin_add_overflow(totalPasswords, count_for_len, &temp_total)) { fprintf(stderr, "[-] Error: Total combination count overflowed.\n"); goto cleanup; }
            totalPasswords = temp_total;
        }
        fprintf(stderr, "[+] Total combinations to generate: "); print_u128(totalPasswords); fprintf(stderr, ".\n");
        u128 passwordsPerThread = totalPasswords / threads;
        u128 remainder = totalPasswords % threads;
        u128 current_start_index = 0;
        for (int i = 0; i < threads; i++) {
            u128 chunk_size = passwordsPerThread + ((u128)i < remainder ? 1 : 0);
            threadData[i].startIndex = current_start_index;
            threadData[i].endIndex = current_start_index + chunk_size;
            current_start_index += chunk_size;
            threadData[i].start_indices_per_length = &start_indices_per_length;
        }
    }
    
    // --- 启动消费者线程  ---
    if (num_verifiers > 0) {
        verifier_threads = malloc(sizeof(pthread_t) * num_verifiers);
        verifier_data = malloc(sizeof(ThreadData) * num_verifiers);
        if (!verifier_threads || !verifier_data) { perror("[-] Error allocating memory for verifier threads"); goto cleanup; }
        for (int i = 0; i < num_verifiers; i++) {
            verifier_data[i].shared_queue = verification_queue;
            verifier_data[i].target_hashes = target_hashes;
            verifier_data[i].output_file = output_handle;
            verifier_data[i].mutex = &output_mutex;
            if(pthread_create(&verifier_threads[i], NULL, verification_thread_worker, &verifier_data[i]) != 0) {
                fprintf(stderr, "[-] Error: Failed to create verifier thread %d\n", i);
            }
        }
    }

    // --- 启动工作线程 (生产者) ---
    for(int i = 0; i < threads; ++i) {
        threadData[i].thread_id = i;
        threadData[i].state = &state;
        threadData[i].mutex = &output_mutex;
        threadData[i].minLength = minLength;
        threadData[i].maxLength = maxLength;
        threadData[i].random = random;
        threadData[i].charset = finalCharset;
        threadData[i].charsetLength = finalCharsetLength;
        threadData[i].infinite = ( (random && !n_specified) || (!random && pubkey_mode) ); 
        threadData[i].hash_mode = hash_mode;
        threadData[i].pubkey_mode = pubkey_mode;
        threadData[i].debug_mode = debug_mode;
        threadData[i].output_file = output_handle;
        threadData[i].local_passwords_checked = 0;

        if (single_target_hex) {
            threadData[i].single_target_bin = single_target_bin;
            threadData[i].single_target_len = single_target_len;
            threadData[i].bloom_filter = NULL;
            threadData[i].target_hashes = NULL;
            threadData[i].shared_queue = NULL;
        } else {
            threadData[i].single_target_bin = NULL;
            threadData[i].single_target_len = 0;
            threadData[i].bloom_filter = bf;
            threadData[i].target_hashes = target_hashes;
            threadData[i].shared_queue = verification_queue;
        }

        if(pthread_create(&threadIds[i], NULL, cracker_thread_worker, &threadData[i]) != 0) {
            fprintf(stderr, "[-] Error: Failed to create thread %d\n", i);
        }
    }
    
    StatusThreadArgs status_args;
    status_args.state = &state;
    status_args.thread_data_array = threadData;
    status_args.thread_count = threads;
    pthread_create(&status_thread, NULL, status_thread_worker, &status_args);

    for (int i = 0; i < threads; i++) { pthread_join(threadIds[i], NULL); }

    if (num_verifiers > 0) {
        queue_shutdown(verification_queue);
        for (int i = 0; i < num_verifiers; i++) { pthread_join(verifier_threads[i], NULL); }
    }

    atomic_store(&state.running, false);
    pthread_join(status_thread, NULL);

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    unsigned long long total_checked = 0;
    for (int i = 0; i < threads; ++i) { total_checked += threadData[i].local_passwords_checked; }
    
    fprintf(stderr, "\n[+] Cracking finished in %.2f seconds.\n", elapsed);
    if (elapsed > 0.001) {
        fprintf(stderr, "[+] Total passwords checked: %llu (%.2f M/s avg).\n", total_checked, total_checked / elapsed / 1000000.0);
    } else {
        fprintf(stderr, "[+] Total passwords checked: %llu.\n", total_checked);
    }

cleanup:
    if (!random && !pubkey_mode) { vector_free(&start_indices_per_length); }
    if (bf) { bloom_free(bf); }
    if (target_hashes) { hash_set_destroy(target_hashes); }
    if (verification_queue) { queue_destroy(verification_queue); }
    
    if (output_handle) { fclose(output_handle); }
    pthread_mutex_destroy(&output_mutex);
    if (threadIds) free(threadIds);
    if (threadData) free(threadData);
    if (verifier_threads) free(verifier_threads);
    if (verifier_data) free(verifier_data);

    return 0;
}
