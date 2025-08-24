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
// gcc HashNyx_bloom.c bloom.c utils.c -O3 -o HashNyx_bloom -pthread -lm -static

// HashNyx_bloom.c   cat hashes.txt | ./HashNyx_bloom   ,  type 1.txt | HashNyx_bloom.exe
#include "bloom.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h> 

#define DEFAULT_FP_RATE 0.0001 // 0.01%

int hex_to_bytes(const char *hex_str, size_t hex_len, uint8_t *byte_array, size_t max_bytes);

int main(int argc, char *argv[]) {
    uint64_t count = 0;
    char line[256];

    FILE *tmp = tmpfile();
    if (!tmp) {
        perror("Failed to create temp file");
        return 1;
    }

    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) >= 32) { 
            fprintf(tmp, "%s\n", line);
            count++;
        }
    }

    if (count == 0) {
        fprintf(stderr, "Error: No valid hashes found in input.\n");
        fclose(tmp);
        return 1;
    }
    rewind(tmp);

    double fp_rate = DEFAULT_FP_RATE;
    if (argc > 1) {
        fp_rate = atof(argv[1]);
        if (fp_rate <= 0 || fp_rate >= 1) {
             fprintf(stderr, "Warning: Invalid fp_rate '%s'. Using default %.4f.\n", argv[1], DEFAULT_FP_RATE);
             fp_rate = DEFAULT_FP_RATE;
        }
    }

    printf("Processing %" PRIu64 " hashes with a target false positive rate of %.4f%%\n", count, fp_rate * 100.0);

    uint64_t bit_count = (uint64_t)ceil(-((double)count * log(fp_rate)) / (log(2) * log(2)));
    int hash_count = (int)round(((double)bit_count / (double)count) * log(2));

    if (bit_count < 1) bit_count = 1;
    if (hash_count < 1) hash_count = 1;

    printf("Optimal parameters calculated:\n");
    printf(" - Bit count (m): %" PRIu64 "\n", bit_count);
    printf(" - Hash functions (k): %d\n", hash_count);

    BloomFilter *bf = bloom_init_optimal(bit_count, hash_count);
    if (!bf) {
        perror("Failed to initialize bloom filter with optimal parameters");
        fclose(tmp);
        return 1;
    }
    
    size_t added = 0;
    while (fgets(line, sizeof(line), tmp)) {
        line[strcspn(line, "\r\n")] = 0;
        bloom_add_hex(bf, line);
        added++;
    }
    fclose(tmp);
    
    printf("Successfully added %zu hashes to Bloom filter.\n", added);
    
    const char *output_file = "targets.bf";
    if (bloom_save(bf, output_file) != 0) {
        perror("Failed to save bloom filter");
    } else {
        size_t byte_size = bf->byte_count;
        double mb_size = (double)byte_size / (1024.0 * 1024.0);
        printf("Bloom filter successfully saved to %s (Size: %.2f MB)\n", output_file, mb_size);
    }
    
    bloom_free(bf);
    return 0;
}
