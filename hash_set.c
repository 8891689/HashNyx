#include "hash_set.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define INITIAL_SIZE 1024 // 初始桶大小
#define MAX_LOAD_FACTOR 0.75

typedef struct Node {
    char* key;
    struct Node* next;
} Node;

struct HashSet {
    Node** buckets;
    size_t size;
    size_t capacity;
    size_t num_items; 
};


size_t hash_set_get_count(const HashSet* set) {
    if (!set) {
        return 0;
    }
    return set->num_items; 
}

// FNV-1a 哈希函数
static unsigned long hash_function(const char* key) {
    unsigned long hash = 0x811c9dc5;
    while (*key) {
        hash ^= (unsigned char)*key++;
        hash *= 0x01000193;
    }
    return hash;
}

static void rehash(HashSet* set);

HashSet* hash_set_create(size_t capacity) {
    HashSet* set = (HashSet*)malloc(sizeof(HashSet));
    if (!set) return NULL;
    
    size_t initial_capacity = INITIAL_SIZE;
    while (initial_capacity < capacity) {
        initial_capacity *= 2;
    }

    set->buckets = (Node**)calloc(initial_capacity, sizeof(Node*));
    if (!set->buckets) {
        free(set);
        return NULL;
    }
    set->size = 0;
    set->capacity = initial_capacity;
    return set;
}

void hash_set_add(HashSet* set, const char* key) {
    if ((double)set->size / set->capacity > MAX_LOAD_FACTOR) {
        rehash(set);
    }

    unsigned long hash = hash_function(key);
    size_t index = hash % set->capacity;

    Node* current = set->buckets[index];
    while (current) {
        if (strcmp(current->key, key) == 0) {
            return; // Key already exists
        }
        current = current->next;
    }

    Node* newNode = (Node*)malloc(sizeof(Node));
    newNode->key = strdup(key);
    newNode->next = set->buckets[index];
    set->buckets[index] = newNode;
    set->size++;
}

bool hash_set_contains(const HashSet* set, const char* key) {
    if (!set) return false;
    unsigned long hash = hash_function(key);
    size_t index = hash % set->capacity;

    Node* current = set->buckets[index];
    while (current) {
        if (strcmp(current->key, key) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

void hash_set_destroy(HashSet* set) {
    if (!set) return;
    for (size_t i = 0; i < set->capacity; ++i) {
        Node* current = set->buckets[i];
        while (current) {
            Node* temp = current;
            current = current->next;
            free(temp->key);
            free(temp);
        }
    }
    free(set->buckets);
    free(set);
}

static void rehash(HashSet* set) {
    size_t old_capacity = set->capacity;
    Node** old_buckets = set->buckets;

    set->capacity *= 2;
    set->buckets = (Node**)calloc(set->capacity, sizeof(Node*));
    set->size = 0;

    for (size_t i = 0; i < old_capacity; ++i) {
        Node* current = old_buckets[i];
        while (current) {
            hash_set_add(set, current->key);
            Node* temp = current;
            current = current->next;
            free(temp->key);
            free(temp);
        }
    }
    free(old_buckets);
}

HashSet* hash_set_load_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening hash file");
        return NULL;
    }

    // 先统计行数以优化哈希表大小
    size_t line_count = 0;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file)) {
        line_count++;
    }
    rewind(file);

    HashSet* set = hash_set_create(line_count > 0 ? line_count : INITIAL_SIZE);
    if (!set) {
        fclose(file);
        return NULL;
    }
    
    fprintf(stderr, "[+] Loading %zu hashes into memory for final verification...\n", line_count);

    while (fgets(buffer, sizeof(buffer), file)) {
        // 移除换行符
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (strlen(buffer) > 0) { // 忽略空行
            hash_set_add(set, buffer);
        }
    }

    fclose(file);
    fprintf(stderr, "[+] Finished loading hashes.\n");
    return set;
}
