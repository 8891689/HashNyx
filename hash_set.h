#ifndef HASH_SET_H
#define HASH_SET_H

#include <stddef.h>
#include <stdbool.h>

typedef struct HashSet HashSet;

HashSet* hash_set_create(size_t capacity);

void hash_set_add(HashSet* set, const char* key);

bool hash_set_contains(const HashSet* set, const char* key);

void hash_set_destroy(HashSet* set);

HashSet* hash_set_load_from_file(const char* filename);


size_t hash_set_get_count(const HashSet* set);

#endif // HASH_SET_H
