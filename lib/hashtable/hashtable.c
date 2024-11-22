/**
 * \file hashtable.c
 * \brief Hashtable implementation
 */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hashtable/hashtable.h>
#include <hashtable/multimap.h>

/*
 *
 * M2 Hash Table Slab Implementation
 *
 */

/**
 * \brief create an empty hashtable with default capacity
 * \return an empty hashtable
 */
struct hashtable *create_hashtable_slab(void *slab_buf, size_t slab_sz) {
    return create_hashtable2_slab(11, slab_buf, slab_sz);
}

struct hashtable *create_hashtable2_slab(int capacity, void *slab_buf, size_t slab_sz) {

    size_t init_size = sizeof(struct hashtable) + capacity * sizeof(struct _ht_entry);

    assert(slab_sz >= init_size); // TODO: Unsure of what to do if there isn't enough size, for now just error with the assert.

    // We will use the first part of the slab for the hashtable, and the rest for the entries.
    struct hashtable *_ht = slab_buf;
    assert(_ht != NULL);

    _ht->using_slab = true;
    void *entry_buf = slab_buf + sizeof(struct hashtable);
    size_t entry_buf_size = slab_sz - sizeof(struct hashtable);

    slab_init(&_ht->sa, sizeof(struct _ht_entry), slab_default_refill);
    slab_grow(&_ht->sa, entry_buf, entry_buf_size);
    // HACK to keep slab_allocator a pointer
    _ht->slab_allocator = &_ht->sa;

    ht_init(_ht, capacity);
    return _ht;
}

/**
 * \brief fill hashtable with entry
 */
void create_hashtable_slab_fill(struct hashtable * _ht, struct slab_allocator *entry_allocator) {
    create_hashtable2_slab_fill(_ht, 11, entry_allocator);
}

void create_hashtable2_slab_fill(struct hashtable *_ht, int capacity, struct slab_allocator *entry_allocator) {
    // We will use the first part of the slab for the hashtable, and the rest for the entries.
    assert(_ht != NULL);
    _ht->using_slab = true;
    _ht->slab_allocator = entry_allocator;
    _ht->sa = *_ht->slab_allocator;
    ht_init(_ht, capacity);
}

/**
 * \brief create an empty hashtable with a given capacity
 * \param capacity the capacity
 * \return an empty hashtable.
 */
void ht_init(struct hashtable *_ht, uint32_t capacity) {
    DEBUG_PRINTF("ht_init called for hash table at %p\n", _ht);

    _ht->capacity = capacity;

    if (_ht->using_slab) {
        _ht->entries = slab_alloc_multiple(_ht->slab_allocator, _ht->capacity);
        if (_ht->entries == NULL){
            _ht->slab_allocator->refill_func(_ht->slab_allocator);
            _ht->entries = slab_alloc_multiple(_ht->slab_allocator, _ht->capacity);
            if (_ht->entries == NULL) {
                DEBUG_PRINTF("Failed to allocate memory for entries\n");
                return;
            };
        }
    } else {
        DEBUG_PRINTF("But why isn't this true?\n");
    }
    assert(_ht->entries != NULL);
    memset(_ht->entries, 0, _ht->capacity * sizeof(struct _ht_entry));
}

int hash(uint64_t key) {
    register int _hash = 5381;

    uint64_t val = key;

    for (size_t i = 0; i < 8; i++) {
        _hash = ((_hash << 5) + _hash) + ((uint8_t) (val & 0xff));
        val >>= 8;
    }
    
    return _hash;
}

int hashtable_put(struct hashtable *ht, uint64_t key, void *value) {
    struct _ht_entry *e;

    DEBUG_PRINTF("Putting %p at key: %ld\n", value, key);
    DEBUG_PRINTF("Hashtable location %p\n", ht);

    e = slab_alloc(ht->slab_allocator);
    if (NULL == e) {
        return 1;
    }
    e->key = key;
    e->value = (void *)value;

    return hashtable_put_helper(ht, e);
}

/**
 * \brief put a new key/value pair into the hashtable
 * \param ht the hashtable
 * \param key the key. Has to be a string.
 * \param value the value. Can be any pointer. This function does
 *      not copy the value or stores it. The caller is responsible for
 *      maintaining the value, the hashtable only keeps pointers.
 * \return 0 if the operation succeeded, otherwise an error code.
 */
int hashtable_put_helper(struct hashtable *ht, struct _ht_entry *entry) {
    int _hash_value = hash(entry->key);

    // TODO: XXX check for size and increase capacity, if necessary
    ++(ht->entry_count);

    entry->hash_value = _hash_value;
    int _index = index_for(ht->capacity, _hash_value);
    entry->next = ht->entries[_index];
    ht->entries[_index] = entry;

    return 0;
}

/**
 * \brief get a value from the hashtable for a given key
 * \param ht the hashtable
 * \param key the key. Has to be a zero-terminated string.
 * \param value the value pointer. Pointer to the value
 * \return the value or NULL if there is no such key/value pair
 */
void *hashtable_get(struct hashtable *ht, uint64_t key) {
    assert(ht != NULL);

    DEBUG_PRINTF("Getting key: %ld\n", key);
    DEBUG_PRINTF("Hashtable location %p\n", ht);

    int _hash_value = hash(key);
    int _index = index_for(ht->capacity, _hash_value);
    struct _ht_entry *_e = ht->entries[_index];

    while (NULL != _e) {
        if ((_hash_value == _e->hash_value) && (key == _e->key)) {
            return _e->value;
        }
        _e = _e->next;
    }
    
    DEBUG_PRINTF("Couldn't find the key: key = %d\n", key);
    return NULL;
}

int hashtable_remove(struct hashtable *ht, uint64_t key) {
    assert(ht != NULL);

    int _hash_value = hash(key);
    int _index = index_for(ht->capacity, _hash_value);
    struct _ht_entry *_e = ht->entries[_index];
    struct _ht_entry *_prev = NULL;
    while (NULL != _e) {
        if ((_hash_value == _e->hash_value) && (key == _e->key)) {
            if (_prev == NULL) {
                ht->entries[_index] = _e->next;
            } else {
                _prev->next = _e->next;
            }
            if (ht->using_slab) slab_free(ht->slab_allocator, _e);
            else free(_e);
            return 0;
        }
        _prev = _e;
        _e = _e->next;
    }
    return 1;
}


/**
 * \brief get the index for an given hash in the bucket table
 * \param table_length the length of the table
 * \param hash_value the hash
 * \return the index
 */
int index_for(int table_length, int hash_value)
{
    return ((unsigned)hash_value % table_length);
}