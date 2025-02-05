/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

/* Modifications:
 * Make keys generic and use jhash to select buckets.
 *
 * NOTE: should the keys are assumed to have a fixed size. It may be
 * changed to support variable sized keys.
 * Farbod Shahinfar 2025
 * */

#pragma once
#include <errno.h>
#include "bpf_arena_alloc.h"
#include "bpf_arena_list.h"

/*#include "builtins.h"*/
#include "my_junk.h"
#include "jhash.h"

typedef __u16 keysz_t;
typedef __u16 valsz_t;
#define EXTRACT_KEY(htab, elm) (((void *)(elm)) + sizeof(hashtab_elem_t))
#define EXTRACT_VAL(htab, elm) (((void *)(elm)) + sizeof(hashtab_elem_t) + htab->key_sz)

struct htab_bucket {
	struct arena_list_head head;
};
typedef struct htab_bucket __arena htab_bucket_t;

struct htab {
	htab_bucket_t *buckets;
	int n_buckets;
    keysz_t key_sz;
    valsz_t val_sz;
};
typedef struct htab __arena htab_t;

static inline htab_bucket_t *__select_bucket(htab_t *htab, __u32 hash)
{
	htab_bucket_t *b = htab->buckets;

	cast_kern(b);
	return &b[hash & (htab->n_buckets - 1)];
}

static inline arena_list_head_t *select_bucket(htab_t *htab, __u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

struct hashtab_elem {
	struct arena_list_node hash_node;
	int hash;
    /* Key, and value would be here */
};
typedef struct hashtab_elem __arena hashtab_elem_t;

static hashtab_elem_t *lookup_elem_raw(arena_list_head_t *head, __u32 hash,
        void *key, keysz_t key_sz)
{
	hashtab_elem_t *l;

	list_for_each_entry(l, head, hash_node)
		if (l->hash == hash) {
            void *l_key = EXTRACT_KEY(htab, l);
            if (my_memcmp(l_key, key, key_sz) == 0) {
                return l;
            }
        }

	return NULL;
}

static int htab_hash(void *key, keysz_t sz)
{
    switch (sz) {
        case 4:
            return jhash_1word(*(__u32 *)key, JHASH_INITVAL);
        case 8:
            return jhash_2words(*(__u32 *)key, *((__u32 *)key + 1),
                    JHASH_INITVAL);
        default:
            break;
    }
	return jhash(key, sz, JHASH_INITVAL);
}

__weak void *htab_lookup_elem(htab_t *htab __arg_arena, void *key)
{
	hashtab_elem_t *l_old;
	arena_list_head_t *head;

	cast_kern(htab);
    int hash = htab_hash(key, htab->key_sz);
	head = select_bucket(htab, hash);
	l_old = lookup_elem_raw(head, hash, key, htab->key_sz);
	if (l_old) {
        void *l_val = (void *)(l_old + 1) + htab->key_sz;
		return l_val;
    }
	return NULL;
}

__weak int htab_update_elem(htab_t *htab __arg_arena, void *key, void *value)
{
	hashtab_elem_t *l_new = NULL, *l_old;
	arena_list_head_t *head;

	cast_kern(htab);
    int hash = htab_hash(key, htab->key_sz);
	head = select_bucket(htab, hash);
	l_old = lookup_elem_raw(head, hash, key, htab->key_sz);

	l_new = bpf_alloc(sizeof(hashtab_elem_t) + htab->key_sz + htab->val_sz);
	if (!l_new)
		return -ENOMEM;
	l_new->hash = hash;
    void *l_key = EXTRACT_KEY(htab, l_new);
    my_memcpy(l_key, key, htab->key_sz);
    void *l_val = l_key + htab->key_sz;
    my_memcpy(l_val, value, htab->val_sz);

	list_add_head(&l_new->hash_node, head);
	if (l_old) {
		list_del(&l_old->hash_node);
		bpf_free(l_old);
	}
	return 0;
}

void htab_init(htab_t *htab, keysz_t key_sz, valsz_t val_sz)
{
    const int count_pages = 2;
	void __arena *buckets = bpf_arena_alloc_pages(&arena,
            NULL, count_pages, NUMA_NO_NODE, 0);

	cast_user(buckets);
	htab->buckets = buckets;
	htab->n_buckets = count_pages * PAGE_SIZE / sizeof(struct htab_bucket);
    htab->key_sz = key_sz;
    htab->val_sz = val_sz;
}
