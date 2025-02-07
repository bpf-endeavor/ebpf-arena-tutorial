#pragma once
#include <linux/bpf.h>

typedef struct {
    __u64 counter;
} entry_t;
