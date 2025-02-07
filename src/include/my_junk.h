#pragma once
#include <linux/bpf.h>
#include "compiler.h"

static inline int my_memcmp(__u8 *a, __u8 *b, __u16 sz)
{
    switch (sz) {
        case 4:
            return *(__u32 *)a == *(__u32 *)b ? 0 : 1;
        case 8:
            return *(__u64 *)a == *(__u64 *)b ? 0 : 1;
        default:
            break;
    }
    for (__u16 i = 0; i < sz && i < 128; i++)
        if (a[i] != b[i])
            return 1;
    return 0;
}


static inline __nobuiltin("memcpy") void *my_memcpy(__u8 *dst, __u8 *src, __u16 sz)
{
    for (__u16 i = 0; i < sz && i < 128; i++)
        dst[i] = src[i];
    return dst;
}
