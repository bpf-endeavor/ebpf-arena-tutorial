/* This program tries to use the Arena map from Mogu without allocating memory
 * pages.
 * */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"

#include "shared_struct.h"

/* NOTE: the user-space loader should change the file descriptor of this map to
 * what is set for Mogu. This will mean both will access to the same map.
 * */
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 2); /* number of pages */
} arena SEC(".maps");

/* The user-space program will provide the memory address
 * */
__arena void *mem = NULL;

SEC("syscall")
int aloe_main(void *_)
{
    /* do a map access so that this program is associated with arena */
    /* int zero = 0; */
    /* int ret = 123; */
    /* ret = bpf_map_push_elem(&arena, &zero, 0); */
    /* bpf_printk("aloe: ret: %d\n"); */
    /* void __arena *_tmp = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0); */
    /* ------------------------------------------------------------ */

    bpf_printk("aloe: \n");
    if (mem == NULL) {
        /* this branch must never happen! */
        bpf_printk("aloe: not seeing the memory!\n");
        return 1;
    }
    __arena entry_t *e = mem;
    bpf_printk("aloe: counter=%lld\n", e->counter);
    return 0;
}

char _license[] SEC("license") = "GPL";
