#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"

#include "shared_struct.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2); /* number of pages */
} arena SEC(".maps");

/* keep a flag fo whether we have allocated & initilized the memory page */
static bool flag_initialized = false;

/* this global variable holds the pointer to page we allocated from arena and
 * is also shared with the userspace
 * */
__arena void *mem = NULL;

static __always_inline int __initialize(void)
{
    /* helper signiture:
     * void *bpf_arena_alloc_pages(void *p__map, void *addr__ign, u32 page_cnt,
     *  int node_id, u64 flags)
     * https://docs.ebpf.io/linux/kfuncs/bpf_arena_alloc_pages/
     * */
    mem = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
    if (mem == NULL) {
        bpf_printk("Failed to allocate memory");
        return -1;
    }

    flag_initialized = true;
    return 0;
}

SEC("syscall")
int mogu_main(void *_)
{
    bpf_printk("hello world\n");
    if (!flag_initialized) {
        if (__initialize() != 0) {
            return 1;
        }
    }
    if (mem == NULL) {
        /* this branch must never happen! */
        return 1;
    }
    __arena entry_t *e = mem;
    e->counter += 1;
    bpf_printk("counter: %lld\n", e->counter);
    return 0;
}

char _license[] SEC("license") = "GPL";
