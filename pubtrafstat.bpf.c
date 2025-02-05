/*
 * @description: Experimenting with eBPF Arena Map features. Trying to figure
 * out:
 *   1. How the API is used ?
 *       -  How does memory address space work (e.g., __arena macro, cast_user,
 *       cast_kern)
 *       - How to initilze the data-structure in the begining?
 *   2. Can I make it work on version 6.8 ? (Ubuntu 22.04 HWE is using this and
 *      I do not want to install a custom kernel)
 *   3. How is the performance compared to the BPF_MAP_TYPE_HASH?
 *   4. What is the minimum version of LLVM that I can use?
 *
 * @author: Farbod Shahinfar - 2025
 * */

/* NOTES: more detailed questions
 * 1. Implementation of arena_htab does not define the memory region NUMA node?
 * 2. Can I apply the CacheDirectory type of optimizations here?
 * 3. How can I do prefetching with this implmentation?
 * 4. Is it possible to allocate from HUGE page pool for the htab?
 * */

/* NOTES: What does the app do
 *   Gather statistics about the incomming traffic to my VM with a public IP
 *   address. It will create a table for each source address as follows:
 *
 *   src ip --> L1 Hash Map --> L2 Hash MAP (A map holding all the
 *                 rc-port+dst-port combinations observed from the source ip.)
 * */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "compiler.h"

/* The arena helpers (e.g, bpf_arena_htab.h header) expects this map (with the
 * exact name arena) to be defined before they are included
 * */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
} arena SEC(".maps");

/* The bpf_arena_list relies on this value, I am not sure what the purpose is
 * */
#define can_loop true
#include "bpf_arena_htab.h"

typedef enum {
    NO = 0, /* relying on the fact that eBPF initilizes everything to zero */
    YES,
} init_status_t;


init_status_t htab_init_status;
void __arena *htab_for_user;

#define __inline static inline __attribute__((always_inline))
#define CONTINUE -1
#define IPV4_SZ 4
#define data(ctx) ((void *)(__u64)(ctx)->data)
#define dataend(ctx) ((void *)(__u64)(ctx)->data_end)

typedef struct {
    __u16 offset;
    __u16 l3_proto;
    __u8 l4_proto;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
} state_t;

typedef struct {
    __u64 counter;
    struct htab __arena *l2map;
} l1_entry_t;

__inline int parse_eth(struct xdp_md *ctx, state_t *s)
{
    struct ethhdr *eth = data(ctx);
    if ((void *)(eth + 1) > dataend(ctx)) {
        return XDP_PASS;
    }
    s->l3_proto = bpf_ntohs(eth->h_proto);
    s->offset = sizeof(struct ethhdr);
    return CONTINUE;
}

__inline int parse_ipv4(struct xdp_md *ctx, state_t *s)
{
    struct iphdr *ip = data(ctx) + s->offset;
    if ((void *)(ip + 1) > dataend(ctx)) {
        return XDP_PASS;
    }
    s->l4_proto = ip->protocol;
    s->saddr = bpf_ntohl(ip->saddr);
    s->offset += ip->ihl * 4;
    return CONTINUE;
}

__inline int parse_l4(struct xdp_md *ctx, state_t *s)
{
    /* The port numbers are in the same position in both TCP and UDP */
    struct udphdr *l4 = data(ctx) + s->offset;
    if ((void *)(l4 + 1) > dataend(ctx)) {
        return XDP_PASS;
    }
    s->sport = bpf_ntohs(l4->source);
    s->dport = bpf_ntohs(l4->dest);
    return CONTINUE;
}

__inline int do_book_keeping(state_t *s)
{
	int zero = 0;
	struct htab __arena *htab; /* L1 map */
	__u64 i;

    /* Check if hash map was created before */
    if (htab_init_status == NO) {
        htab_init_status = YES;
        htab = bpf_alloc(sizeof(*htab));
        cast_kern(htab);
        htab_init(htab, IPV4_SZ, sizeof(l1_entry_t));

        /* Expose the L1 table to userspace */
        cast_user(htab);
        htab_for_user = htab;
    }

    /* Update the counter for the source ip */
    l1_entry_t *e1 = htab_lookup_elem(htab, &s->saddr);
    if (e1 == NULL) {
        /* It is the first packet from this ip. Insert an entry */
        l1_entry_t tmp = {
            .counter = 1,
            .l2map = NULL,
        };
        if (htab_update_elem(htab, &s->saddr, &tmp) != 0) {
            bpf_printk("Failed to insert to L1 map\n");
        }
    }
	return 0;
}

int prog(struct xdp_md *ctx)
{
    state_t s;
    int ret;
    ret = parse_eth(ctx, &s);
    if (ret != CONTINUE)
        goto store;
    ret = parse_ipv4(ctx, &s);
    if (ret != CONTINUE)
        goto store;
    switch (s.l4_proto) {
        case IPPROTO_TCP: /* fallthrough */
        case IPPROTO_UDP:
            ret = parse_l4(ctx, &s);
            ret = XDP_PASS;
            break;
        default:
            ret = XDP_PASS;
            goto store;
    }

store:
	do_book_keeping(&s);
    return ret;
}

char _license[] SEC("license") = "GPL";
