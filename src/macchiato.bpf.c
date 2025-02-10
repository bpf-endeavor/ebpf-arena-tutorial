/* This program tries to use the Arena map from Mogu to reply to network
 * queries from XDP hook point
 * (Basically sharing Arena between two eBPF programs but one is XDP)
 * */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"

#include "shared_struct.h"

long my_kfunc_reg_arena(void *p__map) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 2); /* number of pages */
} arena_map SEC(".maps");

__arena void *mem = NULL;

SEC("xdp")
int macchiato_main(struct xdp_md *xdp)
{
    bpf_printk("macchiato: hello world\n");

    if (mem == NULL) {
        my_kfunc_reg_arena(&arena_map);
        bpf_printk("macchiato: not seein the memory!\n");
        return XDP_PASS;
    }

    void *data = (void *)(__u64)(xdp->data);
    void *data_end = (void *)(__u64)(xdp->data_end);
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth+1);
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_ntohs(8080))
        return XDP_PASS;

    __arena entry_t *e = mem;
    bpf_printk("macchiato: counter=%lld\n", e->counter);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
