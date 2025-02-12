/*
 * */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>

#include <bpf/bpf.h>

#include "include/shared_struct.h"
#include "mogu.skel.h"
#include "aloe.skel.h"

/* Some global vars */
static volatile int running = 0;
static int ebpf_prog_fd = -1;
static struct mogu *skel = NULL;
static struct aloe *askel = NULL;

#ifdef HAS_XDP
#include "macchiato.skel.h"
static struct macchiato *xskel = NULL;
#endif

static int run_ebpf_prog(int prog_fd)
{
    /* Look here: https://docs.kernel.org/bpf/bpf_prog_run.html */
    /* time_t before, after; */
    int ret;
    struct bpf_test_run_opts test_opts;
    memset(&test_opts, 0, sizeof(struct bpf_test_run_opts));
    /* TODO: optionally pass a context to it */
    test_opts.sz = sizeof(struct bpf_test_run_opts);
    test_opts.data_in = NULL;
    test_opts.data_size_in = 0;
    test_opts.ctx_in = NULL;
    test_opts.ctx_size_in = 0;
    test_opts.repeat = 0;
    test_opts.cpu = 0;
    /* before = read_tsc(); */
    ret = bpf_prog_test_run_opts(prog_fd, &test_opts);
    /* after = read_tsc(); */
    if (ret < 0) {
        perror("something went wrong\n");
        return -1;
    }
    /*last_test_duration = test_opts.duration;*/
    return test_opts.retval;
}

static void read_the_shared_mem(void)
{
    entry_t *e = skel->bss->mem;
    if (e == NULL) {
        printf("NOTE: the initialization was not successful!\n");
        return;
    }
    printf("user: counter=%lld\n", e->counter);
}

static void handle_signal(int s) {
    running = 0;
}

static void handle_invoke_signal(int s) {
    if (ebpf_prog_fd == -1)
        return;
    run_ebpf_prog(ebpf_prog_fd);
    read_the_shared_mem();
}

static void handle_invoke_signal2(int s) {
    if (ebpf_prog_fd == -1)
        return;
    run_ebpf_prog(bpf_program__fd(askel->progs.aloe_main));
    read_the_shared_mem();
}

int main(int argc, char *argv[])
{
#ifdef HAS_XDP
    char *ifacename = "veth1";
    const int ifindex = if_nametoindex(ifacename);
    const int xdp_flags = 0;

    if (!ifindex) {
        fprintf(stderr, "Failed to find the interface (%s) for XDP program!\n",
                ifacename);
        return EXIT_FAILURE;
    }
#endif

    skel = mogu__open();
    if (!skel) {
        fprintf(stderr, "Failed to open the skeleton\n");
        return EXIT_FAILURE;
    }
    askel = aloe__open();
    if (!askel) {
        fprintf(stderr, "Failed to open aloe skeleton\n");
        return EXIT_FAILURE;
    }

#ifdef HAS_XDP
    xskel = macchiato__open();
    if (!xskel) {
        fprintf(stderr, "Failed to open macchiato skeleton\n");
        return EXIT_FAILURE;
    }
#endif

    /* Set the sleepable flag for the program using the arena alloc page helper
     * */
    bpf_program__set_flags(skel->progs.mogu_main, BPF_F_SLEEPABLE);
    bpf_program__set_flags(askel->progs.aloe_main, BPF_F_SLEEPABLE);
    /* NOTE: XDP does not support the sleepable flag. Most importantly, we do
     * not want to sleep in XDP anyway because we are after performance */

    if (mogu__load(skel)) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return EXIT_FAILURE;
    }

    if (mogu__attach(skel)) {
        fprintf(stderr, "Failed to attach the program\n");
        mogu__destroy(skel);
        return EXIT_FAILURE;
    }

    /* for testing: invoke the program right after loading it.
     * It should allocate some memory which we would pass to Aloe for use
     * */
    ebpf_prog_fd = bpf_program__fd(skel->progs.mogu_main);
    handle_invoke_signal(0);

    /* Configure Aloe & Macchiato */
    {
        /* Set the same Arena map for Aloe */
        int arena_fd = bpf_map__fd(skel->maps.arena);
        bpf_map__reuse_fd(askel->maps.arena_map, arena_fd);
        /* Pass the pointer to the Aloe */
        askel->bss->mem = skel->bss->mem;

#ifdef HAS_XDP
        bpf_map__reuse_fd(xskel->maps.arena_map, arena_fd);
        xskel->bss->mem = skel->bss->mem;
#endif
    }

    if (aloe__load(askel)) {
        fprintf(stderr, "Failed to load Aloe program\n");
        mogu__detach(skel);
        mogu__destroy(skel);
        return EXIT_FAILURE;
    }

    if (aloe__attach(askel)) {
        fprintf(stderr, "Failed to attach the program\n");
        mogu__detach(skel);
        mogu__destroy(skel);
        aloe__destroy(askel);
        return EXIT_FAILURE;
    }

#ifdef HAS_XDP
    if (macchiato__load(xskel)) {
        fprintf(stderr, "Failed to load Macchiato program\n");
        mogu__detach(skel);
        mogu__destroy(skel);
        aloe__detach(askel);
        aloe__destroy(askel);
        return EXIT_FAILURE;
    }

    {
        /* Attach XDP */
        int prog_fd = bpf_program__fd(xskel->progs.macchiato_main);
        if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) != 0) {
            mogu__detach(skel);
            mogu__destroy(skel);
            aloe__detach(askel);
            aloe__destroy(askel);
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
            macchiato__destroy(xskel);
            return EXIT_FAILURE;
        }
    }
#endif

    /* Keep running and handle signals */
    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_invoke_signal);
    signal(SIGUSR2, handle_invoke_signal2);
    printf("Hit Ctrl+C to terminate ...\n");
    printf("Invoke eBPF program:\n");
    printf("\tMogu: pkill -SIGUSR1 mogu_loader\n");
    printf("\tAloe: pkill -SIGUSR2 mogu_loader\n");
#ifdef HAS_XDP
    printf("\tMacchiato: send a UDP packet (dest port=8080) to the interface %s\n", ifacename);
#endif

    while (running) { pause(); }

    mogu__detach(skel);
    mogu__destroy(skel);
    aloe__detach(askel);
    aloe__destroy(askel);
#ifdef HAS_XDP
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    macchiato__destroy(xskel);
#endif
    printf("Done!\n");
    return 0;
}
