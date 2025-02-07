/*
 * */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "include/shared_struct.h"
#include "mogu.skel.h"
#include "aloe.skel.h"

/* Some global vars */
static volatile int running = 0;
static int ebpf_prog_fd = -1;
static struct mogu *skel = NULL;
static struct aloe *askel = NULL;

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

    /* Set the sleepable flag for the program using the arena alloc page helper
     * */
    bpf_program__set_flags(skel->progs.mogu_main, BPF_F_SLEEPABLE);
    bpf_program__set_flags(askel->progs.aloe_main, BPF_F_SLEEPABLE);

    if (mogu__load(skel)) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return EXIT_FAILURE;
    }

    if (mogu__attach(skel)) {
        fprintf(stderr, "Failed to attach the program\n");
        return EXIT_FAILURE;
    }

    /* for testing: invoke the program right after loading it.
     * It should allocate some memory which we would pass to Aloe for use
     * */
    ebpf_prog_fd = bpf_program__fd(skel->progs.mogu_main);
    handle_invoke_signal(0);

    /* Configure Aloe */
    {
        /* Set the same Arena map for Aloe */
        int arena_fd = bpf_map__fd(skel->maps.arena);
        bpf_map__reuse_fd(askel->maps.arena, arena_fd);
        /* Pass the pointer to the Aloe */
        askel->bss->mem = skel->bss->mem;
    }

    if (aloe__load(askel)) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return EXIT_FAILURE;
    }

    if (aloe__attach(askel)) {
        fprintf(stderr, "Failed to attach the program\n");
        return EXIT_FAILURE;
    }

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

    while (running) { pause(); }

    mogu__detach(skel);
    mogu__destroy(skel);
    aloe__detach(askel);
    aloe__destroy(askel);
    printf("Done!\n");
    return 0;
}
