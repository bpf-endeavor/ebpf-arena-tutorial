/*
 * */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "mogu.skel.h"

static volatile int running = 0;
static int ebpf_prog_fd = -1;

static int run_ebpf_prog(int fd);

static void handle_signal(int s) {
    running = 0;
}

static void handle_invoke_signal(int s) {
    if (ebpf_prog_fd == -1)
        return;
    run_ebpf_prog(ebpf_prog_fd);
}

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

int main(int argc, char *argv[])
{
    struct mogu *skel;

    skel = mogu__open();
    if (!skel) {
        fprintf(stderr, "Failed to open the skeleton\n");
        return EXIT_FAILURE;
    }

    /* Set the sleepable flag for the program using the arena alloc page helper
     * */
    bpf_program__set_flags(skel->progs.mogu_main, BPF_F_SLEEPABLE);

    if (mogu__load(skel)) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return EXIT_FAILURE;
    }

    if (mogu__attach(skel)) {
        fprintf(stderr, "Failed to attach the program\n");
        return EXIT_FAILURE;
    }

    ebpf_prog_fd = bpf_program__fd(skel->progs.mogu_main);

    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_invoke_signal);
    signal(SIGUSR2, handle_invoke_signal);
    printf("Hit Ctrl+C to terminate ...\n");
    printf("Invoke eBPF program:\n\tpkill -SIGUSR1 %s\n", argv[0]);

    /* for testing */
    handle_invoke_signal(0);

    while (running) { pause(); }

    mogu__detach(skel);
    mogu__destroy(skel);
    printf("Done!\n");
    return 0;
}
