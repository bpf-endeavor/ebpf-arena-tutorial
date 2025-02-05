/*
 * */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "pubtrafstat.skel.h"

static volatile int running = 0;
void handle_signal(int s) {
    running = 0;
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
    bpf_program__set_flags(skel->progs.prog, BPF_F_SLEEPABLE);
    
    if (mogu__load(skel)) {
        fprintf(stderr, "Failed to load eBPF program\n");
        return EXIT_FAILURE;
    }

    return 0;

    if (mogu__attach(skel)) {
        fprintf(stderr, "Failed to attach the program\n");
        return EXIT_FAILURE;
    }

    running = 1;
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    printf("Hit Ctrl+C to terminate ...\n");
    while (running) { pause(); }

    mogu__detach(skel);
    mogu__destroy(skel);
    printf("Done!\n");
    return 0; 
}
