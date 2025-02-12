# eBPF Arena Tutorail

This repository shares some examples of using Arena MAP (`BPF_MAP_TYPE_ARENA`)
Read more [here](https://fshahinfar1.github.io/blog/04_ebpf_arena/build/blog.html)

> Tested on kernel 6.9.3 and compiled with clang-19

## How to use

First load the `kmod` (defines a kfunc). Then run the loader.

**Loading kmod:**

1. Use make to compile `kmod/`
2. Use `make load` to load the module

**Running the loader:**

1. Use make to compile the eBPF program and the loader
2. `sudo ./build/mogu_loader.o` to run the loader
3. eBPF logs are shown at `/sys/kernel/tracing/trace_pipe`
4. Send signals to the loader for invoking each eBPF program
    - Mogu: `pkill -SIGUSR1 mogu_loader`
    - Aloe: `pkill -SIGUSR2 mogu_loader`
