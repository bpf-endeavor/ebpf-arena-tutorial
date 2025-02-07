## NOTES

* Arena requires kernel version 6.9 and higher
* Program must be sleepable: The `BPF_F_SLEEPABLE` must be set when loading
    - program must be sleepable to call sleepable kfunc `bpf_arena_alloc_pages`
    - At the moment of writing this: only `fentry`/`fexit`/`fmod_ret`, `lsm`,
      `iter`, `uprobe`, and `struct_ops` programs can be sleepable (according
      to the libbpf error message). Look [here for more info](https://github.com/libbpf/libbpf/blob/master/docs/program_types.rst).
* I managed to share an arena map between two programs
    - In order for it to work, I shared the Arena using libbpf API, and passed
      the memory address of the page from one program to the other (loader
      program did it)
    - Both the programs had to call the `bpf_arena_alloc_pages` although I only
      need one of the to work. If I avoid the extra call in the second program
      the verifier would complain with using memory loads with cast
      instructions but having no Arena map. It seems the program is mark as
      having the map only when it is using it with a helper/kfunc function.

## Questions

1. What is the API?
    -  How does memory address space work (e.g., __arena macro, cast_user,
    cast_kern)
    - How to initilze the data-structure in the begining?
2. Can I make it work on version 6.8 ? (Ubuntu 22.04 HWE is using this and
   I do not want to install a custom kernel)
3. How is the performance compared to the BPF_MAP_TYPE_HASH?
4. What is the minimum version of LLVM that I can use?

## Other Questions

1. Implementation of `arena_htab` does not define the memory region NUMA node?
2. Can I apply the CacheDirectory type of optimizations to arena?
3. How can I do prefetching with this implmentation?
4. Is it possible to allocate from HUGE page pool for the htab?

## Side Note

`Mogu` and `Aloe` (names used for eBPF programs) are the name of two types of
sugary drink with some chewy bits from department's vending machiens.
