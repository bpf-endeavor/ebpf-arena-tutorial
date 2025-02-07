#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h> /* memcpy */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
MODULE_LICENSE("GPL");

/* Define a kfunc function */
__bpf_kfunc_start_defs();
/*
 * The function does nothing itself. But calling it causes the verifier to
 * register the program as using the arena map (if you pass the reference of an
 * arena map to it).
 *
 * The point of this function is to have something to call from an eBPF program
 * with the Arena map struct as the pointer without requiring to sleep.
 * */
__bpf_kfunc long my_kfunc_reg_arena(void *p__map)
{
    return 0;
}
__bpf_kfunc_end_defs();

/*
 * These will probably be the new API
 * */
BTF_KFUNCS_START(bpf_my_kfunc_set)
BTF_ID_FLAGS(func, my_kfunc_reg_arena, 0)
BTF_KFUNCS_END(bpf_my_kfunc_set)

/*
 * These are the old API
 * */
/* BTF_SET8_START(bpf_my_kfunc_set) */
/* BTF_ID_FLAGS(func, my_kfunc_reg_arena, 0) */
/* BTF_SET8_END(bpf_my_kfunc_set) */

static const struct btf_kfunc_id_set my_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_my_kfunc_set,
};

static int __init myinit(void)
{
    int ret;
    /* Register the BTF */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &my_kfunc_set);
    if (ret != 0)
        return ret;
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &my_kfunc_set);
    if (ret != 0)
        return ret;
    pr_info("Load reg_arena kfunc\n");
    return 0;
}

static void __exit myexit(void)
{
    pr_info("Unloading reg_arena kfunc\n");
}

module_init(myinit)
module_exit(myexit)
