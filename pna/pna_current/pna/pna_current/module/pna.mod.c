#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf6628fc9, "module_layout" },
	{ 0x199ed0cd, "net_disable_timestamp" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xc996d097, "del_timer" },
	{ 0xe78ea50a, "remap_vmalloc_range" },
	{ 0x84a24445, "skb_clone" },
	{ 0xd74ee220, "dev_get_by_name" },
	{ 0xcc18bdb6, "remove_proc_entry" },
	{ 0xb78c61e8, "param_ops_bool" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0x59f300eb, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0x7d11c268, "jiffies" },
	{ 0x7242e96d, "strnchr" },
	{ 0x72aa82c6, "param_ops_charp" },
	{ 0xac59d04a, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0xc974af08, "proc_mkdir" },
	{ 0x1b9ecedf, "__mutex_init" },
	{ 0x27e1a049, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x3032758b, "__tracepoint_module_get" },
	{ 0x2fa5a500, "memcmp" },
	{ 0x4ddefefe, "netlink_kernel_release" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x868e2bb, "mutex_lock" },
	{ 0x36dab2ac, "dev_remove_pack" },
	{ 0x8834396c, "mod_timer" },
	{ 0x5ce2e8d7, "netlink_unicast" },
	{ 0xbe2c0274, "add_timer" },
	{ 0xffda7cfd, "init_net" },
	{ 0xfd6293c2, "boot_tvec_bases" },
	{ 0x46c8ecbb, "module_put" },
	{ 0x77782dca, "__alloc_skb" },
	{ 0x5635a60a, "vmalloc_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x54e6fcdd, "net_enable_timestamp" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x39e2795, "kfree_skb" },
	{ 0x4640a095, "create_proc_entry" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x236c8c64, "memcpy" },
	{ 0x7628f3c7, "this_cpu_off" },
	{ 0x50720c5f, "snprintf" },
	{ 0x88fed9c4, "dev_add_pack" },
	{ 0x5caf4af1, "skb_put" },
	{ 0xc3fe87c8, "param_ops_uint" },
	{ 0xddf78a31, "skb_copy_bits" },
	{ 0x6251f549, "dev_get_stats" },
	{ 0xdf4c8767, "ns_to_timeval" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "929B6F6159CD016B9D600E3");
