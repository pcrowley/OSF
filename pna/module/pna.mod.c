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
	{ 0x41572473, "module_layout" },
	{ 0x199ed0cd, "net_disable_timestamp" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x1574c0b9, "del_timer" },
	{ 0x71f33929, "remap_vmalloc_range" },
	{ 0x35688770, "skb_clone" },
	{ 0x4df6a4f1, "dev_get_by_name" },
	{ 0x56ce0b62, "remove_proc_entry" },
	{ 0xb78c61e8, "param_ops_bool" },
	{ 0x9e1bdc28, "init_timer_key" },
	{ 0xb88d9172, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0x7d11c268, "jiffies" },
	{ 0x7242e96d, "strnchr" },
	{ 0x72aa82c6, "param_ops_charp" },
	{ 0x5959f3dd, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0x59db01e4, "proc_mkdir" },
	{ 0xb4f2d493, "__mutex_init" },
	{ 0x27e1a049, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x3032758b, "__tracepoint_module_get" },
	{ 0x2fa5a500, "memcmp" },
	{ 0x9ff7d11a, "netlink_kernel_release" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0xf8ee7211, "mutex_lock" },
	{ 0xde3bac57, "dev_remove_pack" },
	{ 0xce095088, "mod_timer" },
	{ 0x6a655f7c, "netlink_unicast" },
	{ 0x71205378, "add_timer" },
	{ 0x4bfa246c, "init_net" },
	{ 0x7ce94405, "boot_tvec_bases" },
	{ 0x231926a3, "module_put" },
	{ 0x158c44d0, "__alloc_skb" },
	{ 0x5635a60a, "vmalloc_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x54e6fcdd, "net_enable_timestamp" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x8931aa48, "kfree_skb" },
	{ 0xa301657f, "create_proc_entry" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x236c8c64, "memcpy" },
	{ 0x7628f3c7, "this_cpu_off" },
	{ 0x9edbecae, "snprintf" },
	{ 0xe98bc289, "dev_add_pack" },
	{ 0x554619dd, "skb_put" },
	{ 0xc3fe87c8, "param_ops_uint" },
	{ 0x2f8abb5c, "skb_copy_bits" },
	{ 0x11b7c521, "dev_get_stats" },
	{ 0xdf4c8767, "ns_to_timeval" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "929B6F6159CD016B9D600E3");
