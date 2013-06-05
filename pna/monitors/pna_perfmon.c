/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Example PNA monitor.
 * This null is simple so it doesn't use the .init() or .release()
 * callbacks.  It does create a variable called "sample_freq" which should be
 * available under /sys/module/pna/parameters/sample_freq.
 * 
 * All the monitor does is print out some information for 1 out of every
 * sample_freq packets.
 */
/* functions: perf_hook, perf_clean */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include "pna.h"
#include "pna_module.h"

static int perf_init(void);
static void perf_release(void);
static int perf_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void perf_clean(void);

struct pna_rtmon perf = {
    .name = "Null monitor",
    .init = perf_init,       /**< allocate resource on load */
    .hook = perf_hook,       /**< called for every packet PNA sees */
    .clean = perf_clean,     /**< periodic maintenance callback */
    .release = perf_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
PNA_MONITOR(&perf);

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */

#define PROC_NAME "perf"
int path_len;
char path[MAX_STR];

ssize_t perf_pread(struct file *, char __user *, size_t, loff_t *);
int perf_mmap_open(struct inode *inode, struct file *filep);
int perf_mmap_release(struct inode *inode, struct file *filep);
int perf_mmap(struct file *filep, struct vm_area_struct *vma);

static const struct file_operations perf_fops = {
    .owner   = THIS_MODULE,
    .open    = perf_mmap_open,
    .release = perf_mmap_release,
    .read    = perf_pread,
    .mmap    = perf_mmap,
};


//Performance monitoring variables
struct count_info{
	unsigned long int total_count;
	unsigned long int non_ip_count;
	unsigned long int type_count[256];
};

struct count_info packet_counts;
struct count_info *read_ptr;
int perf_mmap_open(struct inode *inode, struct file *filep){
	read_ptr = (struct count_info *)vmalloc_user(sizeof(struct count_info));
	memcpy(read_ptr, &packet_counts, sizeof(struct count_info));
	return 0;
}

int perf_mmap_release(struct inode *inode, struct file *filep){
	vfree(read_ptr);
	return 0;
}

int perf_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, read_ptr, 0)) {
		printk("pna_perfmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

ssize_t perf_pread(struct file *filep, char __user *buf, size_t len, loff_t *ppos)
{
	int ret=0;
	if(len != sizeof(struct count_info)){
		return 0;
	}

	memcpy(buf, &packet_counts, len);
	return len;
}

/**
 * PNA null monitor hook
 */
static int perf_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	ip = (struct iphdr *)skb_network_header(skb);
	packet_counts.total_count++;
	if(!ip){
		packet_counts.non_ip_count++;
	}
	else{
		packet_counts.type_count[ip->protocol]++;
	}
	tcp = (struct tcphdr *)skb_transport_header(skb);
	if(tcp){
		if(tcp->syn){
			packet_counts.type_count[253]++;
		}
	}
	
    return 0;
}

static void perf_clean(void)
{
    pna_info("pna_perf: periodic callback\n");
}

/**
 * Construct the full path to a procfile entry.
 */
static int proc_path(char *buf, ssize_t len, struct proc_dir_entry *entry)
{
    int off = 0;

    if (entry->parent != NULL && entry != entry->parent) {
        off = proc_path(buf, len, entry->parent);
        buf += off;
        len -= off;
    }
    strncpy(buf, entry->name, len);
    strncpy(buf + entry->namelen, "/", 1);

    return off + entry->namelen + 1;
}

static int perf_init(void)
{
	struct proc_dir_entry *proc_node;
	int i;

	proc_node = create_proc_entry(PROC_NAME, 0644, proc_parent);
	if(!proc_node) {
		pna_err("Could not create proc entry %s\n", PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &perf_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct count_info);

	packet_counts.total_count = 0;
	packet_counts.non_ip_count = 0;
	for(i=0 ; i < 256 ; i++){
		packet_counts.type_count[i] = 0;
	}
	return 0;
}

static void perf_release(void)
{
	remove_proc_entry(PROC_NAME, proc_parent);
	return;
}
