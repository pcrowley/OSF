/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a http of the License at
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
/* functions: http_hook, http_clean */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include <linux/sched.h>

#include "pna.h"
#include "pna_hashmap.h"
#include "pna_module.h"

#include "fnv.h"

static int http_init(void);
static void http_release(void);
static int http_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void http_clean(void);

u32 getlist[8] = { 544499047, 542401895, 544490855, 542393703, 544499015, 542401863, 544490823, 542393671};

struct pna_rtmon http = {
    .name = "Null monitor",
    .init = http_init,       /**< allocate resource on load */
    .hook = http_hook,       /**< called for every packet PNA sees */
    .clean = http_clean,     /**< periodic maintenance callback */
    .release = http_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Jason Barnes <jason.barnes@wustl.edu>");
PNA_MONITOR(&http);

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */

#define PROC_NAME "http"
#define LOG_PROC_NAME "http_log"
#define DB_PROC_NAME "http_db"

#define COPY_MAX_BYTES 100
#define COPY_MAX_PACKETS 100000

int path_len;
char path[MAX_STR];

//File Operation prototypes
ssize_t http_pread(struct file *, char __user *, size_t, loff_t *);
int http_control_open(struct inode *inode, struct file *filep);
int http_control_release(struct inode *inode, struct file *filep);
int http_control_mmap(struct file *filep, struct vm_area_struct *vma);
int http_log_open(struct inode *inode, struct file *filep);
int http_log_release(struct inode *inode, struct file *filep);
int http_log_mmap(struct file *filep, struct vm_area_struct *vma);

//OSF Locking Mechanisms
int num_in_hook;
int hook_lock;
int hook_lock_ack;



//OSF other
int switch_tables(void);

static const struct file_operations http_log_fops = {
	.owner	= THIS_MODULE,
	.open	= http_log_open,
	.release =http_log_release,
	.mmap 	= http_log_mmap,
};

struct http_table {
	unsigned int start;
	unsigned int end;
	unsigned int skipped;
	char data[COPY_MAX_PACKETS][COPY_MAX_BYTES];
};

unsigned int cur_start;//The First Packet to Copy
unsigned int cur_end;//The First Packet to Copy in the next set, if == cur_start, then no new packets.
struct http_table table_a;
struct http_table *table;
void *all_zeroes;
struct http_table *log_ptr;

void *fast_memcpy(void *__restrict b, const void *__restrict a, size_t n){
	char *s1 = b;
	const char *s2 = a;
	for(; 0<n; --n)*s1++ = *s2++;
	return b;
}

int http_log_open(struct inode *inode, struct file *filep){
	log_ptr = (struct http_table *)vmalloc_user(sizeof(struct http_table));
	table->start = cur_start;
	table->end = cur_end;
	cur_start = table->end;
	memcpy(log_ptr, table, sizeof(struct http_table));
	return 0;
}

int http_log_release(struct inode *inode, struct file *filep){
	vfree(log_ptr);
	return 0;
}

int http_log_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, log_ptr, 0)) {
		printk("pna_httpmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

int switch_tables(){
	return 0;
}
/**
 * PNA null monitor hook
 */
static int http_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	int i;
	u8 *ptr;
	if((cur_end < cur_start) && (cur_start - cur_end == 1)){
		table->skipped++;
		return 0;
	}
	if((cur_start == 0) && (cur_end == COPY_MAX_PACKETS - 1)){
		table->skipped++;
		return 0;
	}
	ip = (struct iphdr *)skb_network_header(skb);
	if(!ip){
		return 0;
	}
	tcp = (struct tcphdr *)skb_transport_header(skb);
	if(!tcp){
		return 0;
	}
	if(tcp->dest != 20480){
		return 0;
	}
	if((ip->tot_len - (ip->ihl*4) - (tcp->doff*4))== 0){
		return 0;
	}
	//We now have an HTTP packet with nonzero payload, let's check for
	//it starting with "GET "
	ptr = ((u8 *)ip) + ip->ihl*4 + tcp->doff*4;
	for(i=0 ; i < 8 ; i++){
		if((*(u32 *)ptr) == getlist[i]){
			break;
		}
	}
	if(i >= 8){
		return 0;
	}
	//At this point, we have a GET request, time to http
	if((ip->tot_len - ip->ihl*4 - tcp->doff*4) < COPY_MAX_BYTES ){
		fast_memcpy(table->data[cur_end], ptr, (ip->tot_len - ip->ihl*4 - tcp->doff*4));
	}
	else{
		fast_memcpy(table->data[cur_end], ptr, COPY_MAX_BYTES);
	}
	cur_end = cur_end + 1;
	if(cur_end >= COPY_MAX_PACKETS){
		cur_end = 0;
	}
	return 0;
}

static void http_clean(void)
{
	return;
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

static int http_init(void)
{
	struct proc_dir_entry *proc_node;
	hook_lock = 0;
	proc_node = create_proc_entry(PROC_NAME, 0644, proc_parent);
	if(!proc_node) {
		pna_err("Could not create proc entry %s\n", PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &http_log_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct http_table);

	table = &table_a;
	table->start = 0;
	table->end = 0;
	cur_start = 0;
	cur_end = 0;
	return 0;
}

static void http_release(void)
{
	remove_proc_entry(PROC_NAME, proc_parent);
	return;
}
