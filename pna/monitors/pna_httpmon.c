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

static int count;

static int http_init(void);
static void http_release(void);
static int http_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void http_clean(void);

//Precalculated HTTP HF checksums:
u32 http_hf_checksums[997] = { 0, 5400750, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194456, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 195480, 0, 164664590, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 180672, 0, 0, 0, 1450854, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1354162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9266, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1302, 0, 0, 88044, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1341284, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1444004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2370, 0, 0, 0, 0, 0, 0, 0, 0, 164661914, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1345380, 0, 0, 10400, 0, 0, 0, 0, 0, 0, 176906, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2901720, 0, 0, 23384, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 310576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2530, 5393310, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1348530, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2626, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5670, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2694, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 725554, 0, 0, 2732, 0, 0, 0, 0, 0, 0, 2695636, 0, 0, 0, 0, 0, 0, 0, 5401502, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 649248166, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5392558, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11774, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6418528, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2850, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20582970, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5107552, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20728566, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25213102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11944, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
u8 http_hf_convert[997] = { 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 2, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 21, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


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

//List for checking if the first 4 bytes match HTTP
u32	http_filter_list[20] = {
542393671,
1145128264,
1414745936,
542397776,
1162626372,
1128354388,
1230262351,
1313754947,
1129595216,
1347700808,
544499047,
1684104552,
1936945008,
544503152,
1701602660,
1667330676,
1769238639,
1852731235,
1668571504,
1886680168};

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */

#define PROC_NAME "http"
#define LOG_PROC_NAME "http_log"
#define DB_PROC_NAME "http_db"

//Defining preset values for http_match:
//MAX_HF = Maximum number of Header Fields
#define MAX_HF 100
#define ORDER_DEPTH 20
#define MAX_SUBSTRING 30 
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
int http_db_open(struct inode *inode, struct file *filep);
int http_db_release(struct inode *inode, struct file *filep);
int http_db_mmap(struct file *filep, struct vm_area_struct *vma);

//OSF Memory Allocation for logs/db
int realloc_logs(unsigned int new_ips, unsigned int new_logs);
int realloc_db(unsigned int new_size);
int alloc_logs(unsigned int new_ips, unsigned int new_logs);
int alloc_db(unsigned int new_size);
int free_logs(void);
int free_db(void);
int db_alloc_f;
int log_alloc_f;


//OSF Locking Mechanisms
int num_in_hook;
int hook_lock;
int hook_lock_ack;

int control_change_flag;
int log_change_flag;
int db_change_flag;

int setup_complete;

//OSF other
int switch_tables(void);

unsigned int first_ack_log;

static const struct file_operations http_control_fops = {
    .owner   = THIS_MODULE,
    .open    = http_control_open,
    .release = http_control_release,
    .read    = http_pread,
    .mmap    = http_control_mmap,
};

static const struct file_operations http_log_fops = {
	.owner	= THIS_MODULE,
	.open	= http_log_open,
	.release =http_log_release,
	.mmap 	= http_log_mmap,
};

static const struct file_operations http_db_fops = {
	.owner	= THIS_MODULE,
	.open	= http_db_open,
	.release= http_db_release,
	.mmap	= http_db_mmap,
};

//Performance monitoring variables
struct count_info{
	unsigned long int total_count;
	unsigned long int non_ip_count;
	unsigned long int type_count[256];
};

//OSF Control Format
struct http_control{
	unsigned int num_ips;
	unsigned int num_logs;
	unsigned int num_db_entries;
	unsigned int cur_db_entries;
	unsigned int missed_logs;
};
struct http_control control;

//OSF Print format
struct http_print{
	u32	db_entry;
	u32	src_ip;
	u32	dst_ip;
};

//OSF Hashmap format
struct http_info{
	u32	src_ip;
	u32	table_index;
	u32	current_log;
};

//OSF Signature format
struct http_sig{
	struct http_print print;
	u8	version;
	u64	inset;
	u64	outset;
	char	hf_values[ORDER_DEPTH][MAX_SUBSTRING];
	u8	rule_table[ORDER_DEPTH][MAX_HF];
	u8	transition_table[ORDER_DEPTH][MAX_HF];
};
	
//OSF Primary Data Pointers:
struct pna_hashmap *hashmap_a;
struct pna_hashmap *hashmap_b;
struct pna_hashmap *hashmap;
struct pna_hashmap *old_hashmap;
struct http_sig *db;
void *all_zeroes;

//User space read/write pointers:
struct http_control	*control_ptr;
struct http_control	new_control;
struct http_print	*log_ptr;
struct http_info	*log_info_ptr;
struct http_sig		*db_ptr;

int http_control_open(struct inode *inode, struct file *filep){
	control_ptr = (struct http_control *)vmalloc_user(sizeof(struct http_control));
	/*while(hook_lock == 1){
		//This should never happen
	}
	hook_lock = 1;
	while(num_in_hook > 0){
		//set_current_state(TASK_INTERRUPTIBLE);
		//schedule_timeout(100);
	}

	//while(hook_lock_ack == 0){
		//Do nothing until hook is waiting
	//}
	*/
	memcpy(control_ptr, &control, sizeof(struct http_control));
	return 0;
}

int http_control_release(struct inode *inode, struct file *filep){
	//Old Control release
	/*
	int fail_ips;
	int fail_logs;
	int fail_db;
	if(control_ptr->num_ips != control.num_ips || control_ptr->num_logs != control.num_logs){
		realloc_logs(control_ptr->num_ips, control_ptr->num_logs);
	}
	if(control_ptr->num_db_entries != control.num_db_entries){
		realloc_db(control_ptr->num_db_entries);
	}
	if(control.num_ips == 1){
		fail_ips = 1;
	}
	else{
		fail_ips = 0;
	}
	if(control.num_logs == 1){
		fail_logs = 1;
	}
	else{
		fail_logs = 0;
	}
	if(control.num_db_entries == 1){
		fail_db = 1;
	}
	else{
		fail_db = 0;
	}
	memcpy(&control, control_ptr, sizeof(struct http_control));
	if(fail_ips == 1 && fail_logs == 1){
		control.num_ips = 1;
		control.num_logs = 1;
	}
	if(fail_db == 1){
		control.num_db_entries = 1;
	}
	hook_lock = 0;
	vfree(control_ptr);
	*/
	//New Control Release
	if(control_ptr->num_ips == 0){
		vfree(control_ptr);
		return 0;
	}
	if(hashmap != NULL){
		vfree(control_ptr);
		return 0;
	}
	alloc_logs(control_ptr->num_ips, control_ptr->num_logs);
	alloc_db(control_ptr->num_db_entries);
	memcpy(&control, control_ptr, sizeof(struct http_control));
	vfree(control_ptr);
	return 0;
}

int http_control_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, control_ptr, 0)) {
		printk("pna_httpmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

int http_log_open(struct inode *inode, struct file *filep){
	if(control.num_ips == 0 || control.num_logs == 0){
		return -1;
	}
	log_ptr = (struct http_print *)vmalloc_user(hashmap->n_pairs*(hashmap->key_size + hashmap->value_size));
	//log_info_ptr = (struct http_info *)vmalloc_user(sizeof(struct http_info)*control.num_ips);
	while(hook_lock == 1){
		//This should never happen
	}
	hook_lock = 1;
	while(num_in_hook > 0){
	}
	//while(hook_lock_ack == 0){
		//Do nothing until hook is waiting
	//}
	switch_tables();
	hook_lock = 0;
	memcpy(log_ptr, old_hashmap->pairs, old_hashmap->n_pairs*(old_hashmap->key_size + old_hashmap->value_size));
	return 0;
}

int http_log_release(struct inode *inode, struct file *filep){
	hashmap_reset(old_hashmap);
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

int http_db_open(struct inode *inode, struct file *filep){
	if(control.num_db_entries == 0){
		return -1;
	}
	db_ptr = (struct http_sig *)vmalloc_user(sizeof(struct http_sig)*control.num_db_entries);
	//Old open
	/*
	while(hook_lock == 1){
		//This should never happen
	}
	hook_lock = 1;
	while(num_in_hook > 0){
	}
	//while(hook_lock_ack == 0){
		//Do nothing until hook is waiting
	//}
	*/
	return 0;
}

void print_print(struct http_print *print){
	return;
}

void print_sig(struct http_sig *sig){
	return;
}

void debug_http_db(){
	unsigned int i;
	for(i=0 ; i<control.cur_db_entries ; i++){
		print_sig(&db[i]);
	}
	return;
}

int http_db_release(struct inode *inode, struct file *filep){
	/*if(db_ptr[0].print.dst_ip < control.num_db_entries * sizeof(struct http_sig)){
		memcpy(&db, db_ptr, db_ptr[0].print.dst_ip);
	}
	else{
		memcpy(&db, db_ptr, control.num_db_entries * sizeof(struct http_sig));
	}*/
	memcpy(db, db_ptr, control.num_db_entries * sizeof(struct http_sig));
	//debug_http_db();
	//hook_lock = 0;
	vfree(db_ptr);
	control.cur_db_entries = db[0].print.src_ip;
	setup_complete = 1;
	return 0;
}

int http_db_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, db_ptr, 0)) {
		printk("pna_httpmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}
	return 0;
}


ssize_t http_pread(struct file *filep, char __user *buf, size_t len, loff_t *ppos)
{
	return 0;
}

//Memory allocation functions
int realloc_logs(unsigned int new_ips, unsigned int new_logs){
	free_logs();
	alloc_logs(new_ips, new_logs);
	return 0;
}

int realloc_db(unsigned int new_size){
	free_db();
	alloc_db(new_size);
	return 0;
}

int free_logs(){
	hashmap_destroy(hashmap_a);
	hashmap_destroy(hashmap_b);
	vfree(all_zeroes);
	remove_proc_entry(LOG_PROC_NAME, proc_parent);
	return 0;
}

int free_db(){
	vfree(db);
	remove_proc_entry(DB_PROC_NAME, proc_parent);
	return 0;
}

int alloc_logs(unsigned int new_ips, unsigned int new_logs){
	struct proc_dir_entry *proc_node;
	log_alloc_f = 1;
	all_zeroes = vmalloc(sizeof(struct http_info) + sizeof(struct http_print) * new_logs);
	memset(all_zeroes, 0, sizeof(struct http_info) + sizeof(struct http_print) * new_logs);
	hashmap_a = hashmap_create(new_ips, 4, sizeof(struct http_info) + sizeof(struct http_print)*new_logs);
	if(hashmap_a == NULL){
		vfree(all_zeroes);
		if(new_ips == 1 && new_logs == 1){
			return -1;
		}
		control.num_ips = 1;
		control.num_logs = 1;
		return alloc_logs(1, 1);
	}
	hashmap_b = hashmap_create(new_ips, 4, sizeof(struct http_info) + sizeof(struct http_print)*new_logs);
	hashmap = hashmap_a;
	if(hashmap_b == NULL){
		hashmap_destroy(hashmap_a);
		vfree(all_zeroes);
		if(new_ips == 1 && new_logs == 1){
			return -1;
		}
		control.num_ips = 1;
		control.num_logs = 1;
		return alloc_logs(1, 1);
	}
	old_hashmap = hashmap_b;
	proc_node = create_proc_entry(LOG_PROC_NAME, 0644, proc_parent);
	if(!proc_node) {
		pna_err("Could not create proc entry %s\n", LOG_PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &http_log_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = new_ips * (4 + sizeof(struct http_info) + sizeof(struct http_print)*new_logs);
	return 0;
}

int alloc_db(unsigned int new_size){
	struct proc_dir_entry *proc_node;
	db_alloc_f = 1;
	db = (struct http_sig *)vmalloc(sizeof(struct http_sig)*new_size);
	
	if(db == NULL){
		control.num_db_entries = 1;
		return alloc_db(1);
	}

	proc_node = create_proc_entry(DB_PROC_NAME, 0644, proc_parent);
	if(!proc_node){
		pna_err("Could not create proc entry %s\n", DB_PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &http_db_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct http_sig)*new_size;

	return 0;
}

int switch_tables(){
	if(hashmap == hashmap_a){
		hashmap = hashmap_b;
		old_hashmap = hashmap_a;
	}
	else{
		hashmap = hashmap_a;
		old_hashmap = hashmap_b;
	}
	return 0;
}
/**
 * PNA null monitor hook
 */

struct http_print *get_next_print(u32 key){
	struct http_print *ret;
	struct http_info *info;
	void *hash_ptr;
	hash_ptr = hashmap_get(hashmap, &key);
	if(hash_ptr == NULL){
		if((hashmap_put(hashmap, &key, all_zeroes)) == 0){
			return NULL;
		}
		hash_ptr = hashmap_get(hashmap, &key);
		info = (struct http_info *)hash_ptr;
		info->src_ip = key;
		info->current_log = 0;
	}
	info = (struct http_info *)hash_ptr;
	if(info->current_log == control.num_logs){
		//printk("88X %u %u\n", info->current_log, control.num_logs);
		return NULL;
	}
	if(info->src_ip != key){
		printk("Something went wrong in get_next_print\n");
		return NULL;
	}
	ret = (struct http_print *)(hash_ptr + sizeof(struct http_info) + sizeof(struct http_print) * info->current_log);
	info->current_log++;
	return ret;
}

int http_filter(char *data){
	u32 *value;
	int i;
	value = (u32 *)data;
	for(i=0 ; i < 20 ; i++){
		if(*value == http_filter_list[i]){
			return 0;
		}
	}
	return 1;
}

inline u32 calculate_hf(char *data, u32 start, u32 end){
	u32 total=0;
	u32 total_mod;
	u32 i;
	for(i=start; i < end; i++){
		if(data[i] == ' '){
			continue;
		}
		if(data[i] == ':'){
			break;
		}
		total = (total + (u8)data[i]) * 2;
	}
	if(total == 0){
		return 0;
	}
	total_mod = total % 997;
	if(total == http_hf_checksums[total_mod]){
		return http_hf_convert[total_mod];
	}
	return 0;
}

int substring_match(char *data, u32 start, u32 end, char *match){
	u32 i = 0;
	u32 m = start;
	u32 p = start;
	u32 emergency = 0;
	char first = match[0];
	while(m+i < end){
		emergency++;
		if(emergency >= 100){
			return 1;
		}
		if(match[i] == '\0'){
			return 0;
		}
		if((p == m) && (data[m+i] == first)){
			p = m+i;
		}
		if(match[i] == data[m+i]){
			i++;
		}
		else if(m != p){
			m = p;
			i = 0;

		}
		else{
			i = 0;
			m++;
			p = m;
		}
		
	}
	return 1;
}

int http_match(char *data){
	u32	hf_pos[MAX_HF];
	u32	hf_value_pos[MAX_HF];
	u32	hf_end_pos[MAX_HF];
	u32	hf_val[MAX_HF];
	int pos = 0;
	int cur_hf = 0;
	int max_hf;
	int i, j, k, l;
	u8 next_list;
	u64	inset=0;
	int correct_flag;
	//We already know that the first line is correct, so we have to skip it:
	while(data[pos] != '\r'){
		pos++;
	}
	pos++;
	if(data[pos] != '\n'){
		printk("HTTP Parse Error\n");
		return -1;
	}
	pos++;
	if(data[pos] == '\r'){
		pos++;
		if(data[pos] == '\n'){
			//Parsing finished
			return 0;
		}
	}
	//We are now at the first HF.  
	while(cur_hf < MAX_HF){
		hf_pos[cur_hf] = pos;
		cur_hf++;
		if(data[pos] == ':'){
		hf_value_pos[cur_hf] = pos;
		}
		while(data[pos] != '\r'){
			pos++;
		}
		hf_end_pos[cur_hf] = pos;
		pos++;
		if(data[pos] != '\n'){
			printk("HTTP Parse Error\n");
			return -1;
		}
		pos++;
		if(data[pos] == '\r'){
			pos++;
			if(data[pos] == '\n'){
				//Parsing finished
				break;
			}
			else{
				printk("HTTP Parse Error\n");
				return -1;
			}
		}
	}
	max_hf = cur_hf;
	//Everything now broken up correctly, starting fingerprinting here:
	//First, we have to figure out which header fields we need:
	//Our checksums have been precalculated, and are included at compile time
	//as the variables http_hf_checksums and http_hf_convert
	correct_flag = 0;
	for(i=0 ; i < max_hf ; i++){
		hf_val[i] = calculate_hf(data, hf_pos, hf_value_pos);
		if(hf_val[i] != 0){
			inset = inset | (1 << hf_val[i]);
		}
	}
	//We now have everything we need to perform the match, we just have
	//to iterate down the db and narrow it down 3 ways:
	//Set operations to detect if the right fields are there,
	//An automata to make sure the fields are in the right order,
	//And check the HF value substrings to see if they match
	for(i=0 ; i < control.cur_db_entries ; i++){
		correct_flag = 1;
		if((inset & db[i].inset) != db[i].inset){
			continue;
		}
		if((inset & db[i].outset) != 0){
			continue;
		}
		//Okay, so we know that the right fields are here, now let's check the ordering:
		next_list = 0;
		for(j=0 ; j < max_hf ; j++){
			if(hf_val[j] == 0){
				continue;
			}
			if(db[i].rule_table[next_list][hf_val[j]] == 0){
				continue;
			}
			if(db[i].rule_table[next_list][hf_val[j]] == 1){
				break;
			}
			if(db[i].rule_table[next_list][hf_val[j]] == 2){
				next_list = db[i].transition_table[next_list][hf_val[j]];
				continue;
			}
			if(db[i].rule_table[next_list][hf_val[j]] == 3){
				next_list = db[i].transition_table[next_list][hf_val[j]];
				if(substring_match(data, hf_value_pos, hf_end_pos, db[i].hf_values[next_list]) == 0){
					continue;
				}
				else{
					break;
				}
			}
		}
	}

	return 0;
}

static int http_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct http_print *new_print;
	unsigned int offset=0;
	u8 *data_ptr;
	if(setup_complete == 0){
		return 0;
	}
	ip = (struct iphdr *)skb_network_header(skb);
	if(!ip){
		return 0;
	}
	if(ip->protocol != 6){
		return 0;
	}
	tcp =(struct tcphdr *)skb_transport_header(skb);
	if(!tcp){
		return 0;
	}
	//20480 checks if tcp->dest = 80, since byte order is backwards
	if(tcp->dest != 20480){
		return 0;
	}
	offset = (ip->ihl*4) + (tcp->doff * 4);
	data_ptr = ((u8 *)skb->data)+offset;
	if(http_filter(data_ptr) != 0){
		return 0;
	}
	num_in_hook++;
	new_print = get_next_print(ip->saddr);
	if(new_print == NULL){
		control.missed_logs++;
		num_in_hook--;
		return -1;
	}
	//HTTP test
	http_match((char *)data_ptr);
	num_in_hook--;
	return 0;
}

static void http_clean(void)
{
	return;
	while(hook_lock == 1){
		//Do nothing
	}
	hook_lock = 1;
	while(num_in_hook > 0){
		//Do nothing
	}
	hashmap_reset(hashmap_a);
	hashmap_reset(hashmap_b);
	hook_lock = 0;
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
	int i;
	count= 0;
	db_alloc_f = 0;
	log_alloc_f = 0;
	setup_complete = 0;
	first_ack_log = 0;
	hook_lock = 0;
	control_change_flag = 0;
	log_change_flag = 0;
	db_change_flag = 0;
	//hook_lock_ack = 0;
	proc_node = create_proc_entry(PROC_NAME, 0644, proc_parent);
	if(!proc_node) {
		pna_err("Could not create proc entry %s\n", PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &http_control_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct http_control);

	hashmap = NULL;
	hashmap_a = NULL;
	hashmap_b = NULL;
	old_hashmap = NULL;
	db = NULL;

	control.num_ips = 0;
	control.num_logs = 0;
	control.num_db_entries = 0;
	control.cur_db_entries = 0;
	control.missed_logs = 0;
	return 0;
}

static void http_release(void)
{
	printk("Count %d\n", count);
	while(num_in_hook > 0){
		//Do nothing
	}
	if(log_alloc_f != 0){
		free_logs();
	}
	if(db_alloc_f != 0){
		free_db();
	}
	remove_proc_entry(PROC_NAME, proc_parent);
	return;
}
