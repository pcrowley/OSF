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
/* functions: osf_hook, osf_clean */
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

static int osf_init(void);
static void osf_release(void);
static int osf_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void osf_clean(void);

struct pna_rtmon osf = {
    .name = "Null monitor",
    .init = osf_init,       /**< allocate resource on load */
    .hook = osf_hook,       /**< called for every packet PNA sees */
    .clean = osf_clean,     /**< periodic maintenance callback */
    .release = osf_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Jason Barnes <jason.barnes@wustl.edu>");
PNA_MONITOR(&osf);

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */

#define PROC_NAME "osf"
#define LOG_PROC_NAME "osf_log"
#define DB_PROC_NAME "osf_db"

int path_len;
char path[MAX_STR];

//File Operation prototypes
ssize_t osf_pread(struct file *, char __user *, size_t, loff_t *);
int osf_control_open(struct inode *inode, struct file *filep);
int osf_control_release(struct inode *inode, struct file *filep);
int osf_control_mmap(struct file *filep, struct vm_area_struct *vma);
int osf_log_open(struct inode *inode, struct file *filep);
int osf_log_release(struct inode *inode, struct file *filep);
int osf_log_mmap(struct file *filep, struct vm_area_struct *vma);
int osf_db_open(struct inode *inode, struct file *filep);
int osf_db_release(struct inode *inode, struct file *filep);
int osf_db_mmap(struct file *filep, struct vm_area_struct *vma);

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

static const struct file_operations osf_control_fops = {
    .owner   = THIS_MODULE,
    .open    = osf_control_open,
    .release = osf_control_release,
    .read    = osf_pread,
    .mmap    = osf_control_mmap,
};

static const struct file_operations osf_log_fops = {
	.owner	= THIS_MODULE,
	.open	= osf_log_open,
	.release =osf_log_release,
	.mmap 	= osf_log_mmap,
};

static const struct file_operations osf_db_fops = {
	.owner	= THIS_MODULE,
	.open	= osf_db_open,
	.release= osf_db_release,
	.mmap	= osf_db_mmap,
};

//Performance monitoring variables
struct count_info{
	unsigned long int total_count;
	unsigned long int non_ip_count;
	unsigned long int type_count[256];
};

//OSF Control Format
struct osf_control{
	unsigned int num_ips;
	unsigned int num_logs;
	unsigned int num_db_entries;
	unsigned int cur_db_entries;
	unsigned int missed_logs;
};
struct osf_control control;

//OSF Print format
struct osf_print{
	u32	db_entry;
	u32	src_ip;
	u32	dst_ip;
	u32	opt_hash;
	u32	quirks;
	u8	opt_eol_pad;
	u8	ip_opt_len;
	u8	ttl;
	u16	mss;
	u16	win;
	u8	win_type;
	u8	win_scale;
	u8	pay_class;
};

//OSF Hashmap format
struct osf_info{
	u32	src_ip;
	u32	table_index;
	u32	current_log;
};

//OSF Signature format
struct osf_sig{
	struct osf_print print;
	u8 wildcards;
	u8 ack;//0 for syn, 1 for ack
	u32	score;
	char	os_type;
	char	os_class[5];
	char	os_name[20];
	char	os_flavor[20];
};
	
//OSF Primary Data Pointers:
struct pna_hashmap *hashmap_a;
struct pna_hashmap *hashmap_b;
struct pna_hashmap *hashmap;
struct pna_hashmap *old_hashmap;
struct osf_sig *db;
void *all_zeroes;

//User space read/write pointers:
struct osf_control	*control_ptr;
struct osf_control	new_control;
struct osf_print	*log_ptr;
struct osf_info		*log_info_ptr;
struct osf_sig		*db_ptr;

int osf_control_open(struct inode *inode, struct file *filep){
	control_ptr = (struct osf_control *)vmalloc_user(sizeof(struct osf_control));
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
	memcpy(control_ptr, &control, sizeof(struct osf_control));
	return 0;
}

int osf_control_release(struct inode *inode, struct file *filep){
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
	memcpy(&control, control_ptr, sizeof(struct osf_control));
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
	memcpy(&control, control_ptr, sizeof(struct osf_control));
	vfree(control_ptr);
	return 0;
}

int osf_control_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, control_ptr, 0)) {
		printk("pna_osfmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

int osf_log_open(struct inode *inode, struct file *filep){
	if(control.num_ips == 0 || control.num_logs == 0){
		return -1;
	}
	log_ptr = (struct osf_print *)vmalloc_user(hashmap->n_pairs*(hashmap->key_size + hashmap->value_size));
	//log_info_ptr = (struct osf_info *)vmalloc_user(sizeof(struct osf_info)*control.num_ips);
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

int osf_log_release(struct inode *inode, struct file *filep){
	hashmap_reset(old_hashmap);
	vfree(log_ptr);
	return 0;
}

int osf_log_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, log_ptr, 0)) {
		printk("pna_osfmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

int osf_db_open(struct inode *inode, struct file *filep){
	if(control.num_db_entries == 0){
		return -1;
	}
	db_ptr = (struct osf_sig *)vmalloc_user(sizeof(struct osf_sig)*control.num_db_entries);
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

void gen_db_info(struct osf_sig *list){
	unsigned int i;
	first_ack_log = 0;
	for(i=1 ; i<(list[0].print.dst_ip/sizeof(struct osf_sig)) ; i++){
		if(first_ack_log == 0 && list[i].ack == 1){
			first_ack_log = i;
		}
		if(list[i].print.db_entry == 0){
			break;
		}
	}
	control.cur_db_entries = i;
	return;
}

void print_print(struct osf_print *print){
	printk("\tdb_entry:    %u\n", print->db_entry);
	printk("\tsrc_ip:      %u\n", print->src_ip);
	printk("\tdst_ip:      %u\n", print->dst_ip);
	printk("\topt_hash:    %u\n", print->opt_hash);
	printk("\tquirks:      %u\n", print->quirks);
	printk("\topt_eol_pad: %u\n", print->opt_eol_pad);
	printk("\tip_opt_len:  %u\n", print->ip_opt_len);
	printk("\tttl:         %u\n", print->ttl);
	printk("\tmss:         %u\n", print->mss);
	printk("\twin:         %u\n", print->win);
	printk("\twin_type:    %u\n", print->win_type);
	printk("\twin_scale:   %u\n", print->win_scale);
	printk("\tpay_class:   %u\n", print->pay_class);
}

void print_sig(struct osf_sig *sig){
	printk("%c,%s,%s,%s:\n", sig->os_type, sig->os_class, sig->os_name, sig->os_flavor);
	print_print(&sig->print);
	printk("\twildcards:   %u\n", sig->wildcards);
}

void debug_osf_db(){
	unsigned int i;
	for(i=0 ; i<control.cur_db_entries ; i++){
		print_sig(&db[i]);
	}
	return;
}

int osf_db_release(struct inode *inode, struct file *filep){
	/*if(db_ptr[0].print.dst_ip < control.num_db_entries * sizeof(struct osf_sig)){
		memcpy(&db, db_ptr, db_ptr[0].print.dst_ip);
	}
	else{
		memcpy(&db, db_ptr, control.num_db_entries * sizeof(struct osf_sig));
	}*/
	memcpy(db, db_ptr, control.num_db_entries * sizeof(struct osf_sig));
	gen_db_info(db);
	//debug_osf_db();
	//hook_lock = 0;
	vfree(db_ptr);
	setup_complete = 1;
	return 0;
}

int osf_db_mmap(struct file *filep, struct vm_area_struct *vma){
	if(remap_vmalloc_range(vma, db_ptr, 0)) {
		printk("pna_osfmon remap_vmalloc_range failed\n");
		return -EAGAIN;
	}
	return 0;
}


ssize_t osf_pread(struct file *filep, char __user *buf, size_t len, loff_t *ppos)
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
	all_zeroes = vmalloc(sizeof(struct osf_info) + sizeof(struct osf_print) * new_logs);
	memset(all_zeroes, 0, sizeof(struct osf_info) + sizeof(struct osf_print) * new_logs);
	hashmap_a = hashmap_create(new_ips, 4, sizeof(struct osf_info) + sizeof(struct osf_print)*new_logs);
	if(hashmap_a == NULL){
		vfree(all_zeroes);
		if(new_ips == 1 && new_logs == 1){
			return -1;
		}
		control.num_ips = 1;
		control.num_logs = 1;
		return alloc_logs(1, 1);
	}
	hashmap_b = hashmap_create(new_ips, 4, sizeof(struct osf_info) + sizeof(struct osf_print)*new_logs);
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
	proc_node->proc_fops = &osf_log_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = new_ips * (4 + sizeof(struct osf_info) + sizeof(struct osf_print)*new_logs);
	return 0;
}

int alloc_db(unsigned int new_size){
	struct proc_dir_entry *proc_node;
	db_alloc_f = 1;
	db = (struct osf_sig *)vmalloc(sizeof(struct osf_sig)*new_size);
	
	if(db == NULL){
		control.num_db_entries = 1;
		return alloc_db(1);
	}

	proc_node = create_proc_entry(DB_PROC_NAME, 0644, proc_parent);
	if(!proc_node){
		pna_err("Could not create proc entry %s\n", DB_PROC_NAME);
		return -ENOMEM;
	}
	proc_node->proc_fops = &osf_db_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct osf_sig)*new_size;

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

struct osf_print *get_next_print(u32 key){
	struct osf_print *ret;
	struct osf_info *info;
	void *hash_ptr;
	hash_ptr = hashmap_get(hashmap, &key);
	if(hash_ptr == NULL){
		if((hashmap_put(hashmap, &key, all_zeroes)) == 0){
			return NULL;
		}
		hash_ptr = hashmap_get(hashmap, &key);
		info = (struct osf_info *)hash_ptr;
		info->src_ip = key;
		info->current_log = 0;
	}
	info = (struct osf_info *)hash_ptr;
	if(info->current_log == control.num_logs){
		//printk("88X %u %u\n", info->current_log, control.num_logs);
		return NULL;
	}
	if(info->src_ip != key){
		printk("Something went wrong in get_next_print\n");
		return NULL;
	}
	ret = (struct osf_print *)(hash_ptr + sizeof(struct osf_info) + sizeof(struct osf_print) * info->current_log);
	info->current_log++;
	return ret;
}

//Silas, edit this function:
int compute_sig(struct sk_buff *skb, struct osf_print *print){
	/*
	Some notes on what everything does:
	First, you can ignore the second argument to this function for now
	(the variable "struct osf_print *print).  This function is called
	every time the machine recieves a TCP SYN or SYN+ACK packet.
	The pointer skb points directly to the start of the packet.  You can
	access the start of the IP and TCP headers in the following way:
		IP header:
		struct iphdr *ip;
		ip = (struct iphdr *)skb_network_header(skb);
		TCP header:
		struct tcphdr *tcp;
		tcp = (struct tcphdr *)skb_network_header(skb);
	These lines will leave you with two pointers, ip and tcp, that
	point directly to the start of the ip and tcp headers.  You
	can look up the iphdr and tcphr structs to find ways to directly
	access certain fields.  For example, ip->saddr gives the value
	of the IP source address

	To both debug and print results, use the printk function.
	printk will output text directly to the file /var/log/kern.log
	*/
	return 0;
}

//The old compute_sig, included for reference
/*
int compute_sig(struct sk_buff *skb, struct osf_print *print){
	struct iphdr *ip;
	struct tcphdr *tcp;
	ip = (struct iphdr *)skb_network_header(skb);
	tcp = (struct tcphdr *)skb_transport_header(skb);
	//print->src_ip = ip->saddr;
	print->src_ip = ip->saddr;
	print->dst_ip = ip->daddr;
	parse_iphdr(print, skb, ip, tcp);
	parse_tcphdr(print, skb, ip, tcp);
	parse_tcpopts(print, skb, ip, tcp);
	return 0;
}*/

inline int specific_match(struct osf_print *print, struct sk_buff *skb, int i){
	//Returns 0 if no match, 1 if match, -1 if error (if necessary).
	
	if((db[i].print.opt_hash != print->opt_hash) && (db[i].wildcards & (1 << 4) != (1 << 4))){
		return 0;
	}
	if((db[i].print.quirks != print->quirks) && (db[i].wildcards & (1 << 6) != (1 << 6))){
		return 0;
	}
	if((db[i].print.opt_eol_pad != print->opt_eol_pad) && (db[i].wildcards & (1 << 5) != (1 << 5))){
		return 0;
	}
	if((db[i].print.ip_opt_len != print->ip_opt_len) && (db[i].wildcards & (1<<3) != (1<<3))){
		return 0;
	}
	if((db[i].print.ttl < print->ttl) && (db[i].wildcards & (1 << 2) != (1<<2))){
		return 0;
	}
	if((db[i].print.mss != print->mss) && (db[i].wildcards & 1 != 1)){
		return 0;
	}
	if((db[i].print.win_type == 1) && (print->mss * db[i].print.win != print->win)){
		return 0;
	}
	if((db[i].print.win_type == 2) && (print->win != db[i].print.win)){
		return 0;
	}
	if(((db[i].wildcards & 2) != 2) && (db[i].print.win_scale != print->win_scale)){
		return 0;
	}
	return 1;
}

inline u32 general_match(struct osf_print *print, struct sk_buff *skb, int i){
	if(specific_match(print, skb, i)){
		return db[i].score;
	}
	return 100000;
}

int match_sig(struct osf_print *print, struct sk_buff *skb){
	unsigned int max_entry;
	unsigned int max_score;
	unsigned int cur_entry;
	unsigned int cur_score;
	unsigned int full_match;
	int i;
	int ack_f;
	struct tcphdr *tcp;
	tcp =(struct tcphdr *)skb_transport_header(skb);
	if(tcp->ack){
		ack_f = 1;
	}
	else{
		ack_f = 0;
	}
	max_entry = 0;
	max_score = 100000;
	for(i=0 ; i < control.cur_db_entries ; i++){
		if(db[i].ack != ack_f){
			continue;
		}
		cur_entry = i;
		cur_score = 100000;
		full_match = 1;
		//Attempting match change XXX
		if(db[i].os_type == 's'){
			if(specific_match(print, skb, i) == 1){
				max_entry = cur_entry;
				max_score = 0;
				break;
			}
			continue;
		}
		else{
			cur_score = general_match(print, skb, i);
			if(cur_score < max_score){
				max_score = cur_score;
				max_entry = cur_entry;
			}
		}
		/*
		if(db[i].print.opt_hash == print->opt_hash){
			cur_score++;
		}
		else{
			continue;
		}
		if(db[i].print.quirks == print->quirks){
			cur_score++;
		}
		else{
			full_match = 0;
		}
		if(db[i].print.opt_eol_pad == print->opt_eol_pad){
			cur_score++;
		}
		else{
			full_match = 0;
		}
		if(db[i].print.ip_opt_len == print->ip_opt_len){
			cur_score++;
		}
		else{
			full_match = 0;
		}
		if(db[i].print.ttl == print->ttl){
			cur_score++;
		}
		else{
			full_match = 0;
		}
		if(((db[i].wildcards & 1) == 1) || (db[i].print.mss == print->mss)){
			cur_score++;
		}
		else if((db[i].wildcards & 1) == 0){
			full_match = 0;
		}
		//if((db[i].print.mss == print->mss) && ((db[i].wildcards & 1) == 0)){
		//	cur_score++;
		//}
		if(db[i].print.win_type == 0){
			//Do nothing
			cur_score++;
		}
		else if(db[i].print.win_type == 1){
			if((print->win % db[i].print.win) == 0){
				cur_score++;
			}
		}
		else if(db[i].print.win_type == 2){
			if(print->mss * db[i].print.win == print->win){
				cur_score++;
			}
		}
		else if(db[i].print.win_type == 3){
			if(db[i].print.win == print->win){
				cur_score++;
			}
		}
		else{
			full_match = 0;
		}
		if((db[i].print.win_scale == print->win_scale) || ((db[i].wildcards & 2) == 1)){
			cur_score++;
		}
		else if((db[i].wildcards & 2) == 0){
			full_match = 0;
		}
		//if((db[i].print.win_scale == print->win_scale) && ((db[i].wildcards & 2) == 0)){
		//	cur_score++;
		//}
		//No pay class
		//if((full_match == 1) && (db[i].os_type == 's')){
		//	max_entry = cur_entry;
		//	break;
		//}
		if(db[i].os_type == 's'){
			if(full_match == 1){
				max_entry = cur_entry;
				break;
			}
			continue;
		}
		if(cur_score > max_score){
			max_score = cur_score;
			max_entry = cur_entry;
		}
		*/
	}
	print->db_entry = max_entry;
	print->win_type = db[max_entry].print.win_type;
	print_print(print);
	return 0;
}

static int osf_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct osf_print *new_print;
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
	if(!tcp->syn){
		return 0;
	}
	while(hook_lock == 1){
		//set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(100);
		//hook_lock_ack = 1;
	}
	//hook_lock_ack = 0;
	num_in_hook++;
	new_print = get_next_print(ip->saddr);
	if(new_print == NULL){
		control.missed_logs++;
		num_in_hook--;
		return -1;
	}
	compute_sig(skb, new_print);
	num_in_hook--;
    	return 0;
}

static void osf_clean(void)
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

static int osf_init(void)
{
	struct proc_dir_entry *proc_node;
	int i;
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
	proc_node->proc_fops = &osf_control_fops;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = sizeof(struct osf_control);

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

static void osf_release(void)
{
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
