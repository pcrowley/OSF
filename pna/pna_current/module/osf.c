/**
 * Copyright 2012 Washington University in St Louis
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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/proc_fs.h>

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/in.h>

#include <linux/time.h>

#include "pna.h"
#include "osf.h"

//OSF Control information
struct osf_control control;
struct osf_control next_control;
struct osf_control *change_ptr;
struct osf_control *read_ptr;
int control_flag;

//OSF Fingerprint database pointer
struct osf_print *osf_db;
//OSF Log pointer
struct osf_print *osf_log;

//Unknown Fingerprint
static const struct osf_print unknown_fp = {
	.os_type = 'g',
	.os_class = "unkn\0",
	.os_name = "unknown\0",
	.os_flavor = "unknown\0",
};

//Control change procfile operations:
int change_open(struct inode *inode, struct file *filep);
int change_release(struct inode *inode, struct file *filep);
int change_mmap(struct file *filep, struct vm_area_struct *vma);

static const struct file_operations change_fops = {
	.owner 		= THIS_MODULE,
	.open		= change_open,
	.release	= change_release,
	.mmap		= change_mmap,
};

//Control read procfile operations:
int read_open(struct inode *inode, struct file *filep);
int read_release(struct inode *inode, struct file *filep);
int read_mmap(struct file *filep, struct vm_area_struct *vma);

static const struct file_operations read_fops = {
	.owner 		= THIS_MODULE,
	.open		= read_open,
	.release	= read_release,
	.mmap		= read_mmap,
};

//Log procfile operations:
int log_open(struct inode *inode, struct file *filep);
int log_release(struct inode *inode, struct file *filep);
int log_mmap(struct file *filep, struct vm_area_struct *vma);

static const struct file_operations log_fops = {
    .owner      = THIS_MODULE,
    .open       = log_open,
    .release    = log_release,
    .mmap       = log_mmap,
};

//DB procfile operations:
int db_open(struct inode *inode, struct file *filep);
int db_release(struct inode *inode, struct file *filep);
int db_mmap(struct file *filep, struct vm_area_struct *vma);

static const struct file_operations db_fops = {
	.owner		= THIS_MODULE,
	.open		= db_open,
	.release	= db_release,
	.mmap		= db_mmap,
};

void control_switch();

//For the following mutex value:
/*
	Care only has to be taken with the
	database since mutual exclusion is
	built into the log-keeping system.
	In this case, the lock only has to
	pass between the kernel database
	read operation and the userspace
	database write operation.  So, we
	only need 1 naive lock that can
	be passed between the two.
*/
//Mutual exclusion for database
int num_inside_db;
int db_mutex;

//For the control/log mutex:
/*
	Since freeing the logs/db while the
	log reader is going will cause a crash,
	exclusion is needed between the control
	change functions and the log reader.
	(Explicit exclusion is not necessary between
	the db and the control change, since it
	is implicitly given by db_mutex.)
	Again, only a single naive lock is necessary.
	0=Lock is free.
	1=Log has the lock.
	2=Control has the lock.
*/
int log_mutex;

//For the hook mutex and count:
/*
	The control change needs a semaphore,
	but multiple hooks can be used simultaneously
	(I think?) so I'm going to try a lock and
	count system this time:
*/
int num_inside_hook;
int hook_mutex;

//Runs when userspace opens file for control changes
int change_open(struct inode *inode, struct file *filep){
	log_mutex = 2;
	change_ptr = (struct osf_control*) vmalloc_user(sizeof(struct osf_control));
	change_ptr->num_log_entries = control.num_log_entries;
	change_ptr->num_db_entries = control.num_db_entries;
	change_ptr->cur_db_entries = control.cur_db_entries;
	change_ptr->next_log = control.next_log;
	change_ptr->missed_logs = control.missed_logs;
	return 0;
}

//Runs when userspace closes control file
int change_release(struct inode *inode, struct file *filep){
	next_control.num_log_entries = change_ptr->num_log_entries;
	next_control.num_db_entries = change_ptr->num_db_entries;
	next_control.cur_db_entries = change_ptr->cur_db_entries;
	next_control.next_log = change_ptr->next_log;
	next_control.missed_logs = change_ptr->missed_logs;
	vfree(change_ptr);
	hook_mutex = 1;
	while(num_inside_hook > 0){
		//Do nothing
	}
	control_switch();
	hook_mutex = 0;
	return 0;
}

//Runs when userspace mmaps control file
int change_mmap(struct file *filep, struct vm_area_struct *vma){
    if (remap_vmalloc_range(vma, change_ptr, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

//Runs when userspace opens file for control changes
int read_open(struct inode *inode, struct file *filep){
	read_ptr = (struct osf_control*) vmalloc_user(sizeof(struct osf_control));
	read_ptr->num_log_entries = control.num_log_entries;
	read_ptr->num_db_entries = control.num_db_entries;
	read_ptr->cur_db_entries = control.cur_db_entries;
	read_ptr->next_log = control.next_log;
	read_ptr->missed_logs = control.missed_logs;
	return 0;
}

//Runs when userspace closes control file
int read_release(struct inode *inode, struct file *filep){
	vfree(read_ptr);
	return 0;
}

//Runs when userspace mmaps control file
int read_mmap(struct file *filep, struct vm_area_struct *vma){
    if (remap_vmalloc_range(vma, read_ptr, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

//Runs when userspace opens file
int log_open(struct inode *inode, struct file *filep){
	while(log_mutex == 2){
		//Do nothing
	}
	log_mutex = 1;
	return 0;
}

//Runs when userspace closes file
int log_release(struct inode *inode, struct file *filep){
	control.next_log = 0;
	log_mutex = 0;
	return 0;
}

//Runs when userspace mmaps file
int log_mmap(struct file *filep, struct vm_area_struct *vma){
    if (remap_vmalloc_range(vma, osf_log, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

//Runs when userspace opens file
int db_open(struct inode *inode, struct file *filep){
	db_mutex = 1;	
	while(num_inside_db > 0){
		//Wait for database matching cycle to finish
	}
	return 0;
}

//Runs when userspace closes file
int db_release(struct inode *inode, struct file *filep){
	control.cur_db_entries = osf_db->src_ip;
	osf_db->src_ip = 0;
	db_mutex = 0;//Release lock
	return 0;
}

//Runs when userspace mmaps file
int db_mmap(struct file *filep, struct vm_area_struct *vma){
    if (remap_vmalloc_range(vma, osf_db, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }
    return 0;
}



int osf_init(void){
	struct proc_dir_entry *log_proc_node;
	struct proc_dir_entry *db_proc_node;
	struct proc_dir_entry *change_proc_node;
	struct proc_dir_entry *read_proc_node;

	//Setting mutex to defaults:
	db_mutex = 0;
	log_mutex = 0;
	hook_mutex = 0;
	num_inside_hook = 0;
	num_inside_db = 0;

	//Setting control information to defaults:
	control.num_log_entries = 0;
	control.num_db_entries = 0;
	control.cur_db_entries = 0;
	control.next_log = 0;
	control.missed_logs = 0;
	next_control.num_log_entries = 0;
	next_control.num_db_entries = 0;
	next_control.cur_db_entries = 0;
	next_control.next_log = 0;
	next_control.missed_logs = 0;
	control_flag = 0;
	
	//Creating proc entry for the logfile first...
	log_proc_node = create_proc_entry(OSF_PROC_LOG, 0666, NULL);
	log_proc_node->proc_fops = &log_fops;
	log_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	log_proc_node->uid = 0;
	log_proc_node->gid = 0;
	log_proc_node->size = OSF_LOG_SIZE;
	
	//Creating proc entry for the database now...
	db_proc_node = create_proc_entry(OSF_PROC_DB, 0666, NULL);
	db_proc_node->proc_fops = &db_fops;
	db_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	db_proc_node->uid = 0;
	db_proc_node->gid = 0;
	db_proc_node->size = OSF_DB_SIZE;

	//Creating control change proc entry
	change_proc_node = create_proc_entry(OSF_PROC_CHANGE, 0666, NULL);
	change_proc_node->proc_fops = &change_fops;
	change_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	change_proc_node->uid = 0;
	change_proc_node->gid = 0;
	change_proc_node->size = sizeof(struct osf_control);
	
	//Creating control read proc entry
	read_proc_node = create_proc_entry(OSF_PROC_READ, 0666, NULL);
	read_proc_node->proc_fops = &read_fops;
	read_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	read_proc_node->uid = 0;
	read_proc_node->gid = 0;
	read_proc_node->size = sizeof(struct osf_control);

	//Allocating minimum memory to avoid vfree() errors if unused...
	osf_log = (struct osf_print*)vmalloc_user(sizeof(struct osf_print));
	osf_db = (struct osf_print*)vmalloc_user(sizeof(struct osf_print));

	//Initial test case
	osf_log->done = 0;

	return 0;
}

void displaySig(struct osf_print *flow){
	printk("Done: %u\n", flow->done);
	printk("Src:  %u\n", flow->src_ip);
	printk("Dst:  %u\n", flow->dst_ip);
	printk("O_HS: %u\n", flow->opt_hash);
	printk("Q:    %u\n", flow->quirks);
	printk("EOL:  %u\n", flow->opt_eol_pad);
	printk("IPLN: %u\n", flow->ip_opt_len);
	printk("IPV:  %u\n", flow->ip_version);
	printk("TTL:  %u\n", flow->ttl);
	printk("MSS:  %u\n", flow->mss);
	printk("WIN:  %u\n", flow->win);
	printk("WTYP: %u\n", flow->win_type);
	printk("WSCL: %u\n", flow->win_scale);
	printk("PC:   %u\n", flow->pay_class);
	printk("TS1:  %u\n", flow->ts1);
	printk("TS2:  %u\n", flow->ts2);
	printk("WC:   %u\n", flow->wildcards);
	printk("UT:   %u\n", flow->unix_time);
	printk("Type: %c\n", flow->os_type);
	printk("Class:%s\n", flow->os_class);
	printk("Name: %s\n", flow->os_name);
	printk("Flav: %s\n", flow->os_flavor);
	return;
}

void computeSig(struct osf_print *flow, struct tcphdr *tcp, struct iphdr *ip, struct sk_buff *skb)
{
	//We know that this is a TCP packet with the SYN flag set, so
	//we don't have to check that.  We'll start with parsing the
	//TCP options into temporary variables.  At the same time,
	//this will check for the quirks in the TCP options, generate
	//the option hash, and find the EOL padding.
	
	//cur is the pointer to the current byte of the options being processed	
	//It starts at 20 bytes past the TCP header start pointer, where the
	//TCP options always start.
	struct timeval cur_time;
	u8 *opt;
	u8 *cur;
	u8 ipflags;
	u16 *read_2b;
	u32 *read_4b;
	u64 *read_8b;
	u8 temp1;
	u8 temp2;
	u8 *swap_ptr;
	u16 buff;
	opt = (u8 *)skb_transport_header(skb) + 20;
	unsigned short i;
	unsigned short eol_padding = 0;
	unsigned int opt_hash = 0;
	unsigned short opt_num = 0;
	unsigned int quirks = 0;
	unsigned short head_bytes = (tcp->doff)*4 - 20;
	//IP Header Quirks
	bool df_set = false;
	bool df_set_nonzero = false;
	bool df_not_set_zero = false;
	bool zero_is_one = false;
	bool nonzero_flow = false;
	bool congestion = false;
	//TCP Header Quirks
	bool seq_zero = false;
	bool ack_nonzero_noack = false;
	bool ack_zero_ack = false;
	bool urg_nonzero_nourg = false;
	bool urg_set = false;
	bool push_set = false;
	//TCP Option Quirks
	bool eol_flag = false;
	bool opt_nonzero = false;
	bool bad_tcp_flag = false;
	bool ts1_zero = false;
	bool ts2_nonzero = false;
	bool excess_window = false;
	flow->win_scale = 0;
	for(i = 0; i < head_bytes ; i++)
	{
		cur = opt + i;
		if (eol_flag){
			if (*cur != 0){
				//One of the quirks, eol padding should
				//always be zero.
				opt_nonzero = true;			
			}
			eol_padding++;
			continue;
		}
		opt_num++;
		//Experimental hash improvement
		if (*cur != 0){
		opt_hash = opt_hash * 8;
		opt_hash = opt_hash + (opt_num + *cur) * opt_num;
		}
		//End of option list		
		if (*cur == 0){
			printk("EOL,");
			eol_flag = true;
			continue;
		}
		//Options are malformed, cannot continue until EOL padding begins
		if (bad_tcp_flag){
			continue;
		}
		//No operation
		else if (*cur == 1){
			printk("NOP, ");
			continue;
		}
		//MSS
		else if (*cur == 2){
			printk("MSS, ");
			//read_2b = (u16 *)(cur + 2);
			//buff = *read_2b;
			temp1 = *(cur + 2);
			temp2 = *(cur + 3);
			swap_ptr = (u8 *)(&buff)+1;
			*swap_ptr = temp1;
			swap_ptr = (u8 *)(&buff);
			*swap_ptr = temp2;
			flow->mss = buff;
			i = i + 3;
			continue;
		}
		//Window scale
		else if (*cur == 3){
			printk("WS, ");
			flow->win_scale = *(cur + 2);
			if (*(cur+2) > 14){
				excess_window = true;
			}
			i = i + 2;
			continue;
		}
		//SACK flag
		else if (*cur == 4){
			printk("SACK, ");
			i = i + 1;
			continue;		
		}
		//SACK (Shouldn't come up ever, but it has variable length
		//so just in case, i is updated properly to skip over.
		else if (*cur == 5){
			printk("SOCK, ");
			//Leaves i one byte before end of SACK
			i = i + *(cur + 1) - 1;
			continue;		
		}
		//Echo (obsolete, but included)
		else if (*cur == 6){
			printk("ECHO, ");
			i = i + 5;
			continue;
		}
		//Echo reply (obsolete)
		else if (*cur == 7){
			printk("ECRP, ");
			i = i + 5;
			continue;
		}
		//Timestamp, ack respsonse (ts2) unnecessary
		else if (*cur == 8){
			printk("TS, ");
			read_4b = (u32 *)(cur + 2);
			flow->ts1 = *read_4b;
			//Quirk:  If timestamp is 0
			if(*read_4b == 0){
				ts1_zero = true;			
			}
			read_4b = (u32 *)(cur + 6);
			flow->ts2 = *read_4b;
			if((*read_4b != 0) && tcp->ack){
				ts2_nonzero = true;			
			}
			i = i + 9;
			continue;
		}
		//The rest of the TCP options are not directly used,
		//but we have to check all of them for the opt_hash.
		else if (*cur == 9){
			i = i + 1;
			continue;
		}
		else if (*cur == 10){
			i = i + 2;
			continue;
		}
		else if (*cur == 11){
			i = i + 5;
			continue;		
		}
		else if (*cur == 12){
			i = i + 5;
			continue;		
		}
		else if (*cur == 13){
			i = i + 5;
			continue;		
		}
		else if (*cur == 14){
			i = i + 2;
			continue;
		}
		else if (*cur == 15){
			i = i + *(cur + 1) - 1;
			continue;
		}
		else if (*cur == 18){
			i = i + 2;
			continue;
		}
		else if (*cur == 19){
			i = i + 17;
			continue;
		}
		else if (*cur == 27){
			i = i + 7;
			continue;
		}
		else if (*cur == 28){
			i = i + 3;
			continue;
		}
		//Tried all normal TCP options, must be malformed
		bad_tcp_flag = true;
	}
	flow->opt_eol_pad = eol_padding;
	//At this point, the following flow values are complete:
	//opt_hash
	//opt_eol_pad
	//mss
	//wscale
	//Now, moving on to extracting easy values from the ip
	//and tcp headers, checking for quirks along the way:
	flow->opt_hash = opt_hash;
	flow->ip_version = ip->version;
	//iphdr doesn't contain the flags, so we'll have to improvise
	//by just pointing directly to where they are in the skb
	cur = (u8 *)skb_network_header(skb) + 6;
	ipflags = *cur >> 5;//We only need the 3 flags.
	if (ip->version == 4){
		if((ipflags & 2) == 2){
			df_set = true;
			if(ip->id != 0){
				df_set_nonzero = true;			
			}
		}
		else{
			if(ip->id == 0){
				df_not_set_zero = true;
			}
		}
		if(ipflags >= 4){
			zero_is_one = true;
		}
	}
	else if (ip->version == 6){
		nonzero_flow = false;
	}
	//using ipflags for congestion notification now
	cur = (u8 *)skb_network_header(skb) + 1;
	ipflags = *cur & 3;
	if(ipflags != 0){
		congestion = true;
	}
	//IP header quirks are completely accounted for now.  Moving on to
	//TCP header quirks.
	if(tcp->seq == 0){
		seq_zero = true;	
	}
	if(tcp->ack_seq != 0 && !tcp->ack){
		ack_nonzero_noack = true;	
	}
	if(tcp->ack_seq == 0 && tcp->ack){
		ack_zero_ack = true;
	}
	if(tcp->urg_ptr != 0 && !tcp->urg){
		urg_nonzero_nourg = true;
	}
	if(tcp->urg){
		urg_set = true;
	}
	if(tcp->psh){
		push_set = true;
	}
	//All quirk flags set, calculating quirk field:
	//Each quirk flag corresponds to the bits in an int,
	//starting with least significant
	if (df_set) quirks = quirks + (1 << 0);
	if (df_set_nonzero) quirks = quirks + (1 << 1);
	if (df_not_set_zero) quirks = quirks + (1 << 2);
	if (zero_is_one) quirks = quirks + (1 << 3);
	if (nonzero_flow) quirks = quirks + (1 << 4);
	if (congestion) quirks = quirks + (1 << 5);
	if (seq_zero) quirks = quirks + (1 << 6);
	if (ack_nonzero_noack) quirks = quirks + (1 << 7);
	if (ack_zero_ack) quirks = quirks + (1 << 8);
	if (urg_nonzero_nourg) quirks = quirks + (1 << 9);
	if (urg_set) quirks = quirks + (1 << 10);
	if (push_set) quirks = quirks + (1 << 11);
	if (ts1_zero) quirks = quirks + (1 << 12);
	if (ts2_nonzero) quirks = quirks + (1 << 13);
	if (opt_nonzero) quirks = quirks + (1 << 14);
	if (excess_window) quirks = quirks + (1 << 15);
	if (bad_tcp_flag) quirks = quirks + (1 << 16);
	
	flow->quirks = quirks;
	//At this point, quirks is now finished and loaded into flow
	//Moving on to other header info
	flow->ip_opt_len = ((ip->ihl)-5)*4;
	flow->ttl = ip->ttl;  //Actual TTL stored, original estimated in match
	//flow->win = tcp->window;
	buff = tcp->window;
	temp1 = *(u8 *)(&buff);
	temp2 = *((u8 *)(&buff)+1);
	swap_ptr = (u8 *)(&buff);
	*swap_ptr = temp2;
	swap_ptr = (u8 *)(&buff) + 1;
	*swap_ptr = temp1;
	flow->win = buff;
	//flow->win = tcp->window;
	//Getting window type through modulus calculation
	//Type 0 is fixed value
	//Type 1 is multiple of MSS (Tested first)
	//Type 2 is multiple of random variable (Not testable until match)
	if(flow->win % flow->mss == 0){
		flow->win_type = 1;	
	}
	else{
		flow->win_type = 0;
	}
	if(ip->tot_len == 0){
		flow->pay_class = 1;
	}
	else{
		flow->pay_class = 1;
	}
	flow->src_ip = ip->saddr;
	flow->dst_ip = ip->daddr;

	do_gettimeofday(&cur_time);
	flow->unix_time = cur_time.tv_usec;
	
	//displaySig(flow);
	return;
	
//A list of all signature fields
/*
	sig_ent->tcp_sig.opt_hash = get_opt_hash(tcp);
	sig_ent->tcp_sig.quirks = get_quirks(tcp);
	sig_ent->tcp_sig.opt_eol_pad = get_opt_eol_pad(tcp);
	sig_ent->tcp_sig.ip_opt_len = get_ip_opt_len(ip);
	sig_ent->tcp_sig.ip_ver = get_ip_ver(ip);
	sig_ent->tcp_sig.ttl = get_ttl(ip);
	sig_ent->tcp_sig.mss = get_mss(tcp);
	sig_ent->tcp_sig.win = get_win(tcp);
	sig_ent->tcp_sig.win_type = get_win_type(tcp);
	sig_ent->tcp_sig.wscale = get_wscale(tcp);
	sig_ent->tcp_sig.pay_class = get_pay_class(tcp);
	sig_ent->tcp_sig.tot_hdr = get_tot_hdr(tcp);
	sig_ent->tcp_sig.ts1 = get_ts1(tcp);
	sig_ent->tcp_sig.recv_ms = get_recv_ms(tcp);
*/	
//Quirks in the order they appear:
/*
	//IP Header Quirks
	bool df_set_nonzero = false;
	bool df_not_set_zero = false;
	bool zero_is_one = false;
	bool nonzero_flow = false;
	bool congestion = false;
	//TCP Header Quirks
	bool seq_zero = false;
	bool ack_nonzero_noack = false;
	bool ack_zero_ack = false;
	bool urg_nonzero_nourg = false;
	bool urg_set = false;
	bool push_set = false;
	//TCP Option Quirks
	bool eol_flag = false;
	bool bad_tcp_flag = false;
	bool ts1_zero = false;
	bool ts2_nonzero = false;
	bool excess_window = false;
*/
//A list of all quirks
/*
               df     - "don't fragment" set (probably PMTUD); ignored for IPv6
               id+    - DF set but IPID non-zero; ignored for IPv6
               id-    - DF not set but IPID is zero; ignored for IPv6
               ecn    - explicit congestion notification support
               0+     - "must be zero" field not zero; ignored for IPv6
               flow   - non-zero IPv6 flow ID; ignored for IPv4

               seq-   - sequence number is zero
               ack+   - ACK number is non-zero, but ACK flag not set
               ack-   - ACK number is zero, but ACK flag set
               uptr+  - URG pointer is non-zero, but URG flag not set
               urgf+  - URG flag used
               pushf+ - PUSH flag used

               ts1-   - own timestamp specified as zero
               ts2+   - non-zero peer timestamp on initial SYN
               opt+   - trailing non-zero data in options segment
               exws   - excessive window scaling factor (> 14)
               bad    - malformed TCP options
*/
}

void matchSig(struct osf_print *flow, unsigned int ackFlag)
{
	struct osf_print *matTab;
	matTab = &unknown_fp;
	memcpy(&(flow->os_type), &(matTab->os_type), MATCH_SIZE);
	int i;
	printk("New Matching\n");
	displaySig(flow);
	for(i=0 ; i < control.cur_db_entries ; i++){
		matTab = osf_db + i;
		if(ackFlag != matTab->unix_time){
			continue;
		}
		if(flow->opt_hash != matTab->opt_hash){
			continue;
		}
		if(flow->quirks != matTab->quirks){
			continue;
		}
		if(flow->opt_eol_pad != matTab->opt_eol_pad){
			continue;
		}
		if(flow->ip_opt_len != matTab->ip_opt_len){
			continue;
		}
		if(matTab->ip_version != 0 && flow->ip_version != matTab->ip_version){
			continue;
		}
		if(flow->ttl > matTab->ttl || (flow->ttl < matTab->ttl/2 && matTab->ttl > 32)){
			continue;
		}
		if(matTab->mss != 0 && flow->mss != matTab->mss){
			continue;//May not work.
		}
		if(matTab->win_type == 0){
		}
		else if(matTab->win_type == 1){
			if(matTab->win != flow->win){
				continue;			
			}
		}
		else if(matTab->win_type == 2){
			if(!((matTab->win == (flow->win / flow->mss)) && ((flow->win % flow->mss) == 0))){
				continue;			
			}
		}
		else if(matTab->win_type == 3){
			//No way to handle this kind of match *yet*
			//so we must skip.
			continue;
		}
		else if(matTab->win_type == 4){
			if(flow->win % matTab->win == 0){
				continue;			
			}
		}
		if((matTab->win_scale != flow->win_scale) && ((matTab->wildcards & 2) != 2)){
			continue;		
		}
		if(matTab->pay_class != flow->pay_class && matTab->pay_class != 0){
			continue;
		}
		break;
	}
	//Okay, at this point, we've found a match, so we have to copy the tcp_mat.
	if(i >= control.cur_db_entries){
		matTab = &unknown_fp;
	}
	memcpy(&(flow->os_type), &(matTab->os_type), MATCH_SIZE);

	printk("Incoming Signature:\n");	
	displaySig(flow);
	printk("Current Match:\n");
	displaySig(osf_db);


	flow->done = 1;
	return;
}

void control_switch(){
	//WARNING:
	//The use of this function will cause errors if
	//OSF is somehow utilized in parallel.
	//Additional semaphores are necessary to ensure
	//proper operation.  I suggest using a new mutex
	//and checking it at the end of the hook.  Once
	//all hooks are clear, then perform the userspace
	//setting of next_control, then allow normal
	//operation, from that point, all hooks will
	//be stopped until all reallocation has occured.
	struct proc_dir_entry *log_proc_node;
	struct proc_dir_entry *db_proc_node;

	//Checking necessary semaphores:
	while(log_mutex == 1){
		//Do nothing
	}
	log_mutex = 2;
	
	//Reinitialize based on userspace control directions
	//Setting control variables to those set within next_control
	control.num_log_entries = next_control.num_log_entries;
	control.num_db_entries = next_control.num_db_entries;
	control.cur_db_entries = next_control.cur_db_entries;
	control.next_log = next_control.next_log;
	control.missed_logs = next_control.missed_logs;
	//Resetting next_control for next use.
	next_control.num_log_entries = 0;
	next_control.num_db_entries = 0;
	next_control.cur_db_entries = 0;
	next_control.next_log = 0;
	next_control.missed_logs = 0;

	//Freeing all dynamically allocated variables:
	vfree(osf_log);
	vfree(osf_db);

	//Removing proc entries...
	remove_proc_entry(OSF_PROC_LOG, NULL);
	remove_proc_entry(OSF_PROC_DB, NULL);

	//Recreating proc entries...
	//Creating proc entry for the logfile first...
	log_proc_node = create_proc_entry(OSF_PROC_LOG, 0666, NULL);
	log_proc_node->proc_fops = &log_fops;
	log_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	log_proc_node->uid = 0;
	log_proc_node->gid = 0;
	if(control.num_log_entries == 0){
		log_proc_node->size = sizeof(struct osf_print);
	}
	else{
		log_proc_node->size = sizeof(struct osf_print) * control.num_log_entries;
	}
	
	//Creating proc entry for the database now...
	db_proc_node = create_proc_entry(OSF_PROC_DB, 0666, NULL);
	db_proc_node->proc_fops = &db_fops;
	db_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	db_proc_node->uid = 0;
	db_proc_node->gid = 0;
	if(control.num_db_entries == 0){
		db_proc_node->size = sizeof(struct osf_print);
	}
	else{
		db_proc_node->size = sizeof(struct osf_print) * control.num_db_entries;
	}

	//Reallocating...
	if(control.num_log_entries == 0){
		osf_log = (struct osf_print*)vmalloc_user(sizeof(struct osf_print));
	}
	else{
		osf_log = (struct osf_print*)vmalloc_user(sizeof(struct osf_print) * control.num_log_entries);
	}
	if(control.num_db_entries == 0){
		osf_db = (struct osf_print*)vmalloc_user(sizeof(struct osf_print));
	}
	else{
		osf_db = (struct osf_print*)vmalloc_user(sizeof(struct osf_print) * control.num_db_entries);
	}

	//Finally, changing control flag back to normal:
	control_flag = 0;
	log_mutex = 0;
	return;	
}

int osf_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
			 unsigned long data){
	struct tcphdr *tcp;
	struct tcphdr _tcp;
	struct iphdr *ip;
	struct osf_print *next_print;
	
	while(hook_mutex == 1){
			//Do nothing
	}
	num_inside_hook++;
	//If space for log entries is 0, then module is effectively off.
	if(control.num_log_entries == 0){
		num_inside_hook--;
		return -1;
	}
	//Testing to see if the current packet is a TCP SYN packet of any kind
	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcp);
	ip = (struct iphdr *)skb_network_header(skb);
	if(!tcp){
		num_inside_hook--;
		return -1;	
	}
	if(!tcp->syn){
		num_inside_hook--;
		return -1;
	}

	//Checking to see if the current log is taken (although this should not
	//happen).  And if it is, incrementing next_log until it finds an empty
	//space.
	while((osf_log + control.next_log)->done == 1){
		control.next_log = control.next_log + 1;
		if(control.next_log >= control.num_log_entries){
			break;
		}
	}

	//Now checking to see if the log is full:
	if(control.next_log >= control.num_log_entries){
		control.missed_logs = control.missed_logs + 1;
		num_inside_hook--;
		return -1;
	}

	//Setting the address of the location in the log
	next_print = osf_log + control.next_log;
	//Incrementing next_log
	control.next_log = control.next_log + 1;
	//At this point, we are ready to perform matching
	computeSig(next_print, tcp, ip, skb);
	
	//Match complete, now moving on to writing the sig
	if(tcp->ack){
		matchSig(next_print, 1);
	}
	else{
		matchSig(next_print, 0);
	}
	num_inside_hook--;
	return 0;
}

void osf_clean(void){
	return;
}

void osf_release(void){
	vfree(osf_log);
	vfree(osf_db);
	remove_proc_entry(OSF_PROC_LOG, NULL);
	remove_proc_entry(OSF_PROC_DB, NULL);
	remove_proc_entry(OSF_PROC_CHANGE, NULL);
	remove_proc_entry(OSF_PROC_READ, NULL);
	return;
}
