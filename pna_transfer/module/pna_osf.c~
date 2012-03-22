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

/* handle insertion into flow table */
/* functions: flowmon_init, flowmon_cleanup, flowmon_hook */

#include <linux/kernel.h>
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

//Database includes
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include <linux/types.h>

#include "pna.h"
#include "pna_osf.h"

//Database loading variables/functions;
bool db_loaded = false;
bool load_db();
bool unload_db();


/* kernel/user table interaction */
 int osf_flowtab_open(struct inode *inode, struct file *filep);
 int osf_flowtab_release(struct inode *inode, struct file *filep);
 int osf_flowtab_mmap(struct file *filep, struct vm_area_struct *vma);
 void osf_flowtab_clean(struct osf_flowtab_info *info);
 void osf_flowtab_safeclean(void);
 int osf_flowtab_release_all(void);

/* kernel functions for flow monitoring */
 struct osf_flowtab_info *osf_flowtab_get(struct timeval *timeval);
 int osf_flowkey_match(struct osfmon_entry *key_a, struct osfmon_entry *key_b);
int osf_flowmon_init(void);
void osf_flowmon_cleanup(void);

/* pointer to information about the flow tables */
 struct osf_flowtab_info *osf_flowtab_info;

/* pointer to the /proc durectiry parent node */
 struct proc_dir_entry *proc_parent;

/* file operations for accessing the flowtab */
 const struct file_operations osf_flowtab_fops = {
    .owner      = THIS_MODULE,
    .open       = osf_flowtab_open,
    .release    = osf_flowtab_release,
    .mmap       = osf_flowtab_mmap,
};

/* simple null key */
 struct osfmon_entry null_key = {
    .local_ip = 0,
};

/*match table pointer*/
struct osfmon_entry *mat_tab;
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
/*Default match table*/
struct osfmon_entry default_match_table[] = {
//Linux 3.x
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 108,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 64,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 10,
	.tcp_sig.win_type = 2,
	.tcp_sig.wscale = 4,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "unix\0",
	.tcp_mat.name = "Linux\0",
	.tcp_mat.flavor = "3.x\0",
},
//Linux 3.x
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 108,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 64,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 10,
	.tcp_sig.win_type = 2,
	.tcp_sig.wscale = 5,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "unix\0",
	.tcp_mat.name = "Linux\0",
	.tcp_mat.flavor = "3.x\0",
},
//Linux 3.x
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 108,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 64,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 10,
	.tcp_sig.win_type = 2,
	.tcp_sig.wscale = 6,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "unix\0",
	.tcp_mat.name = "Linux\0",
	.tcp_mat.flavor = "3.x\0",
},
//Linux 3.x
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 108,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 64,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 10,
	.tcp_sig.win_type = 2,
	.tcp_sig.wscale = 7,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "unix\0",
	.tcp_mat.name = "Linux\0",
	.tcp_mat.flavor = "3.x\0",
},
//Windows XP
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 53,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 128,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 65535,
	.tcp_sig.win_type = 1,
	.tcp_sig.wscale = 0,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "win\0",
	.tcp_mat.name = "Windows\0",
	.tcp_mat.flavor = "XP\0",
},
//VirtualBox Windows XP
{
	.local_ip = 87,
	.tcp_sig.opt_hash = 53,
	.tcp_sig.quirks = 3,
	.tcp_sig.opt_eol_pad = 0,
	.tcp_sig.ip_opt_len = 0,
	.tcp_sig.ip_ver = -1,
	.tcp_sig.ttl = 128,
	.tcp_sig.mss = 0,
	.tcp_sig.win = 64240,
	.tcp_sig.win_type = 1,
	.tcp_sig.wscale = 0,
	.tcp_sig.pay_class = 0,
	.tcp_sig.tot_hdr = 0,
	.tcp_sig.ts1 = 0,
	.tcp_sig.recv_ms = 0,
	.tcp_mat.type = 's',
	.tcp_mat.os_class = "win\0",
	.tcp_mat.name = "Windows\0",
	.tcp_mat.flavor = "XP\0",
},
//End of List
{
	.local_ip = 88,
	.tcp_mat.type = 'g',
	.tcp_mat.os_class = "unkn\0",
	.tcp_mat.name = "Unknown\0",
	.tcp_mat.flavor = "Unknown\0",
}
};

/* per-cpu data */
DEFINE_PER_CPU(int, osf_flowtab_idx);

int protocol_map2(int l4_protocol)
{
    switch (l4_protocol) {
    case IPPROTO_TCP:
        return PNA_PROTO_TCP;
        break;
    case IPPROTO_UDP:
        return PNA_PROTO_UDP;
    default:
        return -1;
    };
}

void debug_sig(struct osfmon_entry *fp)
{
	//return;
	printk("*************************\n");
	printk("IP: %u\n", fp->local_ip);
	printk("OS Type: %c\n", fp->tcp_mat.type);
	printk("OS Class: %s\n", fp->tcp_mat.os_class);
	printk("OS Name: %s\n", fp->tcp_mat.name);
	printk("OS Flavor: %s\n", fp->tcp_mat.flavor);
	printk("opt_hash: %u\n", fp->tcp_sig.opt_hash);
	printk("quirks: %u\n", fp->tcp_sig.quirks);
	printk("opt_eol_pad: %u\n", fp->tcp_sig.opt_eol_pad);
	printk("ip_opt_len: %u\n", fp->tcp_sig.ip_opt_len);
	printk("ip_ver: %d\n", fp->tcp_sig.ip_ver);
	printk("ttl: %u\n", fp->tcp_sig.ttl);
	printk("mss: %u\n", fp->tcp_sig.mss);
	printk("win: %u\n", fp->tcp_sig.win);
	printk("win_type: %u\n", fp->tcp_sig.win_type);
	printk("wscale: %d\n", fp->tcp_sig.wscale);
	printk("pay_class: %d\n", fp->tcp_sig.pay_class);
	printk("tot_hdr: %u\n", fp->tcp_sig.tot_hdr);
	printk("ts1: %u\n", fp->tcp_sig.ts1);
	printk("recv_ms: %u\n", fp->tcp_sig.recv_ms);
}
//Database load/unload
bool load_db(){
	struct file* fptr = NULL;
	int i = 0;
	char buf[1];
	char *table_base;
	mm_segment_t oldfs;
	
	vfree(mat_tab);
	mat_tab = (struct osfmon_entry*) vmalloc(1 << 16);
	table_base = (char*)mat_tab;

	oldfs = get_fs();
	set_fs(get_ds());
	fptr = filp_open("/home/jason/pna_transfer/tcp.osf", O_RDONLY, 0);	

	vfs_read(fptr, mat_tab, 44674, &fptr->f_pos);

	set_fs(oldfs);
	filp_close(fptr, NULL);
	
	//debug_sig(mat_tab);
	//vfree(mat_tab);
	//mat_tab = &default_match_table;	
	
	return true;
}
bool unload_db(){
	vfree(mat_tab);
	mat_tab = &default_match_table;
	return false;
}

/*
 * kernel/user table interaction
 */
/* runs when user space has opened the file */
 int osf_flowtab_open(struct inode *inode, struct file *filep)
{
    int i;
    struct osf_flowtab_info *info;
    struct timeval now;
    unsigned int first_sec;

    try_module_get(THIS_MODULE);

    /* find the name of file opened (index into flowtab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &osf_flowtab_info[i];

    /* make sure the table was written and not in the last LAG_TIME */
    do_gettimeofday(&now);
    first_sec = info->first_sec + PNA_LAG_TIME;
    if (!info->table_dirty || first_sec >= now.tv_sec ) {
        module_put(THIS_MODULE);
        return -EACCES;
    }

    /* give pointer to filep struct for mmap */
    filep->private_data = info;

    /* lock the table, has the effect of kernel changing tables */
    mutex_lock(&info->read_mutex);

    return 0;
}

/* runs when user space has closed the file */
 int osf_flowtab_release(struct inode *inode, struct file *filep)
{
    int i;
    struct osf_flowtab_info *info;

    /* find the name of file opened (index into flowtab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &osf_flowtab_info[i];

    /* dump a little info about that table */
	//I think this can be avoided, at least until I care
	//about performance monitoring
/*
    if (pna_perfmon) {
        pr_info("pna table%d_inserts:%u,table%d_drops:%u\n",
                i, info->nflows, i, info->nflows_missed);
    }
*/
    /* zero out the table */
    memset(info->table_base, 0, OSF_SZ_FLOW_ENTRIES);

#if 0
    for (i = 0; i < PNA_TABLE_TRIES; i++) {
        printk("tries\t%d\t%u\n", i, info->probes[i]);
        info->probes[i] = 0;
    }
#endif /* 0 */

    /* this table is safe to use again */
    osf_flowtab_clean(info);

    /* unlock this table, has the effect of being free for use again */
    mutex_unlock(&info->read_mutex);

    module_put(THIS_MODULE);
    return 0;
}

 int osf_flowtab_release_all(void)
{
	osf_flowmon_cleanup();
	return 0;
}

/* runs when user space wants to mmap the file */
 int osf_flowtab_mmap(struct file *filep, struct vm_area_struct *vma)
{
    struct osf_flowtab_info *info = filep->private_data;

    if (remap_vmalloc_range(vma, info->table_base, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

/* clear out all the mflowtable data from a flowtab entry */
 void osf_flowtab_clean(struct osf_flowtab_info *info)
{
    info->table_dirty = 0;
    info->first_sec = 0;
    info->smp_id = 0;
    info->nflows = 0;
    info->nflows_missed = 0;
}

/* determine which flow table to use */
 struct osf_flowtab_info *osf_flowtab_get(struct timeval *timeval)
{
    int i;
    struct osf_flowtab_info *info;

    /* figure out which flow table to use */
    info = &osf_flowtab_info[get_cpu_var(osf_flowtab_idx)];

    /* check if table is locked */
    i = 0;
    while (mutex_is_locked(&info->read_mutex) && i < pna_tables) {
        /* if it is locked try the next table ... */
        get_cpu_var(osf_flowtab_idx) = (get_cpu_var(osf_flowtab_idx) + 1) % pna_tables;
        put_cpu_var(osf_flowtab_idx);
        info = &osf_flowtab_info[get_cpu_var(osf_flowtab_idx)];
        /* don't try a table more than once */
        i++;
    }
    if (i == pna_tables) {
        pr_warning("pna: all tables are locked\n");
        return NULL;
    }

    /* make sure this table is marked as dirty */
    // XXX: table_dirty should probably be atomic_t
    if (info->table_dirty == 0) {
        info->first_sec = timeval->tv_sec;
        info->table_dirty = 1;
        info->smp_id = smp_processor_id();
    }

    return info;
}

/* check if flow keys match */
 inline int osf_flowkey_match(struct osfmon_entry *key_a, struct osfmon_entry *key_b)
{
	//Write an actual test here later to conserve memory and file space
	//for now, it just tests the local ips.
	return key_a->local_ip == key_b->local_ip;
}

/* Insert/Update this flow */

void writeSig(struct osfmon_entry *flow, struct tcphdr *tcp, struct iphdr *ip, struct sk_buff *skb)
{
	//These types are used for temporary pointers into the TCP options
	typedef __u8 u8;
	typedef __u16 u16;
	typedef __u32 u32;
	typedef __u64 u64;
	//We know that this is a TCP packet with the SYN flag set, so
	//we don't have to check that.  We'll start with parsing the
	//TCP options into temporary variables.  At the same time,
	//this will check for the quirks in the TCP options, generate
	//the option hash, and find the EOL padding.
	
	//cur is the pointer to the current byte of the options being processed	
	//It starts at 20 bytes past the TCP header start pointer, where the
	//TCP options always start.
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
		opt_hash = opt_hash + (opt_num + *cur) * opt_num;
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
			flow->tcp_sig.mss = buff;
			i = i + 3;
			continue;
		}
		//Window scale
		else if (*cur == 3){
			printk("WS, ");
			flow->tcp_sig.wscale = *(cur + 2);
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
			read_4b = (u32 *)cur + 2;
			flow->tcp_sig.ts1 = *read_4b;
			//Quirk:  If timestamp is 0
			if(*read_4b == 0){
				ts1_zero = true;			
			}
			read_4b = read_4b + 4;
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
	flow->tcp_sig.opt_eol_pad = eol_padding;
	//At this point, the following flow values are complete:
	//opt_hash
	//opt_eol_pad
	//mss
	//wscale
	//Now, moving on to extracting easy values from the ip
	//and tcp headers, checking for quirks along the way:
	flow->tcp_sig.opt_hash = opt_hash;
	flow->tcp_sig.ip_ver = ip->version;
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
	
	flow->tcp_sig.quirks = quirks;
	//At this point, quirks is now finished and loaded into flow
	//Moving on to other header info
	flow->tcp_sig.ip_opt_len = ((ip->ihl)-5)*4;
	flow->tcp_sig.ttl = ip->ttl;  //Actual TTL stored, original estimated in match
	//flow->tcp_sig.win = tcp->window;
	buff = tcp-> window;
	temp1 = *(u8 *)(&buff);
	temp2 = *((u8 *)(&buff)+1);
	swap_ptr = (u8 *)(&buff);
	*swap_ptr = temp2;
	swap_ptr = (u8 *)(&buff) + 1;
	*swap_ptr = temp1;
	flow->tcp_sig.win = buff;
	//flow->tcp_sig.win = tcp->window;
	//Getting window type through modulus calculation
	//Type 0 is fixed value
	//Type 1 is multiple of MSS (Tested first)
	//Type 2 is multiple of random variable (Not testable until match)
	if(flow->tcp_sig.win % flow->tcp_sig.mss == 0){
		flow->tcp_sig.win_type = 1;	
	}
	else{
		flow->tcp_sig.win_type = 0;
	}
	if(ip->tot_len == 0){
		flow->tcp_sig.pay_class = 0;
	}
	else{
		flow->tcp_sig.pay_class = 0;
	}
	//This field is not used for matching, putting 88
	//here for testing so I know when the header info
	//is over.
	flow->tcp_sig.recv_ms = 88;
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



void matchSig(struct osfmon_entry *flow, struct osfmon_entry *matTab)
{

	printk("New Matching\n");
	debug_sig(flow);
	while(matTab->local_ip != 88){
		debug_sig(matTab);
		if(flow->tcp_sig.opt_hash != matTab->tcp_sig.opt_hash){
			matTab = matTab + 1;
			continue;
		}
		if(flow->tcp_sig.quirks != matTab->tcp_sig.quirks){
			matTab = matTab + 1;
			continue;
		}
		if(flow->tcp_sig.opt_eol_pad != matTab->tcp_sig.opt_eol_pad){
			matTab = matTab + 1;
			continue;
		}
		if(flow->tcp_sig.ip_opt_len != matTab->tcp_sig.ip_opt_len){
			matTab = matTab + 1;
			continue;
		}
		if(matTab->tcp_sig.ip_ver != -1 && flow->tcp_sig.ip_ver != matTab->tcp_sig.ip_ver){
			matTab = matTab + 1;
			continue;
		}
		if(flow->tcp_sig.ttl > matTab->tcp_sig.ttl || (flow->tcp_sig.ttl < matTab->tcp_sig.ttl/2 && matTab->tcp_sig.ttl > 32)){
			matTab = matTab + 1;
			continue;
		}
		if(matTab->tcp_sig.mss != 0 && flow->tcp_sig.mss != matTab->tcp_sig.mss){
			matTab = matTab + 1;
			continue;
		}
		if(matTab->tcp_sig.win_type == 0){
		}
		else if(matTab->tcp_sig.win_type == 1){
			if(matTab->tcp_sig.win != flow->tcp_sig.win){
				matTab = matTab + 1;
				continue;			
			}
		}
		else if(matTab->tcp_sig.win_type == 2){
			if(matTab->tcp_sig.win == flow->tcp_sig.win / flow->tcp_sig.mss && flow->tcp_sig.win % flow->tcp_sig.mss == 0){
				matTab = matTab + 1;
				continue;			
			}
		}
		else if(matTab->tcp_sig.win_type == 3){
			//No way to handle this kind of match *yet*
			//so we must skip.
			matTab = matTab + 1;
			continue;
		}
		else if(matTab->tcp_sig.win_type == 4){
			if(flow->tcp_sig.win % matTab->tcp_sig.win == 0){
				matTab = matTab + 1;
				continue;			
			}
		}
		if(matTab->tcp_sig.wscale != flow->tcp_sig.wscale){
			matTab = matTab + 1;
			continue;		
		}
		if(matTab->tcp_sig.pay_class != flow->tcp_sig.pay_class && matTab->tcp_sig.pay_class != -1){
			matTab = matTab + 1;
			continue;
		}
		break;
	}
	//Okay, at this point, we've found a match, so we have to copy the tcp_mat.
	memcpy(&(flow->tcp_mat), &(matTab->tcp_mat), sizeof(struct osf_tcp_mat));
	return;
}
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


int osf_flowmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb)
{
    struct osfmon_entry *flow;
    struct timeval timeval;
    struct osf_flowtab_info *info;
    unsigned int i, hash_0, hash;

    /* get the timestamp on the packet */
    skb_get_timestamp(skb, &timeval);

    if (NULL == (info = osf_flowtab_get(&timeval))) {
        return -1;
    }

    /* hash */
    hash = key->local_ip ^ key->remote_ip;
    hash ^= ((key->remote_port << 16) | key->local_port);
    hash_0 = hash_32(hash, PNA_FLOW_BITS);
	struct tcphdr *tcp;
	struct iphdr *ip;
	struct tcphdr _tcph;
	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
	ip = (struct iphdr *)skb_network_header(skb);
	if(!tcp)
		return -1;
	if(!tcp->syn)
		return -1;
    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* quadratic probe for next entry */
        hash = (hash_0 + ((i+i*i) >> 1)) & (PNA_FLOW_ENTRIES-1);

        /* increment the number of probe tries for the table */
        info->probes[i]++;

        /* strt testing the waters */
        flow = &(info->flowtab[hash]);

        /* check for match -- update flow entry */
/*
        if (flowkey_match(&flow->key, key)) {
            flow->data.bytes[direction] += skb->len + ETH_OVERHEAD;
            flow->data.packets[direction] += 1;
            return 0;
        }
*/
	
        /* check for free spot -- insert flow entry */
        if (osf_flowkey_match(flow, &null_key)) {
            /* copy over the flow key for this entry */
		//Temporary 88 test:
		//flow->local_ip = 88;
		flow->local_ip = key->local_ip;
		writeSig(flow, tcp, ip, skb);
		matchSig(flow, mat_tab);
		//debug_sig(flow);

            info->nflows++;
            return 1;
        }
    }

    info->nflows_missed++;
    return -1;
}

struct osfmon_entry *get_mat_table(){
	return &default_match_table;
}

/* initialization routine for flow monitoring */
int osf_flowmon_init(void)
{
	//First, loading the fingerprint database:
	if(db_loaded == false){
		db_loaded = true;
		db_loaded = load_db();
	}
	//return 0;
    int i;
    struct osf_flowtab_info *info;
    char table_str[PNA_MAX_STR];
    struct proc_dir_entry *proc_node;

    /* create the /proc base dir for pna tables */
    proc_parent = proc_mkdir(OSF_PROCDIR, NULL);
	//return 0;
    /* make memory for table meta-information */
    osf_flowtab_info = (struct osf_flowtab_info *)
                    vmalloc(pna_tables * sizeof(struct osf_flowtab_info));
    if (!osf_flowtab_info) {
        pr_err("insufficient memory for flowtab_info\n");
        osf_flowmon_cleanup();
        return -ENOMEM;
    }
	//return 0;
    memset(osf_flowtab_info, 0, pna_tables * sizeof(struct osf_flowtab_info));
	//return 0;
	//Get the match table
	//mat_tab = get_mat_table();
    /* configure each table for use */
    for (i = 0; i < pna_tables; i++) {
	//printk("FFFFFFFFFFFF %d %d %d\n", PNA_FLOW_ENTRIES, (pna_tables * OSF_SZ_FLOW_ENTRIES), (pna_tables * PNA_SZ_FLOW_ENTRIES));
	//continue;
        info = &osf_flowtab_info[i];
        info->table_base = vmalloc_user(OSF_SZ_FLOW_ENTRIES);
        if (!info->table_base) {
            pr_err("insufficient memory for %d/%d tables (%lu bytes)\n",
                    i, pna_tables, (pna_tables * OSF_SZ_FLOW_ENTRIES));
            osf_flowmon_cleanup();
            return -ENOMEM;
        }
	//break;
        /* set up table pointers */
        info->flowtab = info->table_base;
        osf_flowtab_clean(info);

        /* initialize the read_mutec */
        mutex_init(&info->read_mutex);

        snprintf(table_str, PNA_MAX_STR, PNA_PROCFILE, i);
        strncpy(info->table_name, table_str, PNA_MAX_STR);
        proc_node = create_proc_entry(info->table_name, 0644, proc_parent);
        if (!proc_node) {
            pr_err("failed to make proc entry: %s\n", table_str);
            flowmon_cleanup();
            return -ENOMEM;
        }
        proc_node->proc_fops = &osf_flowtab_fops;
        proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
        proc_node->uid = 0;
        proc_node->gid = 0;
        proc_node->size = OSF_SZ_FLOW_ENTRIES;
    }

    /* get packet arrival timestamps */
    net_enable_timestamp();

    return 0;
}

/* clean up routine for flow monitoring */
void osf_flowmon_cleanup(void)
{
    int i;

    net_disable_timestamp();

    /* destroy each table file we created */
    for (i = pna_tables - 1; i >= 0; i--) {
        if (osf_flowtab_info[i].table_name[0] != '\0') {
            remove_proc_entry(osf_flowtab_info[i].table_name, proc_parent);
        }
        if (osf_flowtab_info[i].table_base != NULL) {
            vfree(osf_flowtab_info[i].table_base);
        }
    }
    /* free up table meta-information struct */
    vfree(osf_flowtab_info);
    /* destroy /proc directory */
    remove_proc_entry(OSF_PROCDIR, NULL);
	db_loaded = unload_db();
}

//Performs the rtmon-style clean operation, which is different
//from the flowmon-style one.
void osf_flowtab_safeclean(void)
{
	return;
	int i;
	for(i = pna_tables - 1; i >=0; i--) {
		memset(osf_flowtab_info[i].table_base, 0, OSF_SZ_FLOW_ENTRIES);
	}
}
