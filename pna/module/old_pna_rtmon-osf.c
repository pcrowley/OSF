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

/* some real-time monitors (connections and local ips) */
/* functions: osfmon_init, osfmon_hook, osfmon_clean, osfmon_release */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>

//For the terrible file I/O I'm doing
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>

#include <linux/tcp.h>
#include <net/ip.h>
//#include <netinet/tcp.h>

#include "pna.h"
#include "pna_osf.h"

void osfmon_clean(void);
struct osfmon_entry *osfmontab;
#define PNA_osfmon_BITS 17
#define PNA_osfmon_ENTRIES (1 << PNA_osfmon_BITS)
#define PNA_osfmon_TABLE_SZ (PNA_osfmon_ENTRIES*sizeof(struct osfmon_entry))

#define PNA_NEW_FLOW 0x01
#define PNA_NEW_CON  0x02

/* in-file prototypes */
static void osfmon_check(void);

//File I/O for log
static void write_file(char *filename, void *data, int size)
{
	struct file *file;
	loff_t pos = 0;
	int fd;
	
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = 1;
	//fd = sys_open(filename, O_WRONLY|O_CREAT, 0644);
	if(fd >= 0) {
		//sys_write(fd, data, strlen(data));
		file = filp_open(filename, O_WRONLY|O_CREAT|O_APPEND, 0644);
		if(file) {
			vfs_write(file, data, size, &pos);
			fput(file);
		}
		if(file_count(file)){
		filp_close(file, NULL);
		}
		//sys_close(fd);
	}
	set_fs(old_fs);
}

/* helper function to translate l4 protocol values to pna index */
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

/*
 * Local IP monitors
 */
int osfmon_init(void)
{
    /* allocate memory for osfmontab */
    osfmontab = vmalloc(PNA_osfmon_TABLE_SZ);
    if (!osfmontab) {
        pr_err("insufficient memory for osfmon (%ld)", PNA_osfmon_TABLE_SZ);
        return -ENOMEM;
    }

    /* make sure memory is clean */
    osfmon_clean();

    return 0;
}

/* insert/update entry for osfmontab */
static struct osfmon_entry *osfmontab_insert(struct pna_flowkey *key)
{
    unsigned int i;
    unsigned int hash, hash_0, hash_1;
    struct osfmon_entry *sig;
    hash_0 = hash_32(key->local_ip, PNA_osfmon_BITS);
    hash_1 = pna_hash(key->local_ip, PNA_osfmon_BITS);

    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* double hashing for entry */
        hash = (hash_0 + i*hash_1) & (PNA_osfmon_ENTRIES-1);

        /* start testing the waters */
        sig = &osfmontab[hash];

        /* check if IP is clear */
        if (0 == sig->local_ip) {
            /* set up entry and return it */
            sig->local_ip = key->local_ip;
            return sig;
        }
    }
   
    return NULL;
}

/* check a osfmon entry for threshold violations */
static void osfmon_check(void)
{
	pna_alert_warn(88, 88, 88);
	return;
	//No alert system for now.
}

//All TCP Options
unsigned int get_opt_hash(struct tcphdr *tcp){
	int end = (tcp->doff - 5) * 4;
	int sum = 0;
	char *ptr = (char *)tcp;
	ptr = ptr + 20;
	int i;
	for(i=0 ; i<end ; i++){
		sum = sum + (int) *ptr;
		ptr++;
	}
	return sum;
}

//All TCP Options, some of the flags
unsigned int get_quirks(struct tcphdr *tcp){
	return 88;
}

//All TCP Options, d_off value
unsigned short get_opt_eol_pad(struct tcphdr *tcp){
	return 88;
}

//Complete
unsigned short get_ip_opt_len(struct iphdr *ip){
	return ip->tot_len - 5;
}

//Complete
short get_ip_ver(struct iphdr *ip){
	return ip->protocol;
}

//Complete
unsigned short get_ttl(struct iphdr *ip){
	return ip->ttl;
}

//MSS is a TCP option
int get_mss(struct tcphdr *tcp){
	return 88;
}

//Complete
unsigned int get_win(struct tcphdr *tcp){
	return tcp->window;
}

//This function/value should be changed to reflect multiples
//of MSS and MTU somehow.  Considering only 1 fingerprint out of
//all of p0f's database uses MTU multiples, I'm thinking about
//using this field as a MSS multiple.
unsigned short get_win_type(struct tcphdr *tcp){
	return 88;
}

//Window scaling is another TCP Option
int get_wscale(struct tcphdr *tcp){
	return 88;
}

//Payload classification is -1 if wildcard, 0 if zero, and >0 if positive
//Probably going to need TCP and IP header length, subtract from something
//in skb.
short get_pay_class(struct tcphdr *tcp){
	return 0;
}

//This is used as an intermediate part of the signature generation in p0f.
//I may omit it, since I have the TCP/IP info available in tcp and ip and
//skb.
unsigned int get_tot_hdr(struct tcphdr *tcp){
	return 88;
}

//Timestamp info in p0f, we store it elsewhere, so we can get rid of it.
unsigned int get_ts1(struct tcphdr *tcp){
	return 88;
}

//This value is in the signature struct for p0f, but it actually isn't used
//anywhere, which I find to be extraordinarily strange.  Maybe it's used
//higher up in the p0f code, and I haven't noticed it yet.
unsigned int get_recv_ms(struct tcphdr *tcp){
	return 88;
}
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
int osfmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
                unsigned long *data)
{
	struct osfmon_entry *sig_ent;
	int *int_data = (int *)data;
    struct timeval tv;
    int protocol = protocol_map2(key->l4_protocol); 

	    /* get entry */
    sig_ent = osfmontab_insert(key);
	//key->osf_record = sig_ent;
    if (!sig_ent || protocol < 0) {
        return -1;
    }
	
	sig_ent->tcp_sig.opt_hash = 88;
	sig_ent->tcp_mat.type = 'f';
	struct tcphdr *tcp;
	struct iphdr *ip;
	struct tcphdr _tcph;
	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
	ip = (struct iphdr *)skb_network_header(skb);
	if(!tcp)
		return -1;
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
	//Match function here
	write_file("/tmp/osf", sig_ent, sizeof(struct osfmon_entry));
	//if(!tcp->syn)
	//	return -1;
	return -1;


	
    osfmon_check();
	//key->osf_record = sig_ent;
    return 0;
}

void osfmon_clean(void)
{
    memset(osfmontab, 0, PNA_osfmon_TABLE_SZ);
}

void osfmon_release(void)
{
    vfree(osfmontab);
}
