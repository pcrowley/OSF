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
#ifndef OSF_H
#define OSF_H

//Type definitions for fixed-width data (kernel)
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

struct osf_print{
	//Fingerprint info, 27 bytes
	u8		done;//Flag set to 1 if log is complete, 0 if empty
	u32		src_ip;//Source IP
	u32		dst_ip;//Destination IP
	u16		opt_hash;//Should never exceed 12800
	u32		quirks;//Set of 17 quirk flags.
	u8		opt_eol_pad;//Amount of bytes past EOL, 40 max
	u8		ip_opt_len;//Length of IP options
	u8		ip_version;//0=any, 4=IPv4, 6=IPv6
	u8		ttl;//Time to live
	u16		mss;//Max segment size, max 65535
	u16		win;//Window size, max 65535
	u8		win_type;//Window type, explained below
	u8		win_scale;//Window scaling, max 255
	u8		pay_class;//0 = any, 1 = No data, 2 = data
	u32		ts1;
	u32		ts2;
	u8		wildcards;//Set of wildcards for above values, see below
	u32		unix_time;//If this doesn't work, change to u64?
	char	os_type;
	char	os_class[5];
	char	os_name[20];
	char	os_flavor[20];
//Window type:
/*
	0=Wildcard.  The value for win can be anything.
	1=Direct value.  The value used for win is exact.
	2=Multiple of MSS.  Actual window is = win * mss.
	3=Multiple of MTU.  Actual window is = win * mtu.
	MTU should never come up.
	4=Multiple of a fixed value.  Actual window % win = 0.
*/
//Wildcards:
/*
	A set of flags for the values that can be wildarded,
	organized by bits:
	1=mss
	2=win_scale
*/
};

struct osf_control{
	unsigned int num_log_entries;//The number of entries to be kept in the log
	unsigned int num_db_entries;//The number of entries to be kept in the database
	unsigned int cur_db_entries;//Current number of entries loaded into database
	unsigned int next_log;//Next log to be written
	unsigned int missed_logs;//Number of logs missed due to the log being full
};

//OSF rtmon function definitions:
int osf_init(void);
int osf_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
			 unsigned long data);
void osf_clean(void);
void osf_release(void);

//OSF Defines
#define OSF_PROC_LOG "osf_log"
#define OSF_PROC_DB  "osf_db"
#define OSF_PROC_CHANGE "osf_change"
#define OSF_PROC_READ "osf_read"
#define OSF_LOG_ENTRIES	1 << 16
#define OSF_DB_ENTRIES 1 << 16
#define OSF_LOG_SIZE	(sizeof(struct osf_print) * OSF_LOG_ENTRIES)
#define OSF_DB_SIZE		(sizeof(struct osf_print) * OSF_DB_ENTRIES)
#define MATCH_SIZE 46

#endif
