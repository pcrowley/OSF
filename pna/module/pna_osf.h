#ifndef _PNA_OSF_H
#define _PNA_OSF_H

int osf_flowtab_open(struct inode *inode, struct file *filep);
int osf_flowtab_release(struct inode *inode, struct file *filep);
int osf_flowtab_release_all(void);
int osf_flowtab_mmap(struct file *filep, struct vm_area_struct *vma);
void osf_flowtab_clean(struct osf_flowtab_info *info);
void osf_flowtab_safeclean(void);
struct osf_flowtab_info *osf_flowtab_get(struct timeval *timeval);
int osf_flowkey_match(struct osfmon_entry *key_a, struct osfmon_entry *key_b);
int osf_flowmon_init(void);
void osf_flowmon_cleanup(void);
int osf_flowmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb);
#define osf_tables 1
#endif