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
/* functions: null_hook, null_clean */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include "pna.h"
#include "pna_module.h"

static int null_init(void);
static void null_release(void);
static int null_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void null_clean(void);

struct pna_rtmon null = {
    .name = "Null monitor",
    .init = null_init,       /**< allocate resource on load */
    .hook = null_hook,       /**< called for every packet PNA sees */
    .clean = null_clean,     /**< periodic maintenance callback */
    .release = null_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
PNA_MONITOR(&null);

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */

#define PROC_NAME "null"
int path_len;
char path[MAX_STR];
static const struct file_operations null_fops = {
    .owner   = THIS_MODULE,
};


/**
 * PNA null monitor hook
 */
static int null_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
    return 0;
}

static void null_clean(void)
{
    pna_info("pna_null: periodic callback\n");
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

static int null_init(void)
{
	printk("Null monitor initialized\n");
    return 0;
}

static void null_release(void)
{
	printk("Null monitor released\n");
}
