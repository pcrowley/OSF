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

/* real-time hook system */
/* @functions: rtmon_init, rtmon_hook, rtmon_clean, rtmon_release */

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "pna.h"
#include "osf.h"

/* in-file prototypes */
static void rtmon_clean(unsigned long data);

/*
 * @init: initialization routine for a hook
 * @hook: hook function called on every packet
 * @clean: clean function called periodically to reset tables/counters
 * @release: take-down function for table data and cleanup
 */
struct pna_rtmon {
    int (*init)(void);
    int (*hook)(struct pna_flowkey *, int, struct sk_buff *, unsigned long *);
    void (*clean)(void);
    void (*release)(void);
};

/* a NULL .hook signals the end-of-list */
struct pna_rtmon monitors[] = {
    { .init = conmon_init, .hook = conmon_hook,
      .clean = conmon_clean, .release = conmon_release },
    { .init = lipmon_init, .hook = lipmon_hook,
      .clean = lipmon_clean, .release = lipmon_release },
	/* OSF monitor functions */
	{ .init = osf_init, .hook = osf_hook,
	  .clean = osf_clean, .release = osf_release },
    /* NULL hook entry is end of list delimited */
    { .init = NULL, .hook = NULL, .clean = NULL, .release = NULL }
};

/* timer for calling clean function */
DEFINE_TIMER(clean_timer, rtmon_clean, 0, 0);

/* reset each rtmon for next round of processing -- once per */
static void rtmon_clean(unsigned long data)
{
    struct pna_rtmon *monitor;

    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        monitor->clean();
    }

    /* update the timer for the next round */
    mod_timer(&clean_timer, jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL));
}

/* hook from main on packet to start real-time monitoring */
int rtmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
               unsigned long data)
{
    int ret;

    struct pna_rtmon *monitor;
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        ret = monitor->hook(key, direction, skb, &data);
    }
    return 0;
}

/* initialize all the resources needed for each rtmon */
int rtmon_init(void)
{
    int ret = 0;

    struct pna_rtmon *monitor;
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        ret += monitor->init();
    }

    /* initialize/correct timer */
    init_timer(&clean_timer);
    clean_timer.expires = jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL);
    add_timer(&clean_timer);

    return ret;
}

/* release the resources each rtmon is using */
void rtmon_release(void)
{
    struct pna_rtmon *monitor;

    /* remove the timer */
    del_timer(&clean_timer);

    /* clean up each of the monitors */
    for (monitor = &monitors[0]; monitor->hook != NULL; monitor++) {
        monitor->release();
    }
}
