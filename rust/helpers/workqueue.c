// SPDX-License-Identifier: GPL-2.0

#include <linux/workqueue.h>

void rust_helper_init_work_with_key(struct work_struct *work, work_func_t func,
				    bool onstack, const char *name,
				    struct lock_class_key *key)
{
	__init_work(work, onstack);
	work->data = (atomic_long_t)WORK_DATA_INIT();
	lockdep_init_map(&work->lockdep_map, name, key, 0);
	INIT_LIST_HEAD(&work->entry);
	work->func = func;
}

struct workqueue_struct *
rust_helper_alloc_freezable_cpu_intensive_workqueue(const char *name)
{
	return alloc_workqueue("%s",
			       WQ_FREEZABLE | WQ_CPU_INTENSIVE | WQ_PERCPU,
			       0, name);
}
