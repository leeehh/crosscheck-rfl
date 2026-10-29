// SPDX-License-Identifier: GPL-2.0

#include <linux/cpumask.h>
#include <linux/cpuhotplug.h>
#include <linux/smp.h>

unsigned int rust_helper_raw_smp_processor_id(void)
{
	return raw_smp_processor_id();
}

unsigned int rust_helper_num_online_cpus(void)
{
	return num_online_cpus();
}

void rust_helper_cpus_read_lock_compat(void)
{
	cpus_read_lock();
}

void rust_helper_cpus_read_unlock_compat(void)
{
	cpus_read_unlock();
}

int rust_helper_cpuhp_setup_state_multi(enum cpuhp_state state,
					const char *name,
					void *startup, void *teardown)
{
	return cpuhp_setup_state_multi(state, name,
		(int (*)(unsigned int, struct hlist_node *))startup,
		(int (*)(unsigned int, struct hlist_node *))teardown);
}

void rust_helper_cpuhp_remove_multi_state(enum cpuhp_state state)
{
	cpuhp_remove_multi_state(state);
}

int rust_helper_cpuhp_state_add_instance_nocalls(enum cpuhp_state state,
						 struct hlist_node *node)
{
	return cpuhp_state_add_instance_nocalls(state, node);
}

int rust_helper_cpuhp_state_remove_instance_nocalls(enum cpuhp_state state,
						    struct hlist_node *node)
{
	return cpuhp_state_remove_instance_nocalls(state, node);
}
