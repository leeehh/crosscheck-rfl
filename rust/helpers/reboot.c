// SPDX-License-Identifier: GPL-2.0

#include <linux/reboot.h>

struct sys_off_handler *
rust_helper_register_sys_off_handler(int mode, int priority,
				     int (*callback)(struct sys_off_data *data),
				     void *cb_data)
{
	return register_sys_off_handler((enum sys_off_mode)mode, priority,
					callback, cb_data);
}

void rust_helper_unregister_sys_off_handler(struct sys_off_handler *handler)
{
	unregister_sys_off_handler(handler);
}

int rust_helper_devm_register_sys_off_handler(struct device *dev, int mode,
					      int priority,
					      int (*callback)(struct sys_off_data *data),
					      void *cb_data)
{
	return devm_register_sys_off_handler(dev, (enum sys_off_mode)mode,
					     priority, callback, cb_data);
}

void rust_helper_set_reboot_mode(int mode)
{
	reboot_mode = (enum reboot_mode)mode;
}

void rust_helper_reboot_machine_restart(const char *cmd)
{
	machine_restart((char *)cmd);
}
