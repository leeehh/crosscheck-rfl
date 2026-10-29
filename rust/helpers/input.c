// SPDX-License-Identifier: GPL-2.0

#include <linux/input.h>
#include <linux/input/mt.h>

void rust_helper_input_abs_set_res(struct input_dev *dev, unsigned int axis, int val)
{
	input_abs_set_res(dev, axis, val);
}

int rust_helper_input_abs_get_max(struct input_dev *dev, unsigned int axis)
{
	return input_abs_get_max(dev, axis);
}

int rust_helper_input_mt_init_slots(struct input_dev *dev, unsigned int num_slots,
				    unsigned int flags)
{
	return input_mt_init_slots(dev, num_slots, flags);
}
