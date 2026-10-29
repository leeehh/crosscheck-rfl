// SPDX-License-Identifier: GPL-2.0

#include <linux/reset.h>

struct reset_control *rust_helper_reset_control_devm_get(struct device *dev,
							 const char *id,
							 unsigned int flags)
{
	return __devm_reset_control_get(dev, id, 0,
					(enum reset_control_flags)flags);
}

int rust_helper_reset_control_do_assert(struct reset_control *rstc)
{
	return reset_control_assert(rstc);
}

int rust_helper_reset_control_do_deassert(struct reset_control *rstc)
{
	return reset_control_deassert(rstc);
}

int rust_helper_reset_control_do_reset(struct reset_control *rstc)
{
	return reset_control_reset(rstc);
}
