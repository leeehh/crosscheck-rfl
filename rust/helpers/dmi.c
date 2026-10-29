// SPDX-License-Identifier: GPL-2.0

#include <linux/dmi.h>

const struct dmi_system_id *
rust_helper_dmi_first_match(const struct dmi_system_id *list)
{
	return dmi_first_match(list);
}

bool rust_helper_dmi_match(enum dmi_field field, const char *value)
{
	return dmi_match(field, value);
}
