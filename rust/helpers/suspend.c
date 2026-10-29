// SPDX-License-Identifier: GPL-2.0

#include <linux/suspend.h>

bool rust_helper_pm_suspend_via_firmware(void)
{
	return pm_suspend_via_firmware();
}
