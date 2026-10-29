// SPDX-License-Identifier: GPL-2.0

#include <linux/mii.h>
#include <linux/phy.h>

void rust_helper_mii_lpa_to_phy_lp_advertising(struct phy_device *phydev,
					       u32 lpa)
{
	mii_lpa_to_linkmode_lpa_t(phydev->lp_advertising, lpa);
}

void rust_helper_phy_lp_advertising_zero(struct phy_device *phydev)
{
	linkmode_zero(phydev->lp_advertising);
}
