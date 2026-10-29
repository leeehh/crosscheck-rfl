// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/regmap.h>

struct regmap *
rust_helper_syscon_regmap_lookup_by_phandle(struct device *dev,
					    const char *property)
{
	if (!dev->of_node)
		return ERR_PTR(-ENODEV);

	return syscon_regmap_lookup_by_phandle(dev->of_node, property);
}

struct regmap *rust_helper_syscon_node_to_regmap_parent(struct device *dev)
{
	if (!dev->parent || !dev->parent->of_node)
		return ERR_PTR(-ENODEV);

	return syscon_node_to_regmap(dev->parent->of_node);
}

int rust_helper_regmap_update_bits(struct regmap *map, unsigned int reg,
				   unsigned int mask, unsigned int val)
{
	return regmap_update_bits(map, reg, mask, val);
}
