// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/of_regulator.h>

#ifndef CONFIG_REGULATOR

void rust_helper_regulator_put(struct regulator *regulator)
{
	regulator_put(regulator);
}

int rust_helper_regulator_set_voltage(struct regulator *regulator, int min_uV,
				      int max_uV)
{
	return regulator_set_voltage(regulator, min_uV, max_uV);
}

int rust_helper_regulator_get_voltage(struct regulator *regulator)
{
	return regulator_get_voltage(regulator);
}

struct regulator *rust_helper_regulator_get(struct device *dev, const char *id)
{
	return regulator_get(dev, id);
}

int rust_helper_regulator_enable(struct regulator *regulator)
{
	return regulator_enable(regulator);
}

int rust_helper_regulator_disable(struct regulator *regulator)
{
	return regulator_disable(regulator);
}

int rust_helper_regulator_is_enabled(struct regulator *regulator)
{
	return regulator_is_enabled(regulator);
}

int rust_helper_devm_regulator_get_enable(struct device *dev, const char *id)
{
	return devm_regulator_get_enable(dev, id);
}

int rust_helper_devm_regulator_get_enable_optional(struct device *dev, const char *id)
{
	return devm_regulator_get_enable_optional(dev, id);
}

#endif

struct regulator_init_data *rust_helper_regulator_of_get_init_data(
	struct device *dev, struct device_node *node,
	const struct regulator_desc *desc)
{
#if defined(CONFIG_OF)
	return of_get_regulator_init_data(dev, node, desc);
#else
	return NULL;
#endif
}

struct regulator_dev *rust_helper_regulator_devm_register(
	struct device *dev, const struct regulator_desc *desc,
	const struct regulator_config *config)
{
#ifdef CONFIG_REGULATOR
	return devm_regulator_register(dev, desc, config);
#else
	return ERR_PTR(-ENODEV);
#endif
}

int rust_helper_regulator_notify(struct regulator_dev *rdev,
				 unsigned long event, void *data)
{
#ifdef CONFIG_REGULATOR
	return regulator_notifier_call_chain(rdev, event, data);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_list_voltage_linear(struct regulator_dev *rdev,
						  unsigned int selector)
{
#ifdef CONFIG_REGULATOR
	return regulator_list_voltage_linear(rdev, selector);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_set_voltage_sel_regmap(struct regulator_dev *rdev,
						     unsigned int sel)
{
#ifdef CONFIG_REGULATOR
	return regulator_set_voltage_sel_regmap(rdev, sel);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_get_voltage_sel_regmap(struct regulator_dev *rdev)
{
#ifdef CONFIG_REGULATOR
	return regulator_get_voltage_sel_regmap(rdev);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_enable_regmap(struct regulator_dev *rdev)
{
#ifdef CONFIG_REGULATOR
	return regulator_enable_regmap(rdev);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_disable_regmap(struct regulator_dev *rdev)
{
#ifdef CONFIG_REGULATOR
	return regulator_disable_regmap(rdev);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_is_enabled_regmap(struct regulator_dev *rdev)
{
#ifdef CONFIG_REGULATOR
	return regulator_is_enabled_regmap(rdev);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_set_current_limit_regmap(struct regulator_dev *rdev,
						       int min_uA, int max_uA)
{
#ifdef CONFIG_REGULATOR
	return regulator_set_current_limit_regmap(rdev, min_uA, max_uA);
#else
	return -ENODEV;
#endif
}

int rust_helper_regulator_ops_get_current_limit_regmap(struct regulator_dev *rdev)
{
#ifdef CONFIG_REGULATOR
	return regulator_get_current_limit_regmap(rdev);
#else
	return -ENODEV;
#endif
}
