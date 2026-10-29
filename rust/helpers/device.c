// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/pm_wakeirq.h>
#include <linux/pm_wakeup.h>

int rust_helper_devm_add_action(struct device *dev,
				void (*action)(void *),
				void *data)
{
	return devm_add_action(dev, action, data);
}

int rust_helper_devm_add_action_or_reset(struct device *dev,
					 void (*action)(void *),
					 void *data)
{
	return devm_add_action_or_reset(dev, action, data);
}

void *rust_helper_dev_get_drvdata(const struct device *dev)
{
	return dev_get_drvdata(dev);
}

void rust_helper_dev_set_drvdata(struct device *dev, void *data)
{
	dev_set_drvdata(dev, data);
}

int rust_helper_device_err_probe(const struct device *dev, int err,
				 const char *msg)
{
	return dev_err_probe(dev, err, "%s", msg);
}

int rust_helper_device_init_wakeup(struct device *dev, bool enable)
{
	return device_init_wakeup(dev, enable);
}

bool rust_helper_device_may_wakeup(struct device *dev)
{
	return device_may_wakeup(dev);
}

int rust_helper_dev_pm_set_wake_irq(struct device *dev, int irq)
{
	return dev_pm_set_wake_irq(dev, irq);
}

void rust_helper_device_set_wakeup_path(struct device *dev)
{
	device_set_wakeup_path(dev);
}

int rust_helper_dev_to_node(struct device *dev)
{
	return dev_to_node(dev);
}
