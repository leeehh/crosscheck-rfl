// SPDX-License-Identifier: GPL-2.0

#include <linux/acpi.h>
#include <linux/gpio/consumer.h>

struct acpi_device *rust_helper_acpi_companion(struct device *dev)
{
	return ACPI_COMPANION(dev);
}

int rust_helper_devm_acpi_dev_add_driver_gpios(
	struct device *dev, const struct acpi_gpio_mapping *gpios)
{
	return devm_acpi_dev_add_driver_gpios(dev, gpios);
}

int rust_helper_acpi_dev_gpio_irq_get_by(struct acpi_device *adev,
					 const char *con_id, int index)
{
	return acpi_dev_gpio_irq_get_by(adev, con_id, index);
}
