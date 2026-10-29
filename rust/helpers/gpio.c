// SPDX-License-Identifier: GPL-2.0

#include <linux/bug.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/driver.h>

#ifdef CONFIG_MIKROTIK_RB532
#include <asm/mach-rc32434/gpio.h>
#include <asm/mach-rc32434/rb.h>
#endif

struct gpio_desc *rust_helper_devm_gpiod_get(struct device *dev,
					     const char *con_id,
					     unsigned int flags)
{
	return devm_gpiod_get(dev, con_id, (enum gpiod_flags)flags);
}

struct gpio_desc *rust_helper_devm_gpiod_get_optional(struct device *dev,
						      const char *con_id,
						      unsigned int flags)
{
	return devm_gpiod_get_optional(dev, con_id, (enum gpiod_flags)flags);
}

struct gpio_desc *rust_helper_devm_fwnode_gpiod_get(struct device *dev,
						    struct fwnode_handle *fwnode,
						    const char *con_id,
						    unsigned int flags,
						    const char *label)
{
	return devm_fwnode_gpiod_get(dev, fwnode, con_id,
				     (enum gpiod_flags)flags, label);
}

int rust_helper_gpiod_direction_output(struct gpio_desc *desc, int value)
{
	return gpiod_direction_output(desc, value);
}

int rust_helper_gpiod_get_value_cansleep(const struct gpio_desc *desc)
{
	return gpiod_get_value_cansleep(desc);
}

int rust_helper_gpiod_set_value(struct gpio_desc *desc, int value)
{
	return gpiod_set_value(desc, value);
}

int rust_helper_gpiod_set_value_cansleep(struct gpio_desc *desc, int value)
{
	return gpiod_set_value_cansleep(desc, value);
}

int rust_helper_gpiod_to_irq(const struct gpio_desc *desc)
{
	return gpiod_to_irq(desc);
}

int rust_helper_gpio_direction_input(unsigned int gpio)
{
	return gpio_direction_input(gpio);
}

int rust_helper_gpio_get_value(unsigned int gpio)
{
	return gpio_get_value(gpio);
}

void rust_helper_gpio_irq_chip_set_chip(struct gpio_irq_chip *girq,
					const struct irq_chip *chip)
{
	gpio_irq_chip_set_chip(girq, chip);
}

void rust_helper_rb532_gpio_set_func(unsigned int gpio)
{
#ifdef CONFIG_MIKROTIK_RB532
	rb532_gpio_set_func(gpio);
#else
	WARN_ONCE(1, "rb532_gpio_set_func called without CONFIG_MIKROTIK_RB532\n");
#endif
}

void rust_helper_set_latch_u5(unsigned int set, unsigned int clear)
{
#ifdef CONFIG_MIKROTIK_RB532
	set_latch_u5(set, clear);
#else
	WARN_ONCE(1, "set_latch_u5 called without CONFIG_MIKROTIK_RB532\n");
#endif
}
