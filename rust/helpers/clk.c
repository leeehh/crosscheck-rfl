// SPDX-License-Identifier: GPL-2.0

#include <linux/clk.h>
#include <linux/clk-provider.h>

/*
 * The "inline" implementation of below helpers are only available when
 * CONFIG_HAVE_CLK or CONFIG_HAVE_CLK_PREPARE aren't set.
 */
#ifndef CONFIG_HAVE_CLK
struct clk *rust_helper_clk_get(struct device *dev, const char *id)
{
	return clk_get(dev, id);
}

void rust_helper_clk_put(struct clk *clk)
{
	clk_put(clk);
}

int rust_helper_clk_enable(struct clk *clk)
{
	return clk_enable(clk);
}

void rust_helper_clk_disable(struct clk *clk)
{
	clk_disable(clk);
}

unsigned long rust_helper_clk_get_rate(struct clk *clk)
{
	return clk_get_rate(clk);
}

int rust_helper_clk_set_rate(struct clk *clk, unsigned long rate)
{
	return clk_set_rate(clk, rate);
}
#endif

#ifndef CONFIG_HAVE_CLK_PREPARE
int rust_helper_clk_prepare(struct clk *clk)
{
	return clk_prepare(clk);
}

void rust_helper_clk_unprepare(struct clk *clk)
{
	clk_unprepare(clk);
}
#endif

struct clk *rust_helper_clk_get_optional(struct device *dev, const char *id)
{
	return clk_get_optional(dev, id);
}

int rust_helper_clk_prepare_enable(struct clk *clk)
{
	return clk_prepare_enable(clk);
}

void rust_helper_clk_disable_unprepare(struct clk *clk)
{
	clk_disable_unprepare(clk);
}

struct clk_hw *rust_helper_clk_hw_register_fixed_rate_with_accuracy(
	struct device *dev, const char *name, const char *parent_name,
	unsigned long flags, unsigned long fixed_rate,
	unsigned long fixed_accuracy)
{
	return clk_hw_register_fixed_rate_with_accuracy(dev, name, parent_name,
						       flags, fixed_rate,
						       fixed_accuracy);
}

void rust_helper_clk_hw_unregister_fixed_rate(struct clk_hw *hw)
{
	clk_hw_unregister_fixed_rate(hw);
}

int rust_helper_of_clk_add_hw_provider_simple(struct device_node *np,
					      struct clk_hw *hw)
{
	return of_clk_add_hw_provider(np, of_clk_hw_simple_get, hw);
}

void rust_helper_of_clk_del_provider(struct device_node *np)
{
	of_clk_del_provider(np);
}

struct clk_hw *rust_helper_devm_clk_hw_register_gate(
	struct device *dev, const char *name, const char *parent_name,
	unsigned long flags, void __iomem *reg, u8 bit_idx,
	u8 clk_gate_flags)
{
	return devm_clk_hw_register_gate(dev, name, parent_name, flags, reg,
					 bit_idx, clk_gate_flags, NULL);
}
