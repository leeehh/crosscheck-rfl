// SPDX-License-Identifier: GPL-2.0

#include <linux/interrupt.h>
#include <linux/irqdomain.h>

int rust_helper_request_irq(unsigned int irq, irq_handler_t handler,
			    unsigned long flags, const char *name, void *dev)
{
	return request_irq(irq, handler, flags, name, dev);
}

int rust_helper_enable_irq_wake(unsigned int irq)
{
	return enable_irq_wake(irq);
}

int rust_helper_disable_irq_wake(unsigned int irq)
{
	return disable_irq_wake(irq);
}

unsigned int rust_helper_irq_find_mapping(struct irq_domain *domain,
					  irq_hw_number_t hwirq)
{
	return irq_find_mapping(domain, hwirq);
}
