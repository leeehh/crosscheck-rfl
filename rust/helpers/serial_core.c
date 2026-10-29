// SPDX-License-Identifier: GPL-2.0

#include <linux/serial_core.h>

void rust_helper_uart_port_lock(struct uart_port *up)
{
	uart_port_lock(up);
}

void rust_helper_uart_port_unlock(struct uart_port *up)
{
	uart_port_unlock(up);
}

void rust_helper_uart_port_lock_irqsave(struct uart_port *up, unsigned long *flags)
{
	uart_port_lock_irqsave(up, flags);
}

void rust_helper_uart_port_unlock_irqrestore(struct uart_port *up, unsigned long flags)
{
	uart_port_unlock_irqrestore(up, flags);
}

/*
 * Drives the serial-core TX pump (the `uart_port_tx` macro cannot be called
 * from Rust). `tx_ready` reports whether the HW can accept another byte and
 * `put_char` writes one byte to the HW; both are Rust trampolines. Returns the
 * number of bytes still pending in the xmit FIFO.
 */
unsigned int rust_helper_uart_port_tx(struct uart_port *port,
				      bool (*tx_ready)(struct uart_port *),
				      void (*put_char)(struct uart_port *, unsigned char))
{
	unsigned char ch;

	return uart_port_tx(port, ch, tx_ready(port), put_char(port, ch));
}
