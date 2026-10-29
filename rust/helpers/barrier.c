// SPDX-License-Identifier: GPL-2.0

#include <asm/barrier.h>

void rust_helper_mb(void)
{
	/* Preserve the mandatory ordering promised by the Rust wrapper. */
	mb();
}

void rust_helper_wmb(void)
{
	/* Preserve the mandatory write ordering promised by the Rust wrapper. */
	wmb();
}

void rust_helper_rmb(void)
{
	/* Preserve the mandatory read ordering promised by the Rust wrapper. */
	rmb();
}

void rust_helper_dma_rmb(void)
{
	dma_rmb();
}

void rust_helper_dma_wmb(void)
{
	dma_wmb();
}

void rust_helper_smp_mb(void)
{
	smp_mb();
}

void rust_helper_smp_wmb(void)
{
	smp_wmb();
}

void rust_helper_smp_rmb(void)
{
	smp_rmb();
}
