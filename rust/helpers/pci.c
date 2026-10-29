// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>

u16 rust_helper_pci_dev_id(struct pci_dev *dev)
{
	return PCI_DEVID(dev->bus->number, dev->devfn);
}

resource_size_t rust_helper_pci_resource_start(struct pci_dev *pdev, int bar)
{
	return pci_resource_start(pdev, bar);
}

resource_size_t rust_helper_pci_resource_len(struct pci_dev *pdev, int bar)
{
	return pci_resource_len(pdev, bar);
}

bool rust_helper_dev_is_pci(const struct device *dev)
{
	return dev_is_pci(dev);
}

int rust_helper_pci_request_mem_regions(struct pci_dev *pdev,
					const char *name)
{
	return pci_request_mem_regions(pdev, name);
}

void rust_helper_pci_release_mem_regions(struct pci_dev *pdev)
{
	pci_release_mem_regions(pdev);
}

bool rust_helper_pci_is_enabled(struct pci_dev *pdev)
{
	return pci_is_enabled(pdev);
}

resource_size_t rust_helper_pci_bus_address(struct pci_dev *pdev, int bar)
{
	return pci_bus_address(pdev, bar);
}

bool rust_helper_pci_channel_offline(struct pci_dev *pdev)
{
	return pci_channel_offline(pdev);
}

bool rust_helper_pci_dev_is_disconnected(struct pci_dev *pdev)
{
	return pci_dev_is_disconnected(pdev);
}

#ifndef CONFIG_PCI_MSI
int rust_helper_pci_alloc_irq_vectors(struct pci_dev *dev,
				      unsigned int min_vecs,
				      unsigned int max_vecs,
				      unsigned int flags)
{
	return pci_alloc_irq_vectors(dev, min_vecs, max_vecs, flags);
}

int rust_helper_pci_alloc_irq_vectors_affinity(struct pci_dev *dev,
					       unsigned int min_vecs,
					       unsigned int max_vecs,
					       unsigned int flags,
					       struct irq_affinity *affd)
{
	return pci_alloc_irq_vectors_affinity(dev, min_vecs, max_vecs,
					      flags, affd);
}

void rust_helper_pci_free_irq_vectors(struct pci_dev *dev)
{
	pci_free_irq_vectors(dev);
}

int rust_helper_pci_irq_vector(struct pci_dev *pdev, unsigned int nvec)
{
	return pci_irq_vector(pdev, nvec);
}
#endif
