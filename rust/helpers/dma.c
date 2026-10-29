// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-mapping.h>
#include <linux/pci-p2pdma.h>

void *rust_helper_dma_alloc_attrs(struct device *dev, size_t size,
				  dma_addr_t *dma_handle, gfp_t flag,
				  unsigned long attrs)
{
	return dma_alloc_attrs(dev, size, dma_handle, flag, attrs);
}

void rust_helper_dma_free_attrs(struct device *dev, size_t size, void *cpu_addr,
				dma_addr_t dma_handle, unsigned long attrs)
{
	dma_free_attrs(dev, size, cpu_addr, dma_handle, attrs);
}

int rust_helper_dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	return dma_set_mask_and_coherent(dev, mask);
}

int rust_helper_dma_set_mask(struct device *dev, u64 mask)
{
	return dma_set_mask(dev, mask);
}

int rust_helper_dma_set_coherent_mask(struct device *dev, u64 mask)
{
	return dma_set_coherent_mask(dev, mask);
}

void rust_helper_dma_set_min_align_mask(struct device *dev,
					unsigned int mask)
{
	dma_set_min_align_mask(dev, mask);
}

void rust_helper_dma_set_max_seg_size(struct device *dev, unsigned int size)
{
	dma_set_max_seg_size(dev, size);
}

int rust_helper_dma_map_sgtable(struct device *dev, struct sg_table *sgt,
				enum dma_data_direction dir, unsigned long attrs)
{
	return dma_map_sgtable(dev, sgt, dir, attrs);
}

size_t rust_helper_dma_max_mapping_size(struct device *dev)
{
	return dma_max_mapping_size(dev);
}

size_t rust_helper_dma_opt_mapping_size(struct device *dev)
{
	return dma_opt_mapping_size(dev);
}

unsigned long rust_helper_dma_get_merge_boundary(struct device *dev)
{
	return dma_get_merge_boundary(dev);
}

bool rust_helper_dma_use_iova(struct dma_iova_state *state)
{
	return dma_use_iova(state);
}

bool rust_helper_dma_need_unmap(struct device *dev)
{
	return dma_need_unmap(dev);
}

int rust_helper_dma_mapping_error(struct device *dev, dma_addr_t address)
{
	return dma_mapping_error(dev, address);
}

dma_addr_t rust_helper_dma_map_bvec(struct device *dev, struct bio_vec *vec,
				    enum dma_data_direction direction,
				    unsigned long attrs)
{
	return dma_map_bvec(dev, vec, direction, attrs);
}

bool rust_helper_bvec_is_pci_p2pdma(const struct bio_vec *vec)
{
	return is_pci_p2pdma_page(vec->bv_page);
}

void rust_helper_dma_unmap_page(struct device *dev, dma_addr_t address,
				unsigned int size,
				enum dma_data_direction direction,
				unsigned long attrs)
{
	dma_unmap_page_attrs(dev, address, size, direction, attrs);
}

void rust_helper_dma_unmap_phys(struct device *dev, dma_addr_t address,
				size_t size, enum dma_data_direction direction,
				unsigned long attrs)
{
	dma_unmap_phys(dev, address, size, direction, attrs);
}
