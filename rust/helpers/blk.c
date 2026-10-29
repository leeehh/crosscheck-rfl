// SPDX-License-Identifier: GPL-2.0

#include <linux/blk-mq.h>
#include <linux/blk-mq-dma.h>
#include <linux/blk-integrity.h>
#include <linux/blkdev.h>

void *rust_helper_blk_mq_rq_to_pdu(struct request *rq)
{
	return blk_mq_rq_to_pdu(rq);
}

struct request *rust_helper_blk_mq_rq_from_pdu(void *pdu)
{
	return blk_mq_rq_from_pdu(pdu);
}

unsigned int rust_helper_req_op(const struct request *req)
{
	return req_op(req);
}

int rust_helper_rq_data_dir(const struct request *rq)
{
	return rq_data_dir(rq);
}

sector_t rust_helper_blk_rq_pos(const struct request *rq)
{
	return blk_rq_pos(rq);
}

unsigned short rust_helper_blk_rq_nr_phys_segments(struct request *rq)
{
	return blk_rq_nr_phys_segments(rq);
}

unsigned int rust_helper_blk_rq_payload_bytes(struct request *rq)
{
	return blk_rq_payload_bytes(rq);
}

int rust_helper_blk_rq_map_sg(struct request *rq, struct scatterlist *sglist)
{
	return blk_rq_map_sg(rq, sglist);
}

bool rust_helper_blk_should_fake_timeout(struct request_queue *q)
{
	return blk_should_fake_timeout(q);
}

bool rust_helper_blk_mq_add_to_batch(struct request *req,
				     struct io_comp_batch *batch,
				     bool is_error,
				     void (*complete)(struct io_comp_batch *))
{
	return blk_mq_add_to_batch(req, batch, is_error, complete);
}

bool rust_helper_blk_rq_dma_map_coalesce(struct dma_iova_state *state)
{
	return blk_rq_dma_map_coalesce(state);
}

bool rust_helper_blk_rq_dma_unmap(struct request *req, struct device *dev,
				  struct dma_iova_state *state,
				  size_t mapped_len,
				  enum pci_p2pdma_map_type map)
{
	return blk_rq_dma_unmap(req, dev, state, mapped_len, map);
}

enum dma_data_direction rust_helper_rq_dma_dir(struct request *req)
{
	return rq_dma_dir(req);
}

unsigned long rust_helper_req_phys_gap_mask(const struct request *req)
{
	return req_phys_gap_mask(req);
}

bool rust_helper_blk_integrity_rq(struct request *req)
{
	return blk_integrity_rq(req);
}

struct bio_vec rust_helper_req_bvec(struct request *req)
{
	return req_bvec(req);
}

struct bio_vec rust_helper_rq_integrity_vec(struct request *req)
{
	return rq_integrity_vec(req);
}
