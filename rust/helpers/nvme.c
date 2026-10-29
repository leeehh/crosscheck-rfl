// SPDX-License-Identifier: GPL-2.0

#include "../../drivers/nvme/host/nvme.h"

u16 rust_helper_nvme_cid(struct request *req)
{
	return nvme_cid(req);
}

bool rust_helper_nvme_state_terminal(struct nvme_ctrl *ctrl)
{
	return nvme_state_terminal(ctrl);
}

enum nvme_ctrl_state rust_helper_nvme_ctrl_state(struct nvme_ctrl *ctrl)
{
	return nvme_ctrl_state(ctrl);
}

void rust_helper_nvme_put_ctrl(struct nvme_ctrl *ctrl)
{
	nvme_put_ctrl(ctrl);
}

enum req_op rust_helper_nvme_req_op(struct nvme_command *command)
{
	return nvme_req_op(command);
}

bool rust_helper_nvme_is_aen_req(u16 qid, u16 command_id)
{
	return nvme_is_aen_req(qid, command_id);
}

struct request *rust_helper_nvme_find_rq(struct blk_mq_tags *tags,
					 u16 command_id)
{
	return nvme_find_rq(tags, command_id);
}

bool rust_helper_nvme_ctrl_sgl_supported(struct nvme_ctrl *ctrl)
{
	return nvme_ctrl_sgl_supported(ctrl);
}

bool rust_helper_nvme_ctrl_meta_sgl_supported(struct nvme_ctrl *ctrl)
{
	return nvme_ctrl_meta_sgl_supported(ctrl);
}

struct device *rust_helper_nvme_ctrl_device(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->device);
}

struct device *rust_helper_nvme_ctrl_parent_device(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->dev);
}

size_t rust_helper_nvme_ctrl_copy_model(struct nvme_ctrl *ctrl, u8 *buffer,
					size_t capacity)
{
	struct nvme_subsystem *subsys = READ_ONCE(ctrl->subsys);
	size_t length;

	if (!subsys || !capacity)
		return 0;
	length = nvme_strlen(subsys->model, sizeof(subsys->model));
	if (length > capacity)
		length = capacity;
	memcpy(buffer, subsys->model, length);
	return length;
}

size_t rust_helper_nvme_ctrl_copy_firmware_rev(struct nvme_ctrl *ctrl,
					       u8 *buffer, size_t capacity)
{
	struct nvme_subsystem *subsys = READ_ONCE(ctrl->subsys);
	size_t length;

	if (!subsys || !capacity)
		return 0;
	length = nvme_strlen(subsys->firmware_rev,
			     sizeof(subsys->firmware_rev));
	if (length > capacity)
		length = capacity;
	memcpy(buffer, subsys->firmware_rev, length);
	return length;
}

unsigned long rust_helper_nvme_ctrl_quirks(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->quirks);
}

u64 rust_helper_nvme_ctrl_cap(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->cap);
}

void rust_helper_nvme_ctrl_set_cap(struct nvme_ctrl *ctrl, u64 value)
{
	WRITE_ONCE(ctrl->cap, value);
}

u32 rust_helper_nvme_ctrl_config(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->ctrl_config);
}

u32 rust_helper_nvme_ctrl_queue_count(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->queue_count);
}

void rust_helper_nvme_ctrl_set_queue_count(struct nvme_ctrl *ctrl, u32 value)
{
	WRITE_ONCE(ctrl->queue_count, value);
}

u16 rust_helper_nvme_ctrl_sqsize(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->sqsize);
}

void rust_helper_nvme_ctrl_set_sqsize(struct nvme_ctrl *ctrl, u16 value)
{
	WRITE_ONCE(ctrl->sqsize, value);
}

void rust_helper_nvme_ctrl_set_numa_node(struct nvme_ctrl *ctrl, int node)
{
	WRITE_ONCE(ctrl->numa_node, node);
}

int rust_helper_nvme_ctrl_instance(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->instance);
}

void rust_helper_nvme_ctrl_set_max_hw_sectors(struct nvme_ctrl *ctrl,
					      u32 value)
{
	WRITE_ONCE(ctrl->max_hw_sectors, value);
}

void rust_helper_nvme_ctrl_set_max_segments(struct nvme_ctrl *ctrl, u32 value)
{
	WRITE_ONCE(ctrl->max_segments, value);
}

void rust_helper_nvme_ctrl_set_max_integrity_segments(struct nvme_ctrl *ctrl,
						      u32 value)
{
	WRITE_ONCE(ctrl->max_integrity_segments, value);
}

u16 rust_helper_nvme_ctrl_oacs(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->oacs);
}

u8 rust_helper_nvme_ctrl_npss(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->npss);
}

void rust_helper_nvme_ctrl_set_npss(struct nvme_ctrl *ctrl, u8 value)
{
	WRITE_ONCE(ctrl->npss, value);
}

u32 rust_helper_nvme_ctrl_hmpre(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->hmpre);
}

u32 rust_helper_nvme_ctrl_hmmin(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->hmmin);
}

u32 rust_helper_nvme_ctrl_hmminds(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->hmminds);
}

u16 rust_helper_nvme_ctrl_hmmaxd(struct nvme_ctrl *ctrl)
{
	return READ_ONCE(ctrl->hmmaxd);
}

bool rust_helper_nvme_ctrl_has_admin_queue(struct nvme_ctrl *ctrl)
{
	return !!READ_ONCE(ctrl->admin_q);
}

bool rust_helper_nvme_ctrl_has_io_tagset(struct nvme_ctrl *ctrl)
{
	return !!READ_ONCE(ctrl->tagset);
}

bool rust_helper_nvme_ctrl_try_get_abort(struct nvme_ctrl *ctrl)
{
	if (atomic_dec_return(&ctrl->abort_limit) >= 0)
		return true;
	atomic_inc(&ctrl->abort_limit);
	return false;
}

void rust_helper_nvme_ctrl_put_abort(struct nvme_ctrl *ctrl)
{
	atomic_inc(&ctrl->abort_limit);
}

void rust_helper_nvme_ctrl_init_reset_work(struct nvme_ctrl *ctrl,
					   work_func_t callback)
{
	INIT_WORK(&ctrl->reset_work, callback);
}

bool rust_helper_nvme_ctrl_flush_reset_work(struct nvme_ctrl *ctrl)
{
	return flush_work(&ctrl->reset_work);
}

bool rust_helper_nvme_ctrl_flush_scan_work(struct nvme_ctrl *ctrl)
{
	return flush_work(&ctrl->scan_work);
}

void rust_helper_nvme_req_mark_cancelled(struct request *req)
{
	nvme_req(req)->flags |= NVME_REQ_CANCELLED;
}
