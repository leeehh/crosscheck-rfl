// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/scatterlist.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>

/* `shost_priv` / `scsi_cmd_priv` / `scsi_add_host` are static inlines; the `scsi_cmnd`
 * accessors (`set_host_byte`, `scsi_set_resid`, `scsi_sglist`, ...) are static inlines too.
 * Wrap them so Rust can call them (mirrors rust/helpers/blk.c). Auto-exported as
 * `rust_helper_*` via exports_helpers_generated.h. */
void *rust_helper_shost_priv(struct Scsi_Host *shost)
{
	return shost_priv(shost);
}

void *rust_helper_scsi_cmd_priv(struct scsi_cmnd *cmd)
{
	return scsi_cmd_priv(cmd);
}

int rust_helper_scsi_add_host(struct Scsi_Host *host, struct device *dev)
{
	return scsi_add_host(host, dev);
}

void rust_helper_set_host_byte(struct scsi_cmnd *cmd, char status)
{
	set_host_byte(cmd, status);
}

void rust_helper_set_status_byte(struct scsi_cmnd *cmd, char status)
{
	set_status_byte(cmd, status);
}

void rust_helper_scsi_set_resid(struct scsi_cmnd *cmd, unsigned int resid)
{
	scsi_set_resid(cmd, resid);
}

unsigned int rust_helper_scsi_sg_count(struct scsi_cmnd *cmd)
{
	return scsi_sg_count(cmd);
}

struct scatterlist *rust_helper_scsi_sglist(struct scsi_cmnd *cmd)
{
	return scsi_sglist(cmd);
}

unsigned int rust_helper_scsi_bufflen(struct scsi_cmnd *cmd)
{
	return scsi_bufflen(cmd);
}
