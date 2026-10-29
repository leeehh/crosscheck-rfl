// SPDX-License-Identifier: GPL-2.0

#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/netdevice.h>

void rust_helper_virtio_device_ready(struct virtio_device *dev)
{
	virtio_device_ready(dev);
}

bool rust_helper_virtio_is_little_endian(struct virtio_device *dev)
{
	return virtio_is_little_endian(dev);
}

bool rust_helper_virtio_has_feature(struct virtio_device *dev,
				    unsigned int feature)
{
	if (feature >= VIRTIO_FEATURES_BITS)
		return false;

	return virtio_has_feature(dev, feature);
}

int rust_helper_virtio_clear_feature(struct virtio_device *dev,
				     unsigned int feature)
{
	if (feature >= VIRTIO_FEATURES_BITS)
		return -EINVAL;

	__virtio_clear_bit(dev, feature);
	return 0;
}

int rust_helper_virtqueue_napi_schedule_or_mark_missed(struct virtqueue *vq,
						       struct napi_struct *napi)
{
	if (!vq || !napi)
		return -EINVAL;

	if (napi_if_scheduled_mark_missed(napi))
		return 0;

	local_bh_disable();
	if (napi_schedule_prep(napi)) {
		virtqueue_disable_cb(vq);
		__napi_schedule(napi);
	} else {
		/* Close the race with another scheduler after the first test. */
		napi_if_scheduled_mark_missed(napi);
	}
	local_bh_enable();
	return 0;
}
