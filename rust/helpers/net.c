// SPDX-License-Identifier: GPL-2.0

#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp.h>
#include <net/xdp_sock_drv.h>

void rust_helper_kfree_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}

void *rust_helper_netdev_priv(const struct net_device *dev)
{
	return netdev_priv(dev);
}

int rust_helper_netif_set_xps_queue_compat(struct net_device *dev,
					   const struct cpumask *mask,
					   u16 index)
{
	return netif_set_xps_queue(dev, mask, index);
}

struct net_device *
rust_helper_netdev_rx_queue_device(struct netdev_rx_queue *queue)
{
	return queue ? queue->dev : NULL;
}

int rust_helper_netdev_rx_queue_index(struct netdev_rx_queue *queue,
				      unsigned int *index)
{
	if (!queue || !queue->dev || !index)
		return -EINVAL;

	*index = get_netdev_rx_queue_index(queue);
	return 0;
}

ssize_t rust_helper_sysfs_emit_u32(char *buffer, u32 value)
{
	if (!buffer)
		return -EINVAL;

	return sysfs_emit(buffer, "%u\n", value);
}

void rust_helper_netif_napi_add_config_weight(struct net_device *dev,
					      struct napi_struct *napi,
					      int (*poll)(struct napi_struct *, int),
					      int index, int weight)
{
	netif_napi_add_config(dev, napi, poll, index);
	napi->weight = weight;
}

void rust_helper_netif_napi_add_tx_weight(struct net_device *dev,
					  struct napi_struct *napi,
					  int (*poll)(struct napi_struct *, int),
					  int weight)
{
	netif_napi_add_tx_weight(dev, napi, poll, weight);
}

void rust_helper_netif_napi_del(struct napi_struct *napi)
{
	netif_napi_del(napi);
}

int rust_helper_eth_prepare_mac_addr_change(struct net_device *dev, void *addr)
{
	return eth_prepare_mac_addr_change(dev, addr);
}

void rust_helper_eth_commit_mac_addr_change(struct net_device *dev, void *addr)
{
	eth_commit_mac_addr_change(dev, addr);
}

int rust_helper_eth_validate_addr(struct net_device *dev)
{
	return eth_validate_addr(dev);
}

void rust_helper_eth_hw_addr_set(struct net_device *dev, const u8 *address)
{
	eth_hw_addr_set(dev, address);
}

void rust_helper_eth_hw_addr_random(struct net_device *dev)
{
	eth_hw_addr_random(dev);
}

void rust_helper_eth_hw_addr_copy(const struct net_device *dev, u8 *address)
{
	ether_addr_copy(address, dev->dev_addr);
}

void rust_helper_netdev_ref_get(struct net_device *dev)
{
	dev_hold(dev);
}

void rust_helper_netdev_ref_put(struct net_device *dev)
{
	dev_put(dev);
}

int rust_helper_netdev_receive_mode_snapshot(struct net_device *dev,
					     bool *promiscuous,
					     bool *all_multicast,
					     u8 *unicast,
					     unsigned int unicast_capacity,
					     unsigned int *unicast_count,
					     u8 *multicast,
					     unsigned int multicast_capacity,
					     unsigned int *multicast_count)
{
	struct netdev_hw_addr *address;
	unsigned int uc_count;
	unsigned int mc_count;
	unsigned int index;
	int ret = 0;

	if (!dev || !promiscuous || !all_multicast || !unicast_count ||
	    !multicast_count || (unicast_capacity && !unicast) ||
	    (multicast_capacity && !multicast))
		return -EINVAL;

	netif_addr_lock_bh(dev);
	*promiscuous = !!(READ_ONCE(dev->flags) & IFF_PROMISC);
	*all_multicast = !!(READ_ONCE(dev->flags) & IFF_ALLMULTI);
	uc_count = netdev_uc_count(dev);
	mc_count = netdev_mc_count(dev);
	*unicast_count = uc_count;
	*multicast_count = mc_count;
	if (uc_count > unicast_capacity || mc_count > multicast_capacity) {
		ret = -ENOSPC;
		goto unlock;
	}

	index = 0;
	netdev_for_each_uc_addr(address, dev)
		ether_addr_copy(unicast + index++ * ETH_ALEN, address->addr);
	index = 0;
	netdev_for_each_mc_addr(address, dev)
		ether_addr_copy(multicast + index++ * ETH_ALEN, address->addr);

unlock:
	netif_addr_unlock_bh(dev);
	return ret;
}

void rust_helper_netdev_add_priv_flags(struct net_device *dev,
				       unsigned long flags)
{
	dev->priv_flags |= flags;
}

bool rust_helper_netif_running(const struct net_device *dev)
{
	return netif_running(dev);
}

bool rust_helper_netif_is_up(const struct net_device *dev)
{
	return READ_ONCE(dev->flags) & IFF_UP;
}

netdev_features_t rust_helper_netdev_features(const struct net_device *dev)
{
	return READ_ONCE(dev->features);
}

void rust_helper_netdev_hw_features_clear(struct net_device *dev,
					  netdev_features_t features)
{
	if (dev)
		dev->hw_features &= ~features;
}

int rust_helper_register_netdevice(struct net_device *dev)
{
	if (!dev)
		return -EINVAL;

	return register_netdevice(dev);
}

void rust_helper_unregister_netdevice(struct net_device *dev)
{
	if (dev)
		unregister_netdevice(dev);
}

void rust_helper_netif_tx_wake_all_queues(struct net_device *dev)
{
	netif_tx_wake_all_queues(dev);
}

bool rust_helper_netif_is_rxfh_configured(const struct net_device *dev)
{
	return netif_is_rxfh_configured(dev);
}

int rust_helper_netdev_rss_key_fill_checked(u8 *buffer, size_t len)
{
	if (!buffer || len > NETDEV_RSS_KEY_LEN)
		return -EINVAL;

	netdev_rss_key_fill(buffer, len);
	return 0;
}

static struct netdev_queue *
rust_helper_netdev_tx_queue(struct net_device *dev, unsigned int index)
{
	if (!dev || index >= READ_ONCE(dev->num_tx_queues))
		return NULL;

	return netdev_get_tx_queue(dev, index);
}

int rust_helper_netdev_tx_timeout_elapsed(struct net_device *dev,
					  unsigned int index,
					  unsigned int *usecs)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue || !usecs)
		return -EINVAL;

	*usecs = jiffies_to_usecs(jiffies - READ_ONCE(queue->trans_start));
	return 0;
}

int rust_helper_netdev_tx_stop_queue(struct net_device *dev,
				     unsigned int index)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue)
		return -EINVAL;

	netif_tx_stop_queue(queue);
	return 0;
}

int rust_helper_netdev_tx_wake_queue(struct net_device *dev,
				     unsigned int index)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue)
		return -EINVAL;

	netif_tx_wake_queue(queue);
	return 0;
}

int rust_helper_netdev_tx_queue_stopped(struct net_device *dev,
					unsigned int index, bool *stopped)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue || !stopped)
		return -EINVAL;

	*stopped = netif_tx_queue_stopped(queue);
	return 0;
}

int rust_helper_netdev_tx_sent_queue(struct net_device *dev,
				     unsigned int index, unsigned int bytes,
				     bool more, bool *kick)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue || !kick)
		return -EINVAL;

	*kick = __netdev_tx_sent_queue(queue, bytes, more);
	return 0;
}

int rust_helper_netdev_tx_completed_queue(struct net_device *dev,
					  unsigned int index,
					  unsigned int packets,
					  unsigned int bytes)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue)
		return -EINVAL;

	netdev_tx_completed_queue(queue, packets, bytes);
	return 0;
}

int rust_helper_netdev_tx_reset_queue(struct net_device *dev,
				      unsigned int index)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue)
		return -EINVAL;

	netdev_tx_reset_queue(queue);
	return 0;
}

int rust_helper_netdev_tx_trans_cond_update(struct net_device *dev,
					    unsigned int index)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue)
		return -EINVAL;

	txq_trans_cond_update(queue);
	return 0;
}

int rust_helper_netdev_tx_queue_trylock(struct net_device *dev,
					unsigned int index,
					struct netdev_queue **locked)
{
	struct netdev_queue *queue;

	if (!locked)
		return -EINVAL;

	*locked = NULL;
	queue = rust_helper_netdev_tx_queue(dev, index);
	if (!queue)
		return -EINVAL;

	if (__netif_tx_trylock(queue))
		*locked = queue;

	return 0;
}

void rust_helper_netdev_tx_queue_tryunlock(struct netdev_queue *queue)
{
	__netif_tx_unlock(queue);
}

int rust_helper_netdev_tx_queue_lock(struct net_device *dev,
				     unsigned int index,
				     struct netdev_queue **locked)
{
	struct netdev_queue *queue = rust_helper_netdev_tx_queue(dev, index);

	if (!queue || !locked)
		return -EINVAL;

	__netif_tx_lock_bh(queue);
	*locked = queue;
	return 0;
}

void rust_helper_netdev_tx_queue_unlock(struct netdev_queue *queue)
{
	__netif_tx_unlock_bh(queue);
}

enum rust_netdev_core_stat {
	RUST_NETDEV_TX_DROPPED,
	RUST_NETDEV_TX_FIFO_ERRORS,
	RUST_NETDEV_RX_LENGTH_ERRORS,
	RUST_NETDEV_RX_FRAME_ERRORS,
};

u64 rust_helper_netdev_core_stat_read(const struct net_device *dev,
				      unsigned int stat)
{
	switch (stat) {
	case RUST_NETDEV_TX_DROPPED:
		return DEV_STATS_READ(dev, tx_dropped);
	case RUST_NETDEV_TX_FIFO_ERRORS:
		return DEV_STATS_READ(dev, tx_fifo_errors);
	case RUST_NETDEV_RX_LENGTH_ERRORS:
		return DEV_STATS_READ(dev, rx_length_errors);
	case RUST_NETDEV_RX_FRAME_ERRORS:
		return DEV_STATS_READ(dev, rx_frame_errors);
	default:
		return 0;
	}
}

int rust_helper_netdev_core_stat_inc(struct net_device *dev, unsigned int stat)
{
	switch (stat) {
	case RUST_NETDEV_TX_DROPPED:
		DEV_STATS_INC(dev, tx_dropped);
		break;
	case RUST_NETDEV_TX_FIFO_ERRORS:
		DEV_STATS_INC(dev, tx_fifo_errors);
		break;
	case RUST_NETDEV_RX_LENGTH_ERRORS:
		DEV_STATS_INC(dev, rx_length_errors);
		break;
	case RUST_NETDEV_RX_FRAME_ERRORS:
		DEV_STATS_INC(dev, rx_frame_errors);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

u16 rust_helper_skb_get_queue_mapping(const struct sk_buff *skb)
{
	return skb_get_queue_mapping(skb);
}

bool rust_helper_netdev_xmit_more(void)
{
	return netdev_xmit_more();
}

void rust_helper_skb_tx_timestamp(struct sk_buff *skb)
{
	skb_tx_timestamp(skb);
}

void rust_helper_skb_orphan_and_reset_ct(struct sk_buff *skb)
{
	skb_orphan(skb);
	nf_reset_ct(skb);
}

int rust_helper_virtio_net_build_tx_sg(struct sk_buff *skb,
				       struct scatterlist *sg,
				       unsigned int sg_capacity,
				       unsigned int header_len,
				       bool allow_inline_header,
				       bool tunnel_header_negotiated,
				       bool little_endian,
				       unsigned int vlan_header_len,
				       bool has_data_valid)
{
	struct virtio_net_hdr_v1_hash_tunnel *header;
	unsigned int needed;
	bool inline_header;
	int count;

	if (!skb || !sg || header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(skb->cb) || vlan_header_len > INT_MAX)
		return -EINVAL;
	if (tunnel_header_negotiated &&
	    header_len < sizeof(struct virtio_net_hdr_v1_hash_tunnel))
		return -EINVAL;

	inline_header = allow_inline_header &&
		!((unsigned long)skb->data & (__alignof__(*header) - 1)) &&
		!skb_header_cloned(skb) && skb_headroom(skb) >= header_len;
	needed = skb_shinfo(skb)->nr_frags + (inline_header ? 1 : 2);
	if (!needed || needed > sg_capacity)
		return -EMSGSIZE;

	if (inline_header)
		header = (void *)(skb->data - header_len);
	else
		header = (void *)skb->cb;
	memset(header, 0, header_len);

	count = virtio_net_hdr_tnl_from_skb(skb, header,
					 tunnel_header_negotiated,
					 little_endian,
					 vlan_header_len,
					 has_data_valid);
	if (count)
		return count;

	sg_init_table(sg, needed);
	if (inline_header) {
		__skb_push(skb, header_len);
		count = skb_to_sgvec(skb, sg, 0, skb->len);
		__skb_pull(skb, header_len);
	} else {
		sg_set_buf(sg, header, header_len);
		count = skb_to_sgvec(skb, sg + 1, 0, skb->len);
		if (count >= 0)
			count++;
	}
	if (count <= 0 || count > needed)
		return count < 0 ? count : -EINVAL;
	return count;
}

static void
rust_helper_virtio_net_set_hash(const struct virtio_net_hdr_v1_hash *header,
				struct sk_buff *skb)
{
	enum pkt_hash_types type;
	u16 report = le16_to_cpu(header->hash_report);
	u32 value;

	switch (report) {
	case VIRTIO_NET_HASH_REPORT_TCPv4:
	case VIRTIO_NET_HASH_REPORT_UDPv4:
	case VIRTIO_NET_HASH_REPORT_TCPv6:
	case VIRTIO_NET_HASH_REPORT_UDPv6:
	case VIRTIO_NET_HASH_REPORT_TCPv6_EX:
	case VIRTIO_NET_HASH_REPORT_UDPv6_EX:
		type = PKT_HASH_TYPE_L4;
		break;
	case VIRTIO_NET_HASH_REPORT_IPv4:
	case VIRTIO_NET_HASH_REPORT_IPv6:
	case VIRTIO_NET_HASH_REPORT_IPv6_EX:
		type = PKT_HASH_TYPE_L3;
		break;
	default:
		type = PKT_HASH_TYPE_NONE;
	}
	value = le16_to_cpu(header->hash_value_lo) |
		((u32)le16_to_cpu(header->hash_value_hi) << 16);
	skb_set_hash(skb, value, type);
}

static int
rust_helper_napi_receive_virtio_finish(struct napi_struct *napi,
				       struct net_device *dev,
				       struct sk_buff *skb,
				       const struct virtio_net_hdr_v1_hash_tunnel *header,
				       bool little_endian,
				       bool hash_report,
				       bool tunnel_header_negotiated,
				       bool tunnel_checksum_negotiated,
				       unsigned int queue_index)
{
	if (hash_report)
		rust_helper_virtio_net_set_hash(&header->hash_hdr, skb);
	if (virtio_net_handle_csum_offload(skb,
					   (struct virtio_net_hdr *)&header->hash_hdr.hdr,
					   tunnel_checksum_negotiated) ||
	    virtio_net_hdr_tnl_to_skb(skb, header,
				      tunnel_header_negotiated,
				      tunnel_checksum_negotiated,
				      little_endian)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	skb_record_rx_queue(skb, queue_index);
	skb->protocol = eth_type_trans(skb, dev);
	napi_gro_receive(napi, skb);
	return 0;
}

int rust_helper_napi_receive_virtio(struct napi_struct *napi,
				    struct net_device *dev,
				    const u8 *buffer,
				    unsigned int length,
				    unsigned int header_len,
				    bool little_endian,
				    bool hash_report,
				    bool tunnel_header_negotiated,
				    bool tunnel_checksum_negotiated,
				    unsigned int queue_index)
{
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	unsigned int payload_len;
	struct sk_buff *skb;

	if (!napi || !dev || !buffer ||
	    header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(header) || length < header_len + ETH_HLEN ||
	    (hash_report && header_len < sizeof(header.hash_hdr)) ||
	    ((tunnel_header_negotiated || tunnel_checksum_negotiated) &&
	     header_len < sizeof(header)))
		return -EINVAL;

	memcpy(&header, buffer, header_len);
	payload_len = length - header_len;
	skb = napi_alloc_skb(napi, payload_len);
	if (!skb)
		return -ENOMEM;
	skb_put_data(skb, buffer + header_len, payload_len);

	return rust_helper_napi_receive_virtio_finish(napi, dev, skb, &header,
						      little_endian, hash_report,
						      tunnel_header_negotiated,
						      tunnel_checksum_negotiated,
						      queue_index);
}

static void rust_helper_copy_from_page(struct page *page, unsigned int offset,
				       void *destination, unsigned int length)
{
	void *address = kmap_local_page(page);

	memcpy(destination, address + offset, length);
	kunmap_local(address);
}

int rust_helper_napi_receive_virtio_pages(struct napi_struct *napi,
					  struct net_device *dev,
					  struct page *const *pages,
					  const u32 *offsets,
					  const u32 *lengths,
					  const u32 *truesizes,
					  unsigned int count,
					  unsigned int header_len,
					  bool little_endian,
					  bool hash_report,
					  bool tunnel_header_negotiated,
					  bool tunnel_checksum_negotiated,
					  unsigned int queue_index)
{
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	struct sk_buff *skb, *current_skb;
	unsigned int payload_len, head_copy, remaining, skip;
	unsigned int i;
	u64 frame_len = 0;

	if (!napi || !dev || !pages || !offsets || !lengths || !truesizes ||
	    !count || header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(header) ||
	    (hash_report && header_len < sizeof(header.hash_hdr)) ||
	    ((tunnel_header_negotiated || tunnel_checksum_negotiated) &&
	     header_len < sizeof(header)))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		if (!pages[i] || offsets[i] > PAGE_SIZE ||
		    lengths[i] > PAGE_SIZE - offsets[i] ||
		    truesizes[i] < lengths[i])
			return -EINVAL;
		frame_len += lengths[i];
		if (frame_len > UINT_MAX)
			return -EOVERFLOW;
	}
	if (lengths[0] < header_len || frame_len < header_len + ETH_HLEN)
		return -EINVAL;

	rust_helper_copy_from_page(pages[0], offsets[0], &header, header_len);
	payload_len = frame_len - header_len;
	skb = napi_alloc_skb(napi, 128U);
	if (!skb)
		return -ENOMEM;
	/* Match virtio-net's page_to_skb() policy: copy a whole small frame,
	 * but keep only the Ethernet header linear when a large frame will use
	 * page fragments. Copying a fixed 128-byte prefix here adds needless
	 * receive-side memory traffic for every full-sized packet.
	 */
	head_copy = payload_len <= skb_tailroom(skb) ? payload_len : ETH_HLEN;

	/* Keep the Ethernet header and a small prefix linear. */
	skip = header_len;
	remaining = head_copy;
	for (i = 0; i < count && remaining; i++) {
		unsigned int local_skip = min(skip, lengths[i]);
		unsigned int part;

		skip -= local_skip;
		part = min(remaining, lengths[i] - local_skip);
		if (!part)
			continue;
		rust_helper_copy_from_page(pages[i], offsets[i] + local_skip,
					   skb_put(skb, part), part);
		remaining -= part;
	}
	if (remaining)
		goto invalid;

	/* Borrowed page references are retained by Rust for this call. Take one
	 * additional reference for each range transferred into the skb.
	 */
	current_skb = skb;
	skip = header_len + head_copy;
	for (i = 0; i < count; i++) {
		unsigned int local_skip = min(skip, lengths[i]);
		unsigned int part = lengths[i] - local_skip;
		unsigned int nr_frags;

		skip -= local_skip;
		if (!part)
			continue;
		nr_frags = skb_shinfo(current_skb)->nr_frags;
		if (nr_frags == MAX_SKB_FRAGS) {
			struct sk_buff *next = alloc_skb(0, GFP_ATOMIC);

			if (!next)
				goto no_memory;
			if (current_skb == skb)
				skb_shinfo(current_skb)->frag_list = next;
			else
				current_skb->next = next;
			current_skb = next;
			skb->truesize += next->truesize;
			nr_frags = 0;
		}
		get_page(pages[i]);
		skb_add_rx_frag(current_skb, nr_frags, pages[i],
				offsets[i] + local_skip, part, truesizes[i]);
		if (current_skb != skb) {
			skb->data_len += part;
			skb->len += part;
			skb->truesize += truesizes[i];
		}
	}

	return rust_helper_napi_receive_virtio_finish(napi, dev, skb, &header,
						      little_endian, hash_report,
						      tunnel_header_negotiated,
						      tunnel_checksum_negotiated,
						      queue_index);

no_memory:
	kfree_skb(skb);
	return -ENOMEM;
invalid:
	kfree_skb(skb);
	return -EINVAL;
}

int rust_helper_napi_receive_virtio_single_page(struct napi_struct *napi,
						 struct net_device *dev,
						 struct page *page,
						 u32 offset, u32 length,
						 u32 truesize,
						 unsigned int header_len,
						 bool little_endian,
						 bool mergeable,
						 bool hash_report,
						 bool tunnel_header_negotiated,
						 bool tunnel_checksum_negotiated,
						 unsigned int queue_index)
{
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	struct sk_buff *skb;
	void *base;
	u8 *buffer;
	u16 buffers = 1;
	unsigned int payload_len, head_copy, remaining;

	if (!napi || !dev || !page || offset > PAGE_SIZE ||
	    length > PAGE_SIZE - offset || truesize < length ||
	    header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(header) || length < header_len + ETH_HLEN ||
	    (hash_report && header_len < sizeof(header.hash_hdr)) ||
	    ((tunnel_header_negotiated || tunnel_checksum_negotiated) &&
	     header_len < sizeof(header)))
		return -EINVAL;

	base = kmap_local_page(page);
	buffer = base + offset;
	memcpy(&header, buffer, header_len);
	if (mergeable) {
		__virtio16 encoded;

		memcpy(&encoded,
		       buffer + offsetof(struct virtio_net_hdr_mrg_rxbuf,
					 num_buffers),
		       sizeof(encoded));
		buffers = little_endian ? le16_to_cpu((__force __le16)encoded) :
					   be16_to_cpu((__force __be16)encoded);
		if (!buffers) {
			kunmap_local(base);
			return -EINVAL;
		}
		if (buffers != 1) {
			kunmap_local(base);
			return buffers;
		}
	}

	payload_len = length - header_len;
	skb = napi_alloc_skb(napi, 128U);
	if (!skb) {
		kunmap_local(base);
		return -ENOMEM;
	}
	head_copy = payload_len <= skb_tailroom(skb) ? payload_len : ETH_HLEN;
	skb_put_data(skb, buffer + header_len, head_copy);
	remaining = payload_len - head_copy;
	if (remaining) {
		get_page(page);
		skb_add_rx_frag(skb, 0, page, offset + header_len + head_copy,
				remaining, truesize);
	}
	kunmap_local(base);

	return rust_helper_napi_receive_virtio_finish(napi, dev, skb, &header,
						      little_endian, hash_report,
						      tunnel_header_negotiated,
						      tunnel_checksum_negotiated,
						      queue_index);
}

struct xdp_rxq_info *rust_helper_xdp_rxq_info_create(void)
{
	struct xdp_rxq_info *rxq;

	rxq = kzalloc(sizeof(*rxq), GFP_KERNEL);
	if (!rxq)
		return ERR_PTR(-ENOMEM);
	return rxq;
}

int rust_helper_xdp_rxq_info_enable(struct xdp_rxq_info *rxq,
				    struct net_device *dev,
				    unsigned int queue_index,
				    struct napi_struct *napi)
{
	int error;

	if (!rxq || !dev || !napi || xdp_rxq_info_is_reg(rxq))
		return -EINVAL;
	error = xdp_rxq_info_reg(rxq, dev, queue_index, napi->napi_id);
	if (error)
		return error;
	error = xdp_rxq_info_reg_mem_model(rxq, MEM_TYPE_PAGE_ORDER0, NULL);
	if (error)
		goto unregister;
	return 0;

unregister:
	xdp_rxq_info_unreg(rxq);
	return error;
}

void rust_helper_xdp_rxq_info_disable(struct xdp_rxq_info *rxq)
{
	if (rxq && xdp_rxq_info_is_reg(rxq))
		xdp_rxq_info_unreg(rxq);
}

void rust_helper_xdp_rxq_info_destroy(struct xdp_rxq_info *rxq)
{
	if (!rxq)
		return;
	rust_helper_xdp_rxq_info_disable(rxq);
	kfree(rxq);
}

void rust_helper_bpf_prog_inc(struct bpf_prog *prog)
{
	bpf_prog_inc(prog);
}

void rust_helper_bpf_prog_put(struct bpf_prog *prog)
{
	bpf_prog_put(prog);
}

bool rust_helper_bpf_prog_xdp_has_frags(const struct bpf_prog *prog)
{
	return prog && prog->aux && prog->aux->xdp_has_frags;
}

void rust_helper_netlink_ext_ack_set_error(struct netlink_ext_ack *extack,
					   const char *message)
{
	if (message)
		NL_SET_ERR_MSG_FMT(extack, "%s", message);
}

unsigned int rust_helper_xdp_max_mtu_no_frags(void)
{
	unsigned int room = SKB_DATA_ALIGN(XDP_PACKET_HEADROOM +
					   sizeof(struct skb_shared_info));

	return PAGE_SIZE - room - ETH_HLEN;
}

unsigned int rust_helper_xdp_rx_page_reserve(void)
{
	return SKB_DATA_ALIGN(XDP_PACKET_HEADROOM +
			      sizeof(struct skb_shared_info));
}

void rust_helper_xdp_set_redirect_target(struct net_device *dev,
					 bool scatter_gather)
{
	xdp_features_set_redirect_target(dev, scatter_gather);
}

void rust_helper_xdp_clear_redirect_target(struct net_device *dev)
{
	xdp_features_clear_redirect_target(dev);
}

void rust_helper_xdp_do_flush(void)
{
	xdp_do_flush();
}

unsigned int rust_helper_xdp_frame_len(const struct xdp_frame *frame)
{
	return frame ? xdp_get_frame_len(frame) : 0;
}

void rust_helper_xdp_return_frame(struct xdp_frame *frame)
{
	if (frame)
		xdp_return_frame(frame);
}

static int rust_helper_copy_page_vector(struct page *const *pages,
					const u32 *offsets,
					const u32 *lengths,
					unsigned int count,
					unsigned int logical_offset,
					void *destination,
					unsigned int length)
{
	unsigned int copied = 0;
	unsigned int logical = 0;
	unsigned int i;

	for (i = 0; i < count && copied < length; i++) {
		unsigned int local_offset;
		unsigned int part;

		if (logical_offset >= logical + lengths[i]) {
			logical += lengths[i];
			continue;
		}
		local_offset = logical_offset > logical ? logical_offset - logical : 0;
		part = min(length - copied, lengths[i] - local_offset);
		rust_helper_copy_from_page(pages[i], offsets[i] + local_offset,
					   (unsigned char *)destination + copied,
					   part);
		copied += part;
		logical_offset += part;
		logical += lengths[i];
	}
	return copied == length ? 0 : -EINVAL;
}

enum rust_xdp_receive_result {
	RUST_XDP_RECEIVE_PASS = 0,
	RUST_XDP_RECEIVE_DROP = 1,
	RUST_XDP_RECEIVE_TX = 2,
	RUST_XDP_RECEIVE_REDIRECT = 3,
};

int rust_helper_napi_receive_virtio_xdp_pages(struct napi_struct *napi,
					      struct net_device *dev,
					      struct xdp_rxq_info *rxq,
					      struct bpf_prog *prog,
					      struct page *const *pages,
					      const u32 *offsets,
					      const u32 *lengths,
					      const u32 *truesizes,
					      unsigned int count,
					      unsigned int header_len,
					      bool mergeable,
					      bool little_endian,
					      bool hash_report,
					      bool tunnel_header_negotiated,
					      bool tunnel_checksum_negotiated,
					      unsigned int queue_index,
					      struct xdp_frame **tx_frame,
					      unsigned int *packet_len)
{
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	struct virtio_net_hdr *common = (void *)&header;
	unsigned int payload_len, linear_len, hard_limit, i;
	unsigned int header_offset, data_offset;
	unsigned int frag_size = 0, frag_truesize = 0;
	struct page *page, *fragment;
	struct xdp_buff xdp;
	struct sk_buff *skb;
	unsigned char *base;
	u64 frame_len = 0;
	u32 xdp_flags = 0;
	u32 action;
	u8 nr_frags = 0;
	u8 header_flags;
	bool fragmented;
	int metasize;
	int error;

	if (!napi || !dev || !rxq || !prog || !pages || !offsets ||
	    !lengths || !truesizes || !count || !tx_frame || !packet_len ||
	    header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(header) ||
	    (hash_report && header_len < sizeof(header.hash_hdr)) ||
	    ((tunnel_header_negotiated || tunnel_checksum_negotiated) &&
	     header_len < sizeof(header)))
		return -EINVAL;

	*tx_frame = NULL;
	*packet_len = 0;
	for (i = 0; i < count; i++) {
		if (!pages[i] || offsets[i] > PAGE_SIZE ||
		    lengths[i] > PAGE_SIZE - offsets[i] ||
		    truesizes[i] < lengths[i])
			return -EINVAL;
		frame_len += lengths[i];
		if (frame_len > UINT_MAX)
			return -EOVERFLOW;
	}
	if (lengths[0] < header_len || frame_len < header_len + ETH_HLEN)
		return -EINVAL;
	payload_len = frame_len - header_len;
	fragmented = mergeable && count > 1 &&
		rust_helper_bpf_prog_xdp_has_frags(prog);
	if (fragmented && count > MAX_SKB_FRAGS + 1)
		return -EINVAL;
	linear_len = fragmented ? lengths[0] - header_len : payload_len;
	if (mergeable) {
		header_offset = XDP_PACKET_HEADROOM;
		data_offset = XDP_PACKET_HEADROOM + header_len;
	} else {
		header_offset = XDP_PACKET_HEADROOM - header_len;
		data_offset = XDP_PACKET_HEADROOM;
	}
	hard_limit = PAGE_SIZE - SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	if (data_offset > hard_limit || linear_len > hard_limit - data_offset)
		return -EMSGSIZE;

	error = rust_helper_copy_page_vector(pages, offsets, lengths, count, 0,
					     &header, header_len);
	if (error)
		return error;
	if (common->gso_type || (common->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
		return -EINVAL;
	header_flags = common->flags;

	page = alloc_page(GFP_ATOMIC);
	if (!page)
		return -ENOMEM;
	base = page_address(page);
	memcpy(base + header_offset, &header, header_len);
	error = rust_helper_copy_page_vector(pages, offsets, lengths, count,
					     header_len,
					     base + data_offset,
					     linear_len);
	if (error)
		goto put_page;

	xdp_init_buff(&xdp, PAGE_SIZE, rxq);
	xdp_prepare_buff(&xdp, base, data_offset, linear_len, true);
	if (fragmented) {
		for (i = 1; i < count; i++) {
			fragment = alloc_page(GFP_ATOMIC);
			if (!fragment) {
				error = -ENOMEM;
				goto return_buff;
			}
			rust_helper_copy_from_page(pages[i], offsets[i],
						   page_address(fragment), lengths[i]);
			if (!xdp_buff_add_frag(&xdp, page_to_netmem(fragment), 0,
					       lengths[i], PAGE_SIZE)) {
				put_page(fragment);
				error = -EMSGSIZE;
				goto return_buff;
			}
		}
	}
	action = bpf_prog_run_xdp(prog, &xdp);

	switch (action) {
	case XDP_PASS:
		if (unlikely(xdp.data_end > xdp_data_hard_end(&xdp))) {
			error = -EINVAL;
			goto return_buff;
		}
		payload_len = xdp_get_buff_len(&xdp);
		metasize = xdp.data - xdp.data_meta;
		metasize = max(metasize, 0);
		if (mergeable)
			memset(&header, 0, header_len);
		else
			memcpy(&header, base + header_offset, header_len);
		common->flags = header_flags;
		if (xdp_buff_has_frags(&xdp)) {
			struct skb_shared_info *shared =
				xdp_get_shared_info_from_buff(&xdp);

			nr_frags = shared->nr_frags;
			frag_size = shared->xdp_frags_size;
			frag_truesize = shared->xdp_frags_truesize;
			xdp_flags = xdp_buff_get_skb_flags(&xdp);
		}
		skb = build_skb(base, PAGE_SIZE);
		if (!skb) {
			error = -ENOMEM;
			goto return_buff;
		}
		skb_reserve(skb, (unsigned char *)xdp.data - base);
		__skb_put(skb, xdp.data_end - xdp.data);
		if (metasize)
			skb_metadata_set(skb, metasize);
		if (nr_frags)
			xdp_update_skb_frags_info(skb, nr_frags, frag_size,
						  frag_truesize, xdp_flags);
		*packet_len = payload_len;
		error = rust_helper_napi_receive_virtio_finish(napi, dev, skb, &header,
							       little_endian, hash_report,
							       tunnel_header_negotiated,
							       tunnel_checksum_negotiated,
							       queue_index);
		return error ?: RUST_XDP_RECEIVE_PASS;
	case XDP_TX:
		*tx_frame = xdp_convert_buff_to_frame(&xdp);
		if (!*tx_frame)
			goto return_buff_drop;
		return RUST_XDP_RECEIVE_TX;
	case XDP_REDIRECT:
		error = xdp_do_redirect(dev, &xdp, prog);
		if (error)
			goto return_buff_drop;
		return RUST_XDP_RECEIVE_REDIRECT;
	case XDP_ABORTED:
		trace_xdp_exception(dev, prog, action);
		goto return_buff_drop;
	case XDP_DROP:
		goto return_buff_drop;
	default:
		bpf_warn_invalid_xdp_action(dev, prog, action);
		trace_xdp_exception(dev, prog, action);
		goto return_buff_drop;
	}

return_buff_drop:
	xdp_return_buff(&xdp);
	return RUST_XDP_RECEIVE_DROP;
return_buff:
	xdp_return_buff(&xdp);
	return error;
put_page:
	put_page(page);
	return error;
}

struct rust_virtio_xsk_pool {
	struct xsk_buff_pool *pool;
	struct virtqueue *rx_vq;
	struct virtqueue *tx_vq;
	struct xdp_rxq_info rxq;
	dma_addr_t header_dma;
	u32 header_len;
	u32 frame_len;
	bool pool_mapped;
	bool header_mapped;
	bool rxq_registered;
	u8 header[sizeof(struct virtio_net_hdr_v1_hash_tunnel)];
};

void *rust_helper_virtio_xsk_pool_create(struct xsk_buff_pool *pool,
					 struct virtqueue *rx_vq,
					 struct virtqueue *tx_vq,
					 struct net_device *dev,
					 struct napi_struct *napi,
					 unsigned int queue_index,
					 unsigned int header_len)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state;
	struct device *dma_dev;
	int error;

	if (!pool || !rx_vq || !tx_vq || !dev || !napi ||
	    header_len < sizeof(struct virtio_net_hdr) ||
	    header_len > sizeof(state->header) ||
	    header_len > xsk_pool_get_headroom(pool))
		return ERR_PTR(-EINVAL);
	dma_dev = virtqueue_dma_dev(rx_vq);
	if (!dma_dev || dma_dev != virtqueue_dma_dev(tx_vq))
		return ERR_PTR(-EINVAL);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return ERR_PTR(-ENOMEM);
	state->pool = pool;
	state->rx_vq = rx_vq;
	state->tx_vq = tx_vq;
	state->header_len = header_len;
	state->frame_len = xsk_pool_get_rx_frame_size(pool);
	if (!state->frame_len || state->frame_len > U32_MAX - header_len) {
		error = -EINVAL;
		goto free_state;
	}
	xp_get_pool(pool);

	state->header_dma = virtqueue_map_single_attrs(tx_vq, state->header,
						       header_len, DMA_TO_DEVICE, 0);
	if (virtqueue_map_mapping_error(tx_vq, state->header_dma)) {
		error = -ENOMEM;
		goto put_pool;
	}
	state->header_mapped = true;

	error = xsk_pool_dma_map(pool, dma_dev, 0);
	if (error)
		goto unmap_header;
	state->pool_mapped = true;

	error = xdp_rxq_info_reg(&state->rxq, dev, queue_index, napi->napi_id);
	if (error)
		goto unmap_pool;
	state->rxq_registered = true;
	error = xdp_rxq_info_reg_mem_model(&state->rxq,
					   MEM_TYPE_XSK_BUFF_POOL, NULL);
	if (error)
		goto unregister_rxq;
	xsk_pool_set_rxq_info(pool, &state->rxq);
	return state;

unregister_rxq:
	xdp_rxq_info_unreg(&state->rxq);
	state->rxq_registered = false;
unmap_pool:
	xsk_pool_dma_unmap(pool, 0);
	state->pool_mapped = false;
unmap_header:
	virtqueue_unmap_single_attrs(tx_vq, state->header_dma, header_len,
				     DMA_TO_DEVICE, 0);
	state->header_mapped = false;
put_pool:
	xp_put_pool(pool);
free_state:
	kfree(state);
	return ERR_PTR(error);
#else
	return ERR_PTR(-EOPNOTSUPP);
#endif
}

void rust_helper_virtio_xsk_pool_destroy(void *handle)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;

	if (!state)
		return;
	if (state->rxq_registered)
		xdp_rxq_info_unreg(&state->rxq);
	if (state->pool_mapped)
		xsk_pool_dma_unmap(state->pool, 0);
	if (state->header_mapped)
		virtqueue_unmap_single_attrs(state->tx_vq, state->header_dma,
					     state->header_len,
					     DMA_TO_DEVICE, 0);
	xp_put_pool(state->pool);
	kfree(state);
#endif
}

unsigned int rust_helper_virtio_xsk_pool_frame_len(void *handle)
{
	struct rust_virtio_xsk_pool *state = handle;

	return state ? state->frame_len : 0;
}

unsigned int rust_helper_virtio_xsk_alloc_rx(void *handle,
					     struct xdp_buff **buffers,
					     unsigned int maximum)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;

	if (!state || !buffers || !maximum)
		return 0;
	return xsk_buff_alloc_batch(state->pool, buffers, maximum);
#else
	return 0;
#endif
}

void rust_helper_virtio_xsk_free_rx(struct xdp_buff *buffer)
{
#ifdef CONFIG_XDP_SOCKETS
	if (buffer)
		xsk_buff_free(buffer);
#endif
}

int rust_helper_virtio_xsk_rx_segment(void *handle,
				      struct xdp_buff *buffer,
				      dma_addr_t *address,
				      unsigned int *length)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;
	dma_addr_t dma;

	if (!state || !buffer || !address || !length)
		return -EINVAL;
	dma = xsk_buff_xdp_get_dma(buffer);
	if (dma < state->header_len)
		return -EOVERFLOW;
	*address = dma - state->header_len;
	*length = state->frame_len + state->header_len;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

int rust_helper_virtio_xsk_rx_header(void *handle,
				     struct xdp_buff *buffer,
				     unsigned int used_length,
				     bool mergeable,
				     bool little_endian,
				     unsigned short *buffer_count,
				     unsigned char *flags)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	u16 count = 1;

	if (!state || !buffer || !buffer_count || !flags ||
	    used_length < state->header_len + ETH_HLEN ||
	    used_length > state->frame_len + state->header_len)
		return -EINVAL;
	xsk_buff_dma_sync_for_cpu(buffer);
	memcpy(&header, buffer->data - state->header_len, state->header_len);
	if (mergeable) {
		count = little_endian ? le16_to_cpu(header.hash_hdr.hdr.num_buffers) :
					 be16_to_cpu(header.hash_hdr.hdr.num_buffers);
		if (!count)
			return -EINVAL;
	}
	*buffer_count = count;
	*flags = header.hash_hdr.hdr.flags;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

#ifdef CONFIG_XDP_SOCKETS
static void rust_helper_virtio_xsk_free_vector(struct xdp_buff **buffers,
					       unsigned int count)
{
	unsigned int i;

	if (!buffers)
		return;

	for (i = 0; i < count; i++) {
		if (buffers[i]) {
			xsk_buff_free(buffers[i]);
			buffers[i] = NULL;
		}
	}
}

static struct sk_buff *
rust_helper_virtio_xsk_construct_skb(struct napi_struct *napi,
				     struct xdp_buff *buffer)
{
	unsigned int metadata = buffer->data - buffer->data_meta;
	unsigned int size = buffer->data_end - buffer->data_hard_start;
	struct sk_buff *skb;

	skb = napi_alloc_skb(napi, size);
	if (!skb)
		goto free_buffer;
	skb_reserve(skb, buffer->data_meta - buffer->data_hard_start);
	size = buffer->data_end - buffer->data_meta;
	memcpy(__skb_put(skb, size), buffer->data_meta, size);
	if (metadata) {
		__skb_pull(skb, metadata);
		skb_metadata_set(skb, metadata);
	}
	xsk_buff_free(buffer);
	return skb;

free_buffer:
	xsk_buff_free(buffer);
	return NULL;
}

static struct sk_buff *
rust_helper_virtio_xsk_append_frag(struct sk_buff *head,
				   struct sk_buff *current_skb,
				   struct page *page, void *buffer,
				   unsigned int length)
{
	unsigned int fragments = skb_shinfo(current_skb)->nr_frags;
	unsigned int offset;

	if (fragments == MAX_SKB_FRAGS) {
		struct sk_buff *next = alloc_skb(0, GFP_ATOMIC);

		if (!next)
			return NULL;
		if (current_skb == head)
			skb_shinfo(current_skb)->frag_list = next;
		else
			current_skb->next = next;
		current_skb = next;
		head->truesize += next->truesize;
		fragments = 0;
	}
	if (current_skb != head) {
		head->data_len += length;
		head->len += length;
		head->truesize += length;
	}
	offset = buffer - page_address(page);
	if (skb_can_coalesce(current_skb, fragments, page, offset)) {
		put_page(page);
		skb_coalesce_rx_frag(current_skb, fragments - 1, length, length);
	} else {
		skb_add_rx_frag(current_skb, fragments, page, offset, length, length);
	}
	return current_skb;
}
#endif

int rust_helper_napi_receive_virtio_xsk(struct napi_struct *napi,
					struct net_device *dev,
					void *handle,
					struct bpf_prog *program,
					struct xdp_buff **buffers,
					const unsigned int *used_lengths,
					unsigned int count,
					bool mergeable,
					bool little_endian,
					bool hash_report,
					bool tunnel_header_negotiated,
					bool tunnel_checksum_negotiated,
					unsigned int queue_index,
					struct xdp_frame **tx_frame,
					unsigned int *packet_len)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;
	struct virtio_net_hdr_v1_hash_tunnel header = {};
	struct virtio_net_hdr *common = (void *)&header;
	struct sk_buff *skb = NULL, *current_skb;
	struct xdp_buff *first;
	unsigned int expected = 1;
	unsigned int total = 0;
	unsigned int i;
	u32 action = XDP_PASS;
	u8 saved_flags;
	int error;

	if (!napi || !dev || !state || !buffers || !used_lengths || !count ||
	    !tx_frame || !packet_len ||
	    state->header_len < sizeof(struct virtio_net_hdr) ||
	    (hash_report && state->header_len < sizeof(header.hash_hdr)) ||
	    ((tunnel_header_negotiated || tunnel_checksum_negotiated) &&
	     state->header_len < sizeof(header))) {
		error = -EINVAL;
		goto free_vector;
	}
	*tx_frame = NULL;
	*packet_len = 0;
	for (i = 0; i < count; i++) {
		if (!buffers[i]) {
			error = -EINVAL;
			goto free_vector;
		}
		if (i == 0) {
			if (used_lengths[i] < state->header_len + ETH_HLEN ||
			    used_lengths[i] > state->frame_len + state->header_len) {
				error = -EINVAL;
				goto free_vector;
			}
			total = used_lengths[i] - state->header_len;
		} else {
			if (!mergeable ||
			    used_lengths[i] > state->frame_len + state->header_len) {
				error = -EINVAL;
				goto free_vector;
			}
			if (check_add_overflow(total, used_lengths[i], &total)) {
				error = -EOVERFLOW;
				goto free_vector;
			}
		}
	}

	first = buffers[0];
	xsk_buff_dma_sync_for_cpu(first);
	memcpy(&header, first->data - state->header_len, state->header_len);
	saved_flags = common->flags;
	if (mergeable) {
		expected = little_endian ?
			le16_to_cpu(header.hash_hdr.hdr.num_buffers) :
			be16_to_cpu(header.hash_hdr.hdr.num_buffers);
		if (!expected || expected != count) {
			error = -EINVAL;
			goto free_vector;
		}
	}
	xsk_buff_set_size(first, used_lengths[0] - state->header_len);

	if (program && mergeable && count > 1)
		action = XDP_ABORTED;
	else if (program)
		action = bpf_prog_run_xdp(program, first);
	switch (action) {
	case XDP_PASS:
		break;
	case XDP_TX:
		*tx_frame = xdp_convert_buff_to_frame(first);
		if (!*tx_frame) {
			error = RUST_XDP_RECEIVE_DROP;
			goto free_vector;
		}
		buffers[0] = NULL;
		return RUST_XDP_RECEIVE_TX;
	case XDP_REDIRECT:
		error = xdp_do_redirect(dev, first, program);
		if (error) {
			error = RUST_XDP_RECEIVE_DROP;
			goto free_vector;
		}
		buffers[0] = NULL;
		return RUST_XDP_RECEIVE_REDIRECT;
	case XDP_ABORTED:
		if (!(mergeable && count > 1))
			trace_xdp_exception(dev, program, action);
		error = RUST_XDP_RECEIVE_DROP;
		goto free_vector;
	case XDP_DROP:
		error = RUST_XDP_RECEIVE_DROP;
		goto free_vector;
	default:
		bpf_warn_invalid_xdp_action(dev, program, action);
		trace_xdp_exception(dev, program, action);
		error = RUST_XDP_RECEIVE_DROP;
		goto free_vector;
	}

	skb = rust_helper_virtio_xsk_construct_skb(napi, first);
	buffers[0] = NULL;
	if (!skb) {
		error = -ENOMEM;
		goto free_vector;
	}
	current_skb = skb;
	for (i = 1; i < count; i++) {
		struct xdp_buff *tail = buffers[i];
		struct page *page;
		void *fragment;

		xdp_prepare_buff(tail, tail->data_hard_start,
				 XDP_PACKET_HEADROOM - state->header_len,
				 used_lengths[i], true);
		tail->flags = 0;
		xsk_buff_dma_sync_for_cpu(tail);
		fragment = napi_alloc_frag(used_lengths[i]);
		if (!fragment) {
			error = -ENOMEM;
			goto free_skb;
		}
		memcpy(fragment, tail->data, used_lengths[i]);
		xsk_buff_free(tail);
		buffers[i] = NULL;
		page = virt_to_page(fragment);
		current_skb = rust_helper_virtio_xsk_append_frag(skb, current_skb,
								 page, fragment,
								 used_lengths[i]);
		if (!current_skb) {
			put_page(page);
			error = -ENOMEM;
			goto free_skb;
		}
	}

	memset(&header, 0, state->header_len);
	common->flags = saved_flags;
	*packet_len = total;
	error = rust_helper_napi_receive_virtio_finish(napi, dev, skb, &header,
						       little_endian, hash_report,
						       tunnel_header_negotiated,
						       tunnel_checksum_negotiated,
						       queue_index);
	if (error)
		return error;
	return RUST_XDP_RECEIVE_PASS;

free_skb:
	kfree_skb(skb);
free_vector:
	rust_helper_virtio_xsk_free_vector(buffers, count);
	return error;
#else
	return -EOPNOTSUPP;
#endif
}

unsigned int rust_helper_virtio_xsk_tx_peek(void *handle,
					    u64 *addresses,
					    unsigned int *lengths,
					    unsigned int maximum)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;
	unsigned int count;
	unsigned int i;

	if (!state || !addresses || !lengths || !maximum)
		return 0;
	count = xsk_tx_peek_release_desc_batch(state->pool, maximum);
	for (i = 0; i < count; i++) {
		addresses[i] = state->pool->tx_descs[i].addr;
		lengths[i] = state->pool->tx_descs[i].len;
	}
	return count;
#else
	return 0;
#endif
}

int rust_helper_virtio_xsk_tx_segments(void *handle, u64 umem_address,
				       unsigned int length,
				       dma_addr_t *header_address,
				       dma_addr_t *data_address,
				       unsigned int *header_length)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;
	dma_addr_t dma;

	if (!state || !length || !header_address || !data_address ||
	    !header_length)
		return -EINVAL;
	dma = xsk_buff_raw_get_dma(state->pool, umem_address);
	xsk_buff_raw_dma_sync_for_device(state->pool, dma, length);
	*header_address = state->header_dma;
	*data_address = dma;
	*header_length = state->header_len;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

void rust_helper_virtio_xsk_tx_completed(void *handle, unsigned int count)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;

	if (state && count)
		xsk_tx_completed(state->pool, count);
#endif
}

bool rust_helper_virtio_xsk_uses_need_wakeup(void *handle)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;

	return state && xsk_uses_need_wakeup(state->pool);
#else
	return false;
#endif
}

void rust_helper_virtio_xsk_set_tx_need_wakeup(void *handle)
{
#ifdef CONFIG_XDP_SOCKETS
	struct rust_virtio_xsk_pool *state = handle;

	if (state)
		xsk_set_tx_need_wakeup(state->pool);
#endif
}

int rust_helper_virtqueue_add_xdp_frame(struct virtqueue *vq,
					struct xdp_frame *frame,
					unsigned int header_len,
					void *token, gfp_t flags)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 1];
	struct skb_shared_info *shared = NULL;
	unsigned int fragments = 0;
	unsigned int i;

	if (!vq || !frame || !token || !header_len ||
	    frame->headroom < header_len)
		return -EOVERFLOW;
	if (xdp_frame_has_frags(frame)) {
		shared = xdp_get_shared_info_from_frame(frame);
		fragments = shared->nr_frags;
		if (fragments > MAX_SKB_FRAGS)
			return -EMSGSIZE;
	}

	frame->headroom -= header_len;
	frame->data -= header_len;
	memset(frame->data, 0, header_len);
	frame->len += header_len;

	sg_init_table(sg, fragments + 1);
	sg_set_buf(&sg[0], frame->data, frame->len);
	for (i = 0; i < fragments; i++) {
		skb_frag_t *fragment = &shared->frags[i];

		sg_set_page(&sg[i + 1], skb_frag_page(fragment),
			    skb_frag_size(fragment), skb_frag_off(fragment));
	}
	return virtqueue_add_outbuf(vq, sg, fragments + 1, token, flags);
}
