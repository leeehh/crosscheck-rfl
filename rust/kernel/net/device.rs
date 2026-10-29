// SPDX-License-Identifier: GPL-2.0

//! Reference-counted network-device registration.
//!
//! A registered `struct net_device` may call into its operations from multiple
//! contexts.  This module keeps one [`Arc`] reference to the driver's state in
//! `netdev_priv`, borrows that state for each callback, and releases it only
//! after `unregister_netdev()` has drained the callbacks.  Drivers therefore do
//! not manufacture owning handles from callback pointers and do not need raw
//! pointer or lifetime code.

use crate::{
    alloc::Flags,
    bindings, container_of,
    cpumask::Cpumask,
    error::{from_err_ptr, from_result, to_result, Error, Result},
    ffi,
    prelude::*,
    str::{as_char_ptr_in_const_context, CStr},
    sync::{Arc, ArcBorrow},
    types::{ForeignOwnable, Opaque},
};
use core::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::{self, size_of},
    ops::{BitOr, BitOrAssign},
    ptr::NonNull,
    slice,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Maximum number of fragmented skb payload entries for this kernel build.
pub const MAX_SKB_FRAGS: u32 = bindings::MAX_SKB_FRAGS;

/// Networking core's standard NAPI poll weight.
pub const NAPI_POLL_WEIGHT: u32 = bindings::NAPI_POLL_WEIGHT;

const ETHTOOL_COALESCE_SUPPORTED: u32 = (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 9);

#[cfg(CONFIG_DIMLIB)]
const DIM_PROFILE_RX: u8 = 1 << 0;
#[cfg(CONFIG_DIMLIB)]
const DIM_COALESCE_USEC_PKTS: u8 = (1 << 0) | (1 << 1);

/// Operations required by a basic Ethernet network device.
///
/// Additional operation groups (ethtool, statistics, XDP, and the remaining
/// `net_device_ops`) build on the same state/registration lifetime.
pub trait Operations: Send + Sync + Sized + 'static {
    /// Install the MAC-address transaction callback.
    const HAS_SET_MAC_ADDRESS: bool = false;

    /// Install the receive-mode notification callback.
    const HAS_SET_RX_MODE: bool = false;

    /// Install the 64-bit link statistics callback.
    const HAS_GET_STATS64: bool = false;

    /// Install both VLAN add and remove callbacks.
    const HAS_VLAN_RX: bool = false;

    /// Install the standard pass-through feature checker.
    const HAS_PASSTHRU_FEATURES_CHECK: bool = false;

    /// Install the physical-port-name callback.
    const HAS_GET_PHYS_PORT_NAME: bool = false;

    /// Install the feature-change callback.
    const HAS_SET_FEATURES: bool = false;

    /// Install the transmit-watchdog callback.
    const HAS_TX_TIMEOUT: bool = false;

    /// Install an ethtool operation table for this device.
    const HAS_ETHTOOL_OPS: bool = false;

    /// Install the typed driver-information callback.
    const HAS_ETHTOOL_DRIVER_INFO: bool = false;

    /// Install networking core's standard carrier query.
    const HAS_ETHTOOL_LINK: bool = false;

    /// Install the typed ring-parameter query.
    const HAS_ETHTOOL_RING_PARAMETERS: bool = false;

    /// Install the typed ring-parameter update callback.
    const HAS_ETHTOOL_SET_RING_PARAMETERS: bool = false;

    /// Install the typed channel query.
    const HAS_ETHTOOL_CHANNELS: bool = false;

    /// Install the typed channel-count update callback.
    const HAS_ETHTOOL_SET_CHANNELS: bool = false;

    /// Install device-wide notification-coalescing query and update callbacks.
    const HAS_ETHTOOL_COALESCE: bool = false;

    /// Install per-queue notification-coalescing query and update callbacks.
    const HAS_ETHTOOL_PER_QUEUE_COALESCE: bool = false;

    /// Install the receive dynamic-interrupt-moderation work callback.
    #[cfg(CONFIG_DIMLIB)]
    const HAS_RX_DIM: bool = false;

    /// Install networking core's standard timestamp capabilities query.
    const HAS_ETHTOOL_TIMESTAMP_INFO: bool = false;

    /// Install the typed virtual-link settings query and update callbacks.
    const HAS_ETHTOOL_LINK_SETTINGS: bool = false;

    /// Install the RSS key-size query.
    const HAS_ETHTOOL_RSS_KEY_SIZE: bool = false;

    /// Install the RSS indirection-table-size query.
    const HAS_ETHTOOL_RSS_INDIRECTION_SIZE: bool = false;

    /// Install the active receive-ring count query.
    const HAS_ETHTOOL_RX_RING_COUNT: bool = false;

    /// Install RSS indirection/key query and update callbacks.
    const HAS_ETHTOOL_RSS: bool = false;

    /// Install per-flow RSS input-field query and update callbacks.
    const HAS_ETHTOOL_RSS_FLOW_FIELDS: bool = false;

    /// Install the ethtool string-set and statistics callbacks.
    const HAS_ETHTOOL_STATS: bool = false;

    /// Install fine-grained receive/transmit queue statistics callbacks.
    const HAS_QUEUE_STATS: bool = false;

    /// Install native-XDP control-plane setup.
    const HAS_XDP: bool = false;

    /// Install native-XDP frame transmission.
    const HAS_XDP_XMIT: bool = false;

    /// Install AF_XDP zero-copy pool setup and wakeup callbacks.
    const HAS_XSK: bool = false;

    /// Install the native-XDP receive-hash metadata callback.
    const HAS_XDP_METADATA_RX_HASH: bool = false;

    /// Install one read-only attribute in every receive queue's sysfs directory.
    const HAS_RX_QUEUE_SYSFS: bool = false;

    /// Directory name for the optional receive-queue sysfs attribute group.
    const RX_QUEUE_SYSFS_GROUP_NAME: &'static CStr = c"";

    /// File name for the optional read-only receive-queue sysfs attribute.
    const RX_QUEUE_SYSFS_ATTRIBUTE_NAME: &'static CStr = c"";

    /// Bring the interface up.
    fn open(&self, device: &Device<Self>) -> Result;

    /// Stop the interface and quiesce its queues.
    fn stop(&self, device: &Device<Self>) -> Result;

    /// Consume or enqueue one transmit packet.
    fn start_xmit(&self, packet: TxPacket, device: &Device<Self>) -> TxResult;

    /// Poll one registered NAPI context. Drivers that do not add NAPI contexts keep this default.
    fn poll(&self, device: &Device<Self>, napi: &NapiContext<'_>, budget: u32) -> u32 {
        let _ = (device, napi, budget);
        0
    }

    /// Attach or detach one native XDP program.
    fn xdp_setup_program(&self, device: &Device<Self>, setup: XdpProgramSetup<'_>) -> Result {
        let _ = (device, setup);
        Err(EOPNOTSUPP)
    }

    /// Transfer a prefix of native XDP frames to the device.
    fn xdp_xmit(
        &self,
        device: &Device<Self>,
        frames: &mut XdpFrameBatch<'_>,
        flags: XdpXmitFlags,
    ) -> Result {
        let _ = (device, frames, flags);
        Err(EOPNOTSUPP)
    }

    /// Bind or unbind one AF_XDP zero-copy pool.
    fn xsk_pool_setup(&self, device: &Device<Self>, setup: XskPoolSetup<'_>) -> Result {
        let _ = (device, setup);
        Err(EOPNOTSUPP)
    }

    /// Schedule work for one userspace AF_XDP queue.
    fn xsk_wakeup(&self, device: &Device<Self>, queue_id: u32, flags: XskWakeupFlags) -> Result {
        let _ = (device, queue_id, flags);
        Err(EOPNOTSUPP)
    }

    /// Return receive-hash metadata for the current native-XDP buffer.
    fn xdp_rx_hash(
        &self,
        device: &Device<Self>,
        context: &XdpMetadataContext<'_>,
    ) -> Result<XdpRxHash> {
        let _ = (device, context);
        Err(EOPNOTSUPP)
    }

    /// Return the value exposed by the optional read-only receive-queue sysfs attribute.
    fn rx_queue_sysfs_value(&self, device: &Device<Self>, queue: u32) -> Result<u32> {
        let _ = (device, queue);
        Err(EOPNOTSUPP)
    }

    /// Program a validated Ethernet address. The framework commits it to the netdev only after
    /// this method succeeds.
    fn set_mac_address(&self, device: &Device<Self>, address: EthernetAddress) -> Result {
        let _ = (device, address);
        Err(EOPNOTSUPP)
    }

    /// React to a change in promiscuous, all-multicast, or address-list state.
    fn set_rx_mode(&self, device: &Device<Self>) {
        let _ = device;
    }

    /// Return one coherent 64-bit statistics snapshot.
    fn get_stats64(&self, device: &Device<Self>) -> LinkStats64 {
        let _ = device;
        LinkStats64::default()
    }

    /// Return one receive queue's collected fine-grained statistics.
    fn queue_stats_rx(&self, device: &Device<Self>, queue: u32) -> QueueStatsRx {
        let _ = (device, queue);
        QueueStatsRx::default()
    }

    /// Return one transmit queue's collected fine-grained statistics.
    fn queue_stats_tx(&self, device: &Device<Self>, queue: u32) -> QueueStatsTx {
        let _ = (device, queue);
        QueueStatsTx::default()
    }

    /// Return the historical delta outside the currently active queues.
    fn base_stats(&self, device: &Device<Self>) -> (QueueStatsRx, QueueStatsTx) {
        let _ = device;
        (QueueStatsRx::default(), QueueStatsTx::default())
    }

    /// Add one VLAN filter.
    fn vlan_rx_add(&self, device: &Device<Self>, tag: VlanTag) -> Result {
        let _ = (device, tag);
        Err(EOPNOTSUPP)
    }

    /// Remove one VLAN filter.
    fn vlan_rx_kill(&self, device: &Device<Self>, tag: VlanTag) -> Result {
        let _ = (device, tag);
        Err(EOPNOTSUPP)
    }

    /// Return the physical port name exposed through rtnetlink and sysfs.
    fn get_phys_port_name(&self, device: &Device<Self>) -> Result<PhysPortName> {
        let _ = device;
        Err(EOPNOTSUPP)
    }

    /// Apply a new networking feature set.
    fn set_features(&self, device: &Device<Self>, features: Features) -> Result {
        let _ = (device, features);
        Err(EOPNOTSUPP)
    }

    /// Report a transmit watchdog timeout for one queue.
    fn tx_timeout(&self, device: &Device<Self>, queue: u32) {
        let _ = (device, queue);
    }

    /// Return bounded text fields for `ETHTOOL_GDRVINFO`.
    fn ethtool_driver_info<'a>(&'a self, device: &'a Device<Self>) -> EthtoolDriverInfo<'a> {
        let _ = device;
        EthtoolDriverInfo::new(crate::c_str!(""), crate::c_str!(""), crate::c_str!(""))
    }

    /// Return maximum and current receive/transmit ring sizes.
    fn ethtool_ring_parameters(&self, device: &Device<Self>) -> EthtoolRingParameters {
        let _ = device;
        EthtoolRingParameters::default()
    }

    /// Apply a complete ethtool ring-size request.
    fn ethtool_set_ring_parameters(
        &self,
        device: &Device<Self>,
        parameters: EthtoolRingParameters,
    ) -> Result {
        let _ = (device, parameters);
        Err(EOPNOTSUPP)
    }

    /// Return supported and active channel counts.
    fn ethtool_channels(&self, device: &Device<Self>) -> EthtoolChannels {
        let _ = device;
        EthtoolChannels::default()
    }

    /// Apply a complete ethtool channel-count request.
    fn ethtool_set_channels(&self, device: &Device<Self>, channels: EthtoolChannels) -> Result {
        let _ = (device, channels);
        Err(EOPNOTSUPP)
    }

    /// Return device-wide interrupt-notification coalescing state.
    fn ethtool_coalesce(&self, device: &Device<Self>) -> Result<EthtoolCoalesce> {
        let _ = device;
        Err(EOPNOTSUPP)
    }

    /// Apply device-wide interrupt-notification coalescing state.
    fn ethtool_set_coalesce(&self, device: &Device<Self>, coalesce: EthtoolCoalesce) -> Result {
        let _ = (device, coalesce);
        Err(EOPNOTSUPP)
    }

    /// Return interrupt-notification coalescing state for one queue pair.
    fn ethtool_per_queue_coalesce(
        &self,
        device: &Device<Self>,
        queue: u32,
    ) -> Result<EthtoolCoalesce> {
        let _ = (device, queue);
        Err(EOPNOTSUPP)
    }

    /// Apply interrupt-notification coalescing state for one queue pair.
    fn ethtool_set_per_queue_coalesce(
        &self,
        device: &Device<Self>,
        queue: u32,
        coalesce: EthtoolCoalesce,
    ) -> Result {
        let _ = (device, queue, coalesce);
        Err(EOPNOTSUPP)
    }

    /// Apply one receive dynamic-interrupt-moderation profile decision.
    #[cfg(CONFIG_DIMLIB)]
    fn rx_dim_moderation(&self, device: &Device<Self>, context: u32, moderation: RxDimModeration) {
        let _ = (device, context, moderation);
    }

    /// Return virtual link speed, duplex and port type.
    fn ethtool_link_settings(&self, device: &Device<Self>) -> EthtoolLinkSettings {
        let _ = device;
        EthtoolLinkSettings::default()
    }

    /// Apply speed and duplex values validated by networking core for a virtual device.
    fn ethtool_set_link_settings(
        &self,
        device: &Device<Self>,
        settings: EthtoolLinkSettings,
    ) -> Result {
        let _ = (device, settings);
        Err(EOPNOTSUPP)
    }

    /// Return the negotiated RSS key size.
    fn ethtool_rss_key_size(&self, device: &Device<Self>) -> u32 {
        let _ = device;
        0
    }

    /// Return the negotiated RSS indirection-table size.
    fn ethtool_rss_indirection_size(&self, device: &Device<Self>) -> u32 {
        let _ = device;
        0
    }

    /// Return the number of active receive rings.
    fn ethtool_rx_ring_count(&self, device: &Device<Self>) -> u32 {
        let _ = device;
        0
    }

    /// Fill an optional RSS indirection table and key, returning the selected hash function.
    fn ethtool_get_rss(
        &self,
        device: &Device<Self>,
        indirection: Option<&mut [u32]>,
        key: Option<&mut [u8]>,
    ) -> Result<EthtoolRssHashFunction> {
        let _ = (device, indirection, key);
        Err(EOPNOTSUPP)
    }

    /// Apply one RSS hash-function, indirection-table, and/or key update.
    fn ethtool_set_rss(
        &self,
        device: &Device<Self>,
        parameters: EthtoolRssParameters<'_>,
    ) -> Result {
        let _ = (device, parameters);
        Err(EOPNOTSUPP)
    }

    /// Return the selected input fields for one RSS flow type.
    fn ethtool_get_rss_flow_fields(
        &self,
        device: &Device<Self>,
        flow_type: EthtoolRssFlowType,
    ) -> Result<EthtoolRssFlowFields> {
        let _ = (device, flow_type);
        Err(EOPNOTSUPP)
    }

    /// Apply the selected input fields for one RSS flow type.
    fn ethtool_set_rss_flow_fields(
        &self,
        device: &Device<Self>,
        flow_type: EthtoolRssFlowType,
        fields: EthtoolRssFlowFields,
    ) -> Result {
        let _ = (device, flow_type, fields);
        Err(EOPNOTSUPP)
    }

    /// Return the number of strings and values in one ethtool string set.
    fn ethtool_string_count(
        &self,
        device: &Device<Self>,
        string_set: EthtoolStringSet,
    ) -> Result<u32> {
        let _ = (device, string_set);
        Err(EOPNOTSUPP)
    }

    /// Fill one ethtool string set using fixed-width, zero-padded slots.
    fn ethtool_strings(
        &self,
        device: &Device<Self>,
        string_set: EthtoolStringSet,
        output: &mut EthtoolStrings<'_>,
    ) -> Result {
        let _ = (device, string_set, output);
        Err(EOPNOTSUPP)
    }

    /// Fill the ethtool statistics values in the same order as the stats strings.
    fn ethtool_stats(&self, device: &Device<Self>, output: &mut [u64]) {
        let _ = (device, output);
    }
}

/// Validated Ethernet MAC address copied from a callback request.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EthernetAddress([u8; 6]);

impl EthernetAddress {
    /// Validate and own a unicast, nonzero Ethernet address.
    pub fn new(bytes: [u8; 6]) -> Result<Self> {
        if bytes[0] & 1 != 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::from_errno(-(bindings::EADDRNOTAVAIL as c_int)));
        }
        Ok(Self(bytes))
    }

    /// Address bytes in network order.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// An owned snapshot of the receive-filter state requested by networking core.
///
/// The address lists and interface flags are copied under `netif_addr_lock_bh`,
/// so a worker may program them after the originating callback returns.
pub struct ReceiveMode {
    promiscuous: bool,
    all_multicast: bool,
    unicast: KVec<[u8; 6]>,
    multicast: KVec<[u8; 6]>,
}

impl ReceiveMode {
    /// Whether all receive traffic should be accepted.
    pub fn promiscuous(&self) -> bool {
        self.promiscuous
    }

    /// Whether all multicast traffic should be accepted.
    pub fn all_multicast(&self) -> bool {
        self.all_multicast
    }

    /// Requested unicast address filters.
    pub fn unicast(&self) -> &[[u8; 6]] {
        &self.unicast
    }

    /// Requested multicast address filters.
    pub fn multicast(&self) -> &[[u8; 6]] {
        &self.multicast
    }
}

/// Fill a bounded RSS key from networking core's process-wide random key.
pub fn fill_rss_key(key: &mut [u8]) -> Result {
    // SAFETY: `key` is writable for exactly `key.len()` bytes. The helper
    // rejects lengths larger than networking core's key storage before copy.
    to_result(unsafe { bindings::netdev_rss_key_fill_checked(key.as_mut_ptr(), key.len()) })
}

/// Opaque netdev feature bit set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Features(u64);

impl Features {
    /// DMA addresses may exceed 32 bits.
    pub const HIGH_DMA: Self = Self(1u64 << bindings::NETIF_F_HIGHDMA_BIT);
    /// Scatter-gather packet I/O.
    pub const SCATTER_GATHER: Self = Self(1u64 << bindings::NETIF_F_SG_BIT);
    /// Generic hardware checksum offload.
    pub const HW_CHECKSUM: Self = Self(1u64 << bindings::NETIF_F_HW_CSUM_BIT);
    /// IPv4 TCP segmentation offload.
    pub const TSO: Self = Self(1u64 << bindings::NETIF_F_TSO_BIT);
    /// ECN-capable TCP segmentation offload.
    pub const TSO_ECN: Self = Self(1u64 << bindings::NETIF_F_TSO_ECN_BIT);
    /// IPv6 TCP segmentation offload.
    pub const TSO6: Self = Self(1u64 << bindings::NETIF_F_TSO6_BIT);
    /// UDP L4 segmentation offload.
    pub const GSO_UDP_L4: Self = Self(1u64 << bindings::NETIF_F_GSO_UDP_L4_BIT);
    /// UDP tunnel segmentation offload.
    pub const GSO_UDP_TUNNEL: Self = Self(1u64 << bindings::NETIF_F_GSO_UDP_TUNNEL_BIT);
    /// Checksummed UDP tunnel segmentation offload.
    pub const GSO_UDP_TUNNEL_CHECKSUM: Self =
        Self(1u64 << bindings::NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT);
    /// Robustness against malformed GSO packets.
    pub const GSO_ROBUST: Self = Self(1u64 << bindings::NETIF_F_GSO_ROBUST_BIT);
    /// Receive checksum validation.
    pub const RX_CHECKSUM: Self = Self(1u64 << bindings::NETIF_F_RXCSUM_BIT);
    /// Hardware generic receive offload.
    pub const GRO_HW: Self = Self(1u64 << bindings::NETIF_F_GRO_HW_BIT);
    /// Receive hash reporting/configuration.
    pub const RX_HASH: Self = Self(1u64 << bindings::NETIF_F_RXHASH_BIT);
    /// Hardware C-tag VLAN receive filtering.
    pub const HW_VLAN_CTAG_FILTER: Self = Self(1u64 << bindings::NETIF_F_HW_VLAN_CTAG_FILTER_BIT);

    /// Empty feature set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Construct from networking-core feature bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Raw networking-core feature bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any bits in `other` are set.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Add feature bits.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Remove feature bits.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl BitOr for Features {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Features {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Additional private netdev flags applied before registration.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateFlags(u32);

impl PrivateFlags {
    /// Driver supports a programmed unicast address filter.
    pub const UNICAST_FILTER: Self = Self(bindings::netdev_priv_flags_IFF_UNICAST_FLT as u32);
    /// MAC address may change while the interface is running.
    pub const LIVE_ADDRESS_CHANGE: Self =
        Self(bindings::netdev_priv_flags_IFF_LIVE_ADDR_CHANGE as u32);
    /// TX accepts skbs whose linear area may not contain the whole header.
    pub const TX_SKB_NO_LINEAR: Self =
        Self(bindings::netdev_priv_flags_IFF_TX_SKB_NO_LINEAR as u32);

    /// No additional private flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw private flag bits, for framework configuration only.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for PrivateFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for PrivateFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// XDP action capabilities advertised before netdev registration.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XdpFeatures(u32);

impl XdpFeatures {
    /// Basic XDP actions.
    pub const BASIC: Self = Self(bindings::netdev_xdp_act_NETDEV_XDP_ACT_BASIC);
    /// XDP redirect support.
    pub const REDIRECT: Self = Self(bindings::netdev_xdp_act_NETDEV_XDP_ACT_REDIRECT);
    /// AF_XDP zero-copy support.
    pub const XSK_ZERO_COPY: Self = Self(bindings::netdev_xdp_act_NETDEV_XDP_ACT_XSK_ZEROCOPY);
    /// Multi-buffer receive support.
    pub const RX_SCATTER_GATHER: Self = Self(bindings::netdev_xdp_act_NETDEV_XDP_ACT_RX_SG);

    /// No XDP actions.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw XDP capability bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for XdpFeatures {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for XdpFeatures {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Header fields covered by one hardware receive hash reported to an XDP program.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XdpRssHashType(u32);

impl XdpRssHashType {
    /// No protocol classification is available for the hash.
    pub const NONE: Self = Self(0);
    /// IPv4 network-layer fields.
    pub const L3_IPV4: Self = Self(1 << 0);
    /// IPv6 network-layer fields.
    pub const L3_IPV6: Self = Self(1 << 1);
    /// IPv6 network-layer fields with extension headers.
    pub const L3_IPV6_EX: Self = Self((1 << 1) | (1 << 2));
    /// IPv4 and TCP transport fields.
    pub const L4_IPV4_TCP: Self = Self((1 << 0) | (1 << 3) | (1 << 4));
    /// IPv4 and UDP transport fields.
    pub const L4_IPV4_UDP: Self = Self((1 << 0) | (1 << 3) | (1 << 5));
    /// IPv6 and TCP transport fields.
    pub const L4_IPV6_TCP: Self = Self((1 << 1) | (1 << 3) | (1 << 4));
    /// IPv6 and UDP transport fields.
    pub const L4_IPV6_UDP: Self = Self((1 << 1) | (1 << 3) | (1 << 5));
    /// IPv6 extension-header and TCP transport fields.
    pub const L4_IPV6_TCP_EX: Self = Self((1 << 1) | (1 << 2) | (1 << 3) | (1 << 4));
    /// IPv6 extension-header and UDP transport fields.
    pub const L4_IPV6_UDP_EX: Self = Self((1 << 1) | (1 << 2) | (1 << 3) | (1 << 5));

    fn bits(self) -> u32 {
        self.0
    }
}

/// Receive hash and protocol coverage returned by an XDP metadata callback.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XdpRxHash {
    value: u32,
    hash_type: XdpRssHashType,
}

impl XdpRxHash {
    /// Construct one driver-validated receive-hash result.
    pub const fn new(value: u32, hash_type: XdpRssHashType) -> Self {
        Self { value, hash_type }
    }

    /// Hash value reported by the device.
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Packet-header fields covered by the hash.
    pub const fn hash_type(self) -> XdpRssHashType {
        self.hash_type
    }
}

/// Callback-scoped view of one native-XDP receive buffer.
///
/// The raw XDP buffer and receive-queue pointers remain inside this module. Drivers may only copy
/// a checked suffix of the device headroom, which is sufficient for device-specific receive
/// headers placed immediately before the current packet data.
pub struct XdpMetadataContext<'a> {
    raw: NonNull<bindings::xdp_buff>,
    _lifetime: PhantomData<&'a bindings::xdp_md>,
}

impl XdpMetadataContext<'_> {
    unsafe fn from_raw(raw: *const bindings::xdp_md) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw.cast_mut().cast()).ok_or(EINVAL)?,
            _lifetime: PhantomData,
        })
    }

    fn device(&self) -> Result<NonNull<bindings::net_device>> {
        // SAFETY: The callback lifetime guarantees a live XDP buffer and registered RXQ. Null
        // checks make a broken core/driver contract fail closed before constructing a device view.
        let rxq = NonNull::new(unsafe { self.raw.as_ref().rxq }).ok_or(EINVAL)?;
        // SAFETY: `rxq` was checked and is live for the same callback duration.
        NonNull::new(unsafe { rxq.as_ref().dev }).ok_or(EINVAL)
    }

    /// Copy bytes immediately preceding the buffer's current packet-data pointer.
    ///
    /// The requested slice must remain within XDP's hard-start/data headroom. A program that has
    /// adjusted the head beyond the driver's header therefore gets a deterministic error instead
    /// of permitting an out-of-bounds read.
    pub fn read_before_data(&self, output: &mut [u8]) -> Result {
        // SAFETY: The callback keeps the XDP buffer live; these fields are immutable while the
        // metadata callback runs on the owning NAPI CPU.
        let (data, hard_start) = unsafe {
            (
                self.raw.as_ref().data.cast::<u8>(),
                self.raw.as_ref().data_hard_start.cast::<u8>(),
            )
        };
        let data_address = data as usize;
        let hard_start_address = hard_start as usize;
        let available = data_address.checked_sub(hard_start_address).ok_or(EINVAL)?;
        if data.is_null() || hard_start.is_null() || output.len() > available {
            return Err(EINVAL);
        }
        // SAFETY: The address-order and length checks prove the complete source range is between
        // data_hard_start and data. `output` is exclusively writable and cannot overlap it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.sub(output.len()),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        Ok(())
    }
}

/// One reference-counted native XDP program.
pub struct XdpProgram {
    raw: NonNull<bindings::bpf_prog>,
}

// SAFETY: BPF program references are immutable after publication and the kernel reference count
// may be released from any context.
unsafe impl Send for XdpProgram {}
unsafe impl Sync for XdpProgram {}

impl Clone for XdpProgram {
    fn clone(&self) -> Self {
        // SAFETY: `self.raw` owns a live BPF program reference.
        unsafe { bindings::bpf_prog_inc(self.raw.as_ptr()) };
        Self { raw: self.raw }
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        // SAFETY: This object owns exactly one BPF program reference.
        unsafe { bindings::bpf_prog_put(self.raw.as_ptr()) };
    }
}

impl XdpProgram {
    fn acquire(raw: NonNull<bindings::bpf_prog>) -> Self {
        // SAFETY: Networking core supplies a live callback-scoped program reference.
        unsafe { bindings::bpf_prog_inc(raw.as_ptr()) };
        Self { raw }
    }

    /// Whether this program may consume a fragmented XDP buffer.
    pub fn has_fragments(&self) -> bool {
        // SAFETY: The owned reference keeps both the program and its immutable auxiliary state
        // live for this query.
        unsafe { bindings::bpf_prog_xdp_has_frags(self.raw.as_ptr()) }
    }
}

/// XDP-program setup request received under networking core's control-plane serialization.
pub struct XdpProgramSetup<'a> {
    program: Option<NonNull<bindings::bpf_prog>>,
    extack: *mut bindings::netlink_ext_ack,
    _lifetime: PhantomData<&'a bindings::netdev_bpf>,
}

impl XdpProgramSetup<'_> {
    /// Acquire an independently owned reference to the requested program, or `None` for detach.
    pub fn program(&self) -> Option<XdpProgram> {
        self.program.map(XdpProgram::acquire)
    }

    /// Attach a diagnostic to this netlink transaction.
    pub fn set_error(&self, message: &CStr) {
        // SAFETY: `extack` is callback-scoped (and may be NULL); `message` is NUL-terminated and
        // the helper copies it into extack-owned storage.
        unsafe { bindings::netlink_ext_ack_set_error(self.extack, message.as_char_ptr()) };
    }
}

/// AF_XDP pool setup request received under networking core's control-plane serialization.
pub struct XskPoolSetup<'a> {
    pool: Option<NonNull<bindings::xsk_buff_pool>>,
    queue_id: u16,
    _lifetime: PhantomData<&'a bindings::netdev_bpf>,
}

impl XskPoolSetup<'_> {
    /// Queue pair selected by AF_XDP core.
    pub fn queue_id(&self) -> u16 {
        self.queue_id
    }

    /// Whether this request binds a pool; `false` requests unbind.
    pub fn is_enable(&self) -> bool {
        self.pool.is_some()
    }

    /// Acquire, map, and register the requested pool for one pair of virtqueues.
    ///
    /// The returned owner holds an independent pool reference, the bidirectional UMEM mapping,
    /// the shared zero TX-header mapping, and an XSK RXQ registration. Drivers must quiesce and
    /// reset both queues before dropping their final owner.
    pub fn create_virtio_pool<T: Operations>(
        &self,
        device: &Device<T>,
        napi: &Napi<T>,
        rx_queue: &crate::virtio::VirtQueue,
        tx_queue: &crate::virtio::VirtQueue,
        header_len: u32,
        flags: Flags,
    ) -> Result<Arc<VirtioXskPool>> {
        let pool = self.pool.ok_or(EINVAL)?;
        if !napi.token.begin_use() {
            return Err(ENODEV);
        }
        if napi.token.dev.as_ptr() != device.as_raw() {
            napi.token.end_use();
            return Err(EINVAL);
        }
        // SAFETY: The callback-scoped request pins `pool`; the NAPI user pins its registered
        // allocation, and both virtqueues belong to the live driver instance. The helper acquires
        // its own pool reference and unwinds every partial registration on failure.
        let raw = unsafe {
            bindings::virtio_xsk_pool_create(
                pool.as_ptr(),
                rx_queue.as_raw(),
                tx_queue.as_raw(),
                device.as_raw(),
                napi.token.napi.get(),
                self.queue_id.into(),
                header_len,
            )
        };
        napi.token.end_use();
        let raw = NonNull::new(from_err_ptr(raw)?).ok_or(ENOMEM)?;
        // SAFETY: A successful constructor returns a live opaque pool owner.
        let frame_len = unsafe { bindings::virtio_xsk_pool_frame_len(raw.as_ptr()) };
        if frame_len == 0 {
            // SAFETY: `raw` is the uniquely owned successful constructor result.
            unsafe { bindings::virtio_xsk_pool_destroy(raw.as_ptr()) };
            return Err(EINVAL);
        }
        Ok(Arc::new(
            VirtioXskPool {
                raw,
                rx_queue: *rx_queue,
                tx_queue: *tx_queue,
                header_len,
                frame_len,
                rx_allocating: AtomicBool::new(false),
                tx_batch_active: AtomicBool::new(false),
            },
            flags,
        )?)
    }
}

/// Flags supplied to `ndo_xsk_wakeup`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XskWakeupFlags(u32);

impl XskWakeupFlags {
    /// Userspace may need receive-ring progress.
    pub const RECEIVE: Self = Self(1 << 0);
    /// Userspace has transmit descriptors ready.
    pub const TRANSMIT: Self = Self(1 << 1);

    fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Test whether every bit in `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Raw wakeup bits, including future networking-core extensions.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// One independently owned, DMA-mapped AF_XDP pool bound to a virtio queue pair.
pub struct VirtioXskPool {
    raw: NonNull<c_void>,
    rx_queue: crate::virtio::VirtQueue,
    tx_queue: crate::virtio::VirtQueue,
    header_len: u32,
    frame_len: u32,
    rx_allocating: AtomicBool,
    tx_batch_active: AtomicBool,
}

// SAFETY: Atomic reservations serialize both driver-consumed pool rings. Virtqueue submission
// remains serialized by the driver, while this owner exposes only immutable mapped addresses.
unsafe impl Send for VirtioXskPool {}
unsafe impl Sync for VirtioXskPool {}

impl Drop for VirtioXskPool {
    fn drop(&mut self) {
        // SAFETY: This is the final Rust owner. The type contract requires both queues to have
        // been synchronously reset, so no descriptor retains any mapping owned by this handle.
        unsafe { bindings::virtio_xsk_pool_destroy(self.raw.as_ptr()) };
    }
}

impl VirtioXskPool {
    /// Device-visible receive frame size excluding the virtio header.
    pub fn rx_frame_len(&self) -> u32 {
        self.frame_len
    }

    /// Negotiated virtio header length reserved before every receive frame.
    pub fn header_len(&self) -> u32 {
        self.header_len
    }

    /// Allocate a batch of uniquely owned UMEM receive buffers.
    pub fn allocate_rx_batch(
        self: &Arc<Self>,
        maximum: u32,
        flags: Flags,
    ) -> Result<KVec<KBox<VirtioXskRxBuffer>>> {
        if self
            .rx_allocating
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(EBUSY);
        }
        let result = self.allocate_rx_batch_inner(maximum, flags);
        self.rx_allocating.store(false, Ordering::Release);
        result
    }

    fn allocate_rx_batch_inner(
        self: &Arc<Self>,
        maximum: u32,
        flags: Flags,
    ) -> Result<KVec<KBox<VirtioXskRxBuffer>>> {
        if maximum == 0 {
            return Err(EINVAL);
        }
        let maximum = maximum as usize;
        let mut raw_buffers = KVec::with_capacity(maximum, flags)?;
        raw_buffers.resize(maximum, core::ptr::null_mut(), flags)?;
        let mut buffers = KVec::with_capacity(maximum, flags)?;
        // SAFETY: `raw_buffers` has exactly `maximum` writable slots and this owner pins the pool
        // and its DMA mapping throughout allocation.
        let count = unsafe {
            bindings::virtio_xsk_alloc_rx(
                self.raw.as_ptr(),
                raw_buffers.as_mut_ptr(),
                maximum as u32,
            )
        } as usize;
        if count == 0 {
            return Err(ENOMEM);
        }
        if count > maximum {
            return Err(EIO);
        }

        for index in 0..count {
            let Some(raw) = NonNull::new(raw_buffers[index]) else {
                for pointer in &raw_buffers[index + 1..count] {
                    // SAFETY: These entries were returned as owned by the successful batch.
                    unsafe { bindings::virtio_xsk_free_rx(*pointer) };
                }
                return Err(EIO);
            };
            let buffer = match KBox::new(
                VirtioXskRxBuffer {
                    raw: Some(raw),
                    pool: self.clone(),
                    used_length: 0,
                },
                flags,
            ) {
                Ok(buffer) => buffer,
                Err(error) => {
                    for pointer in &raw_buffers[index + 1..count] {
                        // SAFETY: The current value was dropped by `KBox::new`; these later
                        // values have not yet been wrapped.
                        unsafe { bindings::virtio_xsk_free_rx(*pointer) };
                    }
                    return Err(error.into());
                }
            };
            // Capacity was reserved before the C allocation, so this should not allocate. Keep
            // the impossible allocator-failure path ownership-complete nevertheless.
            if let Err(error) = buffers.push(buffer, flags) {
                for pointer in &raw_buffers[index + 1..count] {
                    // SAFETY: These later values have not yet been wrapped.
                    unsafe { bindings::virtio_xsk_free_rx(*pointer) };
                }
                return Err(error.into());
            }
        }
        Ok(buffers)
    }

    /// Transfer one owned XSK receive buffer to the bound virtqueue.
    pub fn submit_rx_buffer(
        &self,
        queue: &crate::virtio::VirtQueue,
        buffer: KBox<VirtioXskRxBuffer>,
        flags: Flags,
    ) -> Result {
        if *queue != self.rx_queue || buffer.pool.raw != self.raw || buffer.used_length != 0 {
            return Err(EINVAL);
        }
        let raw_buffer = buffer.raw.ok_or(EINVAL)?;
        let mut address = 0;
        let mut length = 0;
        // SAFETY: `buffer` owns a pool-produced XDP buffer and the pool mapping remains live.
        to_result(unsafe {
            bindings::virtio_xsk_rx_segment(
                self.raw.as_ptr(),
                raw_buffer.as_ptr(),
                &mut address,
                &mut length,
            )
        })?;
        // SAFETY: The helper derived this range from the live mapping for the exact bound queue;
        // the submitted wrapper retains the pool owner until completion or reset.
        let segment = unsafe { crate::virtio::DmaSegment::from_provider(queue, address, length)? };
        let mut sg = crate::virtio::PremappedSg::new([segment])?;
        let raw = KBox::into_raw(buffer);
        match queue.add_inbuf_premapped(&mut sg, raw.cast(), core::ptr::null_mut(), flags) {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: Submission failed, so the queue never acquired this token.
                drop(unsafe { KBox::<VirtioXskRxBuffer>::from_raw(raw) });
                Err(error)
            }
        }
    }

    /// Restore one completed receive buffer from the bound XSK queue.
    pub fn get_rx_buffer(
        &self,
        queue: &crate::virtio::VirtQueue,
    ) -> Result<Option<(KBox<VirtioXskRxBuffer>, u32)>> {
        if *queue != self.rx_queue {
            return Err(EINVAL);
        }
        let Some((token, used_length)) = queue.get_buf() else {
            return Ok(None);
        };
        // SAFETY: A queue consumed through this typed method contains only tokens installed by
        // `submit_rx_buffer` for the currently bound pool.
        let mut buffer = unsafe { KBox::<VirtioXskRxBuffer>::from_raw(token.cast()) };
        if buffer.pool.raw != self.raw || buffer.raw.is_none() {
            return Err(EIO);
        }
        buffer.used_length = used_length;
        Ok(Some((buffer, used_length)))
    }

    /// Restore one receive token returned synchronously by queue reset or resize.
    ///
    /// The token must have been submitted by [`Self::submit_rx_buffer`].
    pub fn reclaim_rx_buffer(token: *mut c_void) -> Result<KBox<VirtioXskRxBuffer>> {
        if token.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: The method's token contract restores the unique wrapper allocation.
        Ok(unsafe { KBox::<VirtioXskRxBuffer>::from_raw(token.cast()) })
    }

    /// Reserve a prefix of AF_XDP userspace TX descriptors.
    pub fn tx_batch(self: &Arc<Self>, maximum: u32, flags: Flags) -> Result<XskTxBatch> {
        if self
            .tx_batch_active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(EBUSY);
        }
        let result = self.tx_batch_inner(maximum, flags);
        if result.is_err() {
            self.tx_batch_active.store(false, Ordering::Release);
        }
        result
    }

    fn tx_batch_inner(self: &Arc<Self>, maximum: u32, flags: Flags) -> Result<XskTxBatch> {
        let maximum = maximum as usize;
        let mut addresses = KVec::with_capacity(maximum, flags)?;
        let mut lengths = KVec::with_capacity(maximum, flags)?;
        addresses.resize(maximum, 0, flags)?;
        lengths.resize(maximum, 0, flags)?;
        let count = if maximum == 0 {
            0
        } else {
            // SAFETY: Both arrays have `maximum` writable entries and the owner pins the pool.
            (unsafe {
                bindings::virtio_xsk_tx_peek(
                    self.raw.as_ptr(),
                    addresses.as_mut_ptr(),
                    lengths.as_mut_ptr(),
                    maximum as u32,
                )
            }) as usize
        };
        if count > maximum {
            return Err(EIO);
        }
        Ok(XskTxBatch {
            pool: self.clone(),
            addresses,
            lengths,
            count,
            submitted: 0,
        })
    }

    /// Return completed userspace TX descriptors to the AF_XDP completion ring.
    pub fn complete_tx(&self, count: u32) {
        // SAFETY: The driver calls this exactly once for each completed or synchronously detached
        // XSK-tagged virtqueue token.
        unsafe { bindings::virtio_xsk_tx_completed(self.raw.as_ptr(), count) };
    }

    /// Whether userspace requested explicit TX wakeup notification.
    pub fn uses_need_wakeup(&self) -> bool {
        // SAFETY: The owned pool remains live for this immutable query.
        unsafe { bindings::virtio_xsk_uses_need_wakeup(self.raw.as_ptr()) }
    }

    /// Publish that the TX producer currently needs a driver wakeup.
    pub fn set_tx_need_wakeup(&self) {
        // SAFETY: The owned pool remains live and AF_XDP serializes its wakeup flags.
        unsafe { bindings::virtio_xsk_set_tx_need_wakeup(self.raw.as_ptr()) };
    }
}

/// One uniquely owned AF_XDP receive buffer.
pub struct VirtioXskRxBuffer {
    raw: Option<NonNull<bindings::xdp_buff>>,
    pool: Arc<VirtioXskPool>,
    used_length: u32,
}

// SAFETY: A unique buffer may move between the allocation/refill and NAPI contexts; the UMEM
// mapping remains pinned by `pool` and no CPU access occurs while the virtqueue owns the wrapper.
unsafe impl Send for VirtioXskRxBuffer {}

impl Drop for VirtioXskRxBuffer {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            // SAFETY: A present pointer is uniquely owned and has not been transferred to XDP
            // redirect or frame conversion.
            unsafe { bindings::virtio_xsk_free_rx(raw.as_ptr()) };
        }
    }
}

/// Validated first-buffer metadata from one XSK virtio receive completion.
pub struct VirtioXskRxHeader {
    buffer_count: u16,
    flags: u8,
}

impl VirtioXskRxHeader {
    /// Number of virtqueue buffers making up this packet.
    pub fn buffer_count(&self) -> u16 {
        self.buffer_count
    }

    /// Device-provided virtio header flags saved before native XDP may mutate memory.
    pub fn flags(&self) -> u8 {
        self.flags
    }
}

impl VirtioXskRxBuffer {
    /// Validate and read the first completed virtio header after DMA synchronization.
    pub fn header(&self, mergeable: bool, little_endian: bool) -> Result<VirtioXskRxHeader> {
        let raw = self.raw.ok_or(EINVAL)?;
        let mut buffer_count = 0;
        let mut flags = 0;
        // SAFETY: Completion restored CPU ownership; the helper bounds every header access by the
        // negotiated frame/header lengths and synchronizes the mapped UMEM range first.
        to_result(unsafe {
            bindings::virtio_xsk_rx_header(
                self.pool.raw.as_ptr(),
                raw.as_ptr(),
                self.used_length,
                mergeable,
                little_endian,
                &mut buffer_count,
                &mut flags,
            )
        })?;
        Ok(VirtioXskRxHeader {
            buffer_count,
            flags,
        })
    }

    /// Used length reported by the device, including the first buffer's virtio header.
    pub fn used_length(&self) -> u32 {
        self.used_length
    }

    /// Start a receive frame with this completed first buffer.
    pub fn into_frame(buffer: KBox<Self>, flags: Flags) -> Result<VirtioXskRxFrame> {
        if buffer.used_length == 0 {
            return Err(EINVAL);
        }
        let pool = buffer.pool.clone();
        let mut buffers = KVec::with_capacity(1, flags)?;
        buffers.push(buffer, flags)?;
        Ok(VirtioXskRxFrame { pool, buffers })
    }

    fn take_raw(mut buffer: KBox<Self>) -> Result<*mut bindings::xdp_buff> {
        let raw = buffer.raw.take().ok_or(EINVAL)?.as_ptr();
        drop(buffer);
        Ok(raw)
    }
}

/// One complete XSK receive packet assembled from its mergeable virtqueue buffers.
pub struct VirtioXskRxFrame {
    pool: Arc<VirtioXskPool>,
    buffers: KVec<KBox<VirtioXskRxBuffer>>,
}

impl VirtioXskRxFrame {
    /// Append one completed mergeable tail buffer.
    pub fn append(&mut self, buffer: KBox<VirtioXskRxBuffer>, flags: Flags) -> Result {
        if buffer.pool.raw != self.pool.raw || buffer.used_length == 0 {
            return Err(EINVAL);
        }
        self.buffers.push(buffer, flags)?;
        Ok(())
    }

    /// Number of virtqueue buffers in this packet.
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Payload bytes across all buffers, excluding the first virtio header.
    pub fn packet_len(&self) -> u32 {
        self.buffers
            .iter()
            .enumerate()
            .fold(0u32, |total, (index, buffer)| {
                let length = if index == 0 {
                    buffer.used_length.saturating_sub(self.pool.header_len)
                } else {
                    buffer.used_length
                };
                total.saturating_add(length)
            })
    }
}

/// Reserved AF_XDP TX descriptors with fail-closed completion accounting.
pub struct XskTxBatch {
    pool: Arc<VirtioXskPool>,
    addresses: KVec<u64>,
    lengths: KVec<u32>,
    count: usize,
    submitted: usize,
}

impl XskTxBatch {
    /// Number of descriptors reserved from userspace.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no descriptors were available.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of reserved descriptors not yet transferred to the virtqueue.
    pub fn remaining(&self) -> usize {
        self.count - self.submitted
    }

    /// Submit the next descriptor and return its packet length.
    pub fn submit_next(&mut self, queue: &crate::virtio::VirtQueue, flags: Flags) -> Result<u32> {
        if *queue != self.pool.tx_queue {
            return Err(EINVAL);
        }
        let address = *self.addresses.get(self.submitted).ok_or(ENOSPC)?;
        let length = *self.lengths.get(self.submitted).ok_or(ENOSPC)?;
        let mut header_address = 0;
        let mut data_address = 0;
        let mut header_length = 0;
        // SAFETY: The descriptor is in the reserved prefix and the pool pins both mappings. The
        // helper resolves the UMEM DMA address and synchronizes exactly `length` bytes.
        to_result(unsafe {
            bindings::virtio_xsk_tx_segments(
                self.pool.raw.as_ptr(),
                address,
                length,
                &mut header_address,
                &mut data_address,
                &mut header_length,
            )
        })?;
        // SAFETY: Both addresses were returned from mappings owned by this pool for `queue`; the
        // pool remains live until every submitted XSK token is completed during normal or reset
        // processing.
        let header = unsafe {
            crate::virtio::DmaSegment::from_provider(queue, header_address, header_length)?
        };
        // SAFETY: Same mapping and lifetime argument as the shared header segment.
        let data =
            unsafe { crate::virtio::DmaSegment::from_provider(queue, data_address, length)? };
        queue.add_xsk_tx_segments([header, data], length, flags)?;
        self.submitted += 1;
        Ok(length)
    }
}

impl Drop for XskTxBatch {
    fn drop(&mut self) {
        let remaining = self.remaining().min(u32::MAX as usize) as u32;
        if remaining != 0 {
            self.pool.complete_tx(remaining);
        }
        self.pool.tx_batch_active.store(false, Ordering::Release);
    }
}

/// Flags supplied with a native XDP frame batch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XdpXmitFlags(u32);

impl XdpXmitFlags {
    /// Notify the device after accepting this batch.
    pub const FLUSH: Self = Self(1 << 0);

    /// No flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Construct from networking-core bits for driver-side validation.
    fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Test whether every bit in `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether this flag set contains only networking core's defined XDP transmit bits.
    pub const fn is_valid(self) -> bool {
        self.0 & !Self::FLUSH.0 == 0
    }
}

/// An owned native XDP frame.
pub struct XdpFrame {
    raw: NonNull<bindings::xdp_frame>,
}

// SAFETY: A uniquely owned XDP frame may move between CPUs; XDP core selects the correct memory
// model when the final reference is returned.
unsafe impl Send for XdpFrame {}

impl XdpFrame {
    pub(crate) unsafe fn from_raw(raw: *mut bindings::xdp_frame) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw).ok_or(EINVAL)?,
        })
    }

    pub(crate) fn as_raw(&self) -> *mut bindings::xdp_frame {
        self.raw.as_ptr()
    }

    pub(crate) fn into_raw(self) -> *mut bindings::xdp_frame {
        let raw = self.raw.as_ptr();
        mem::forget(self);
        raw
    }

    /// Current complete frame length, including all XDP fragments.
    pub fn len(&self) -> u32 {
        // SAFETY: The owned pointer remains live for the synchronous query.
        unsafe { bindings::xdp_frame_len(self.raw.as_ptr()) }
    }

    /// Whether the frame currently has no packet bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for XdpFrame {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the frame and has not transferred it to a device queue.
        unsafe { bindings::xdp_return_frame(self.raw.as_ptr()) };
    }
}

/// Result of running one received virtio frame through a native XDP program.
pub enum XdpReceive {
    /// The adjusted packet was converted to an skb and delivered to GRO.
    Pass { packet_len: u32 },
    /// The program or validation path dropped the packet.
    Drop,
    /// The program transferred the packet to the driver's XDP transmit path.
    Transmit(XdpFrame),
    /// XDP core accepted a redirect; the NAPI poll must flush redirects before returning.
    Redirect,
}

/// Callback-scoped native XDP frame array.
///
/// Frames can only be accepted in prefix order. [`Self::submit_next`] both queues the frame and
/// advances the accepted count, preventing a driver from publishing an ownership transfer without
/// returning the matching count to networking core.
pub struct XdpFrameBatch<'a> {
    frames: &'a mut [*mut bindings::xdp_frame],
    accepted: usize,
}

impl XdpFrameBatch<'_> {
    fn new(frames: &mut [*mut bindings::xdp_frame]) -> Result<XdpFrameBatch<'_>> {
        if frames.iter().any(|frame| frame.is_null()) {
            return Err(EINVAL);
        }
        Ok(XdpFrameBatch {
            frames,
            accepted: 0,
        })
    }

    /// Number of frames supplied by networking core.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether the supplied batch is empty.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Number of frames not yet transferred.
    pub fn remaining(&self) -> usize {
        self.frames.len() - self.accepted
    }

    /// Submit the next frame to a virtqueue and atomically account its ownership transfer.
    pub fn submit_next(&mut self, queue: &crate::virtio::VirtQueue, header_len: u32) -> Result {
        let frame = *self.frames.get(self.accepted).ok_or(ENOSPC)?;
        queue.add_borrowed_xdp_frame(frame, header_len, GFP_ATOMIC)?;
        self.accepted += 1;
        Ok(())
    }

    fn accepted(&self) -> usize {
        self.accepted
    }
}

/// Flush all XDP redirects accumulated on the current NAPI CPU.
pub fn xdp_do_flush() {
    // SAFETY: Callers invoke this before returning from the same NAPI poll that accepted redirects.
    unsafe { bindings::xdp_do_flush() };
}

/// Maximum MTU accepted by a linear order-0 XDP receive buffer.
pub fn xdp_max_mtu_no_fragments() -> u32 {
    // SAFETY: This helper only evaluates kernel layout constants.
    unsafe { bindings::xdp_max_mtu_no_frags() }
}

/// Page space reserved around a device-visible native-XDP receive buffer.
#[derive(Clone, Copy)]
pub struct XdpRxPageLayout {
    headroom: usize,
    tailroom: usize,
}

impl XdpRxPageLayout {
    /// Bytes kept before the virtio header for XDP head adjustment and frame conversion.
    pub const fn headroom(self) -> usize {
        self.headroom
    }

    /// Bytes kept after the device-visible buffer for XDP fragment metadata.
    pub const fn tailroom(self) -> usize {
        self.tailroom
    }
}

/// Layout required when posting an order-0 receive page that may enter native XDP.
pub fn xdp_rx_page_layout() -> XdpRxPageLayout {
    let headroom = bindings::XDP_PACKET_HEADROOM as usize;
    // SAFETY: This helper only evaluates the matching kernel layout and alignment constants. The
    // reserve always contains `XDP_PACKET_HEADROOM`; saturating subtraction keeps this safe even
    // if that internal C invariant is broken by a future kernel change.
    let reserve = unsafe { bindings::xdp_rx_page_reserve() } as usize;
    XdpRxPageLayout {
        headroom,
        tailroom: reserve.saturating_sub(headroom),
    }
}

/// Pre-publication Ethernet configuration applied atomically by [`Registration::configure`].
pub struct EthernetConfig {
    private_flags: PrivateFlags,
    features: Features,
    hardware_features: Features,
    hardware_encapsulation_features: Features,
    vlan_features: Features,
    xdp_features: XdpFeatures,
    xdp_rx_hash_metadata: bool,
    rx_queue_sysfs: bool,
    min_mtu: u32,
    max_mtu: u32,
    mtu: u32,
    needed_headroom: u16,
}

impl EthernetConfig {
    /// Start a configuration with a validated MTU range and selected initial MTU.
    pub fn new(min_mtu: u32, max_mtu: u32, mtu: u32) -> Result<Self> {
        if min_mtu == 0 || min_mtu > mtu || mtu > max_mtu {
            return Err(EINVAL);
        }
        Ok(Self {
            private_flags: PrivateFlags::empty(),
            features: Features::empty(),
            hardware_features: Features::empty(),
            hardware_encapsulation_features: Features::empty(),
            vlan_features: Features::empty(),
            xdp_features: XdpFeatures::empty(),
            xdp_rx_hash_metadata: false,
            rx_queue_sysfs: false,
            min_mtu,
            max_mtu,
            mtu,
            needed_headroom: 0,
        })
    }

    /// Add private netdev capability flags.
    pub fn private_flags(mut self, flags: PrivateFlags) -> Self {
        self.private_flags = flags;
        self
    }

    /// Set initially enabled networking features.
    pub fn features(mut self, features: Features) -> Self {
        self.features = features;
        self
    }

    /// Set features userspace may enable.
    pub fn hardware_features(mut self, features: Features) -> Self {
        self.hardware_features = features;
        self
    }

    /// Set features supported for encapsulated traffic.
    pub fn hardware_encapsulation_features(mut self, features: Features) -> Self {
        self.hardware_encapsulation_features = features;
        self
    }

    /// Set features inherited by VLAN devices.
    pub fn vlan_features(mut self, features: Features) -> Self {
        self.vlan_features = features;
        self
    }

    /// Set advertised XDP capabilities.
    pub fn xdp_features(mut self, features: XdpFeatures) -> Self {
        self.xdp_features = features;
        self
    }

    /// Advertise the typed native-XDP receive-hash metadata callback.
    pub fn xdp_rx_hash_metadata(mut self, enabled: bool) -> Self {
        self.xdp_rx_hash_metadata = enabled;
        self
    }

    /// Install the operation type's read-only per-RX-queue sysfs attribute before publication.
    pub fn rx_queue_sysfs(mut self, enabled: bool) -> Self {
        self.rx_queue_sysfs = enabled;
        self
    }

    /// Reserve additional packet headroom.
    pub fn needed_headroom(mut self, bytes: u16) -> Self {
        self.needed_headroom = bytes;
        self
    }
}

/// Networking-core counters used by virtio-net's aggregate statistics and failure paths.
#[derive(Clone, Copy)]
pub enum CoreStat {
    /// Packets dropped by the TX path.
    TxDropped,
    /// Unexpected TX queue/descriptor failures.
    TxFifoErrors,
    /// Receive length errors.
    RxLengthErrors,
    /// Receive framing errors.
    RxFrameErrors,
}

impl CoreStat {
    fn as_raw(self) -> u32 {
        match self {
            Self::TxDropped => 0,
            Self::TxFifoErrors => 1,
            Self::RxLengthErrors => 2,
            Self::RxFrameErrors => 3,
        }
    }
}

/// VLAN protocol and identifier supplied by networking core.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VlanTag {
    protocol: u16,
    id: u16,
}

impl VlanTag {
    /// Host-endian EtherType.
    pub const fn protocol(self) -> u16 {
        self.protocol
    }

    /// VLAN identifier in the inclusive range 0..=4095.
    pub const fn id(self) -> u16 {
        self.id
    }
}

/// Owned physical-port name with the kernel `IFNAMSIZ - 1` limit.
#[derive(Clone, Copy)]
pub struct PhysPortName {
    bytes: [u8; bindings::IFNAMSIZ as usize - 1],
    len: usize,
}

impl PhysPortName {
    /// Copy a non-NUL byte string into an owned physical-port name.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty()
            || name.len() >= bindings::IFNAMSIZ as usize
            || name.iter().any(|byte| *byte == 0)
        {
            return Err(EINVAL);
        }
        let mut bytes = [0; bindings::IFNAMSIZ as usize - 1];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Complete 64-bit link statistics snapshot returned by [`Operations::get_stats64`].
#[derive(Clone, Copy, Default)]
pub struct LinkStats64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,
    pub rx_otherhost_dropped: u64,
}

impl LinkStats64 {
    fn into_raw(self) -> bindings::rtnl_link_stats64 {
        bindings::rtnl_link_stats64 {
            rx_packets: self.rx_packets,
            tx_packets: self.tx_packets,
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            rx_errors: self.rx_errors,
            tx_errors: self.tx_errors,
            rx_dropped: self.rx_dropped,
            tx_dropped: self.tx_dropped,
            multicast: self.multicast,
            collisions: self.collisions,
            rx_length_errors: self.rx_length_errors,
            rx_over_errors: self.rx_over_errors,
            rx_crc_errors: self.rx_crc_errors,
            rx_frame_errors: self.rx_frame_errors,
            rx_fifo_errors: self.rx_fifo_errors,
            rx_missed_errors: self.rx_missed_errors,
            tx_aborted_errors: self.tx_aborted_errors,
            tx_carrier_errors: self.tx_carrier_errors,
            tx_fifo_errors: self.tx_fifo_errors,
            tx_heartbeat_errors: self.tx_heartbeat_errors,
            tx_window_errors: self.tx_window_errors,
            rx_compressed: self.rx_compressed,
            tx_compressed: self.tx_compressed,
            rx_nohandler: self.rx_nohandler,
            rx_otherhost_dropped: self.rx_otherhost_dropped,
        }
    }
}

/// Receive-queue statistics whose absent fields remain undefined to networking core.
#[derive(Clone, Copy, Default)]
pub struct QueueStatsRx {
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub alloc_fail: Option<u64>,
    pub hw_drops: Option<u64>,
    pub hw_drop_overruns: Option<u64>,
    pub csum_complete: Option<u64>,
    pub csum_unnecessary: Option<u64>,
    pub csum_none: Option<u64>,
    pub csum_bad: Option<u64>,
    pub hw_gro_packets: Option<u64>,
    pub hw_gro_bytes: Option<u64>,
    pub hw_gro_wire_packets: Option<u64>,
    pub hw_gro_wire_bytes: Option<u64>,
    pub hw_drop_ratelimits: Option<u64>,
}

impl QueueStatsRx {
    fn write_raw(self, output: *mut bindings::netdev_queue_stats_rx) {
        macro_rules! write_field {
            ($field:ident) => {
                if let Some(value) = self.$field {
                    // SAFETY: The callback adapter validated that `output` is exclusive storage.
                    unsafe { (*output).$field = value };
                }
            };
        }
        write_field!(bytes);
        write_field!(packets);
        write_field!(alloc_fail);
        write_field!(hw_drops);
        write_field!(hw_drop_overruns);
        write_field!(csum_complete);
        write_field!(csum_unnecessary);
        write_field!(csum_none);
        write_field!(csum_bad);
        write_field!(hw_gro_packets);
        write_field!(hw_gro_bytes);
        write_field!(hw_gro_wire_packets);
        write_field!(hw_gro_wire_bytes);
        write_field!(hw_drop_ratelimits);
    }
}

/// Transmit-queue statistics whose absent fields remain undefined to networking core.
#[derive(Clone, Copy, Default)]
pub struct QueueStatsTx {
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub hw_drops: Option<u64>,
    pub hw_drop_errors: Option<u64>,
    pub csum_none: Option<u64>,
    pub needs_csum: Option<u64>,
    pub hw_gso_packets: Option<u64>,
    pub hw_gso_bytes: Option<u64>,
    pub hw_gso_wire_packets: Option<u64>,
    pub hw_gso_wire_bytes: Option<u64>,
    pub hw_drop_ratelimits: Option<u64>,
    pub stop: Option<u64>,
    pub wake: Option<u64>,
}

impl QueueStatsTx {
    fn write_raw(self, output: *mut bindings::netdev_queue_stats_tx) {
        macro_rules! write_field {
            ($field:ident) => {
                if let Some(value) = self.$field {
                    // SAFETY: The callback adapter validated that `output` is exclusive storage.
                    unsafe { (*output).$field = value };
                }
            };
        }
        write_field!(bytes);
        write_field!(packets);
        write_field!(hw_drops);
        write_field!(hw_drop_errors);
        write_field!(csum_none);
        write_field!(needs_csum);
        write_field!(hw_gso_packets);
        write_field!(hw_gso_bytes);
        write_field!(hw_gso_wire_packets);
        write_field!(hw_gso_wire_bytes);
        write_field!(hw_drop_ratelimits);
        write_field!(stop);
        write_field!(wake);
    }
}

/// One ethtool string-set identifier.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EthtoolStringSet(u32);

impl EthtoolStringSet {
    /// Driver statistics names and values.
    pub const STATS: Self = Self(bindings::ethtool_stringset_ETH_SS_STATS);

    const fn from_raw(value: u32) -> Self {
        Self(value)
    }
}

/// Fixed-width ethtool string-set output borrowed for one callback.
pub struct EthtoolStrings<'a> {
    bytes: &'a mut [u8],
    next: usize,
}

impl EthtoolStrings<'_> {
    /// Append one NUL-terminated, zero-padded ethtool string.
    pub fn push(&mut self, name: &[u8]) -> Result {
        let width = bindings::ETH_GSTRING_LEN as usize;
        if name.len() >= width || name.contains(&0) {
            return Err(EINVAL);
        }
        let start = self.next.checked_mul(width).ok_or(EOVERFLOW)?;
        let end = start.checked_add(width).ok_or(EOVERFLOW)?;
        let slot = self.bytes.get_mut(start..end).ok_or(ENOSPC)?;
        slot.fill(0);
        slot[..name.len()].copy_from_slice(name);
        self.next += 1;
        Ok(())
    }
}

/// Borrowed, bounded text returned through ethtool's driver-information callback.
pub struct EthtoolDriverInfo<'a> {
    driver: &'a CStr,
    version: &'a CStr,
    bus_info: &'a CStr,
}

impl<'a> EthtoolDriverInfo<'a> {
    /// Create one driver-information record. Each field is truncated with a trailing NUL by the
    /// callback adapter when it is copied into networking core's fixed-size buffers.
    pub const fn new(driver: &'a CStr, version: &'a CStr, bus_info: &'a CStr) -> Self {
        Self {
            driver,
            version,
            bus_info,
        }
    }
}

/// Maximum and current ring sizes exposed through ethtool.
#[derive(Clone, Copy, Default)]
pub struct EthtoolRingParameters {
    pub rx_max_pending: u32,
    pub rx_mini_max_pending: u32,
    pub rx_jumbo_max_pending: u32,
    pub tx_max_pending: u32,
    pub rx_pending: u32,
    pub rx_mini_pending: u32,
    pub rx_jumbo_pending: u32,
    pub tx_pending: u32,
}

/// Supported and active queue/channel counts exposed through ethtool.
#[derive(Clone, Copy, Default)]
pub struct EthtoolChannels {
    pub max_rx: u32,
    pub max_tx: u32,
    pub max_other: u32,
    pub max_combined: u32,
    pub rx_count: u32,
    pub tx_count: u32,
    pub other_count: u32,
    pub combined_count: u32,
}

/// Notification-coalescing fields supported by virtio-net's ethtool contract.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct EthtoolCoalesce {
    pub rx_coalesce_usecs: u32,
    pub rx_max_coalesced_frames: u32,
    pub tx_coalesce_usecs: u32,
    pub tx_max_coalesced_frames: u32,
    pub use_adaptive_rx_coalesce: bool,
}

/// Receive interrupt moderation selected by networking core's DIM algorithm.
#[cfg(CONFIG_DIMLIB)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct RxDimModeration {
    pub usecs: u16,
    pub packets: u16,
}

/// Virtual link settings copied between a driver and ethtool.
#[derive(Clone, Copy)]
pub struct EthtoolLinkSettings {
    pub speed: u32,
    pub duplex: u8,
    pub port: u8,
}

impl Default for EthtoolLinkSettings {
    fn default() -> Self {
        Self {
            speed: bindings::SPEED_UNKNOWN as u32,
            duplex: bindings::DUPLEX_UNKNOWN as u8,
            port: bindings::PORT_OTHER as u8,
        }
    }
}

/// RSS hash-function selector used by ethtool.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EthtoolRssHashFunction(u8);

impl EthtoolRssHashFunction {
    /// Leave the configured function unchanged on update.
    pub const NO_CHANGE: Self = Self(bindings::ETH_RSS_HASH_NO_CHANGE as u8);
    /// Toeplitz hash function used by virtio-net.
    pub const TOEPLITZ: Self = Self(1u8 << bindings::ETH_RSS_HASH_TOP_BIT);

    /// Construct a selector from networking-core bits.
    pub const fn from_raw(value: u8) -> Self {
        Self(value)
    }

    /// Raw networking-core selector.
    pub const fn as_raw(self) -> u8 {
        self.0
    }
}

/// Borrowed RSS update supplied by networking core.
pub struct EthtoolRssParameters<'a> {
    hash_function: EthtoolRssHashFunction,
    indirection: Option<&'a [u32]>,
    key: Option<&'a [u8]>,
}

impl EthtoolRssParameters<'_> {
    /// Requested hash function, or [`EthtoolRssHashFunction::NO_CHANGE`].
    pub const fn hash_function(&self) -> EthtoolRssHashFunction {
        self.hash_function
    }

    /// Optional complete indirection-table replacement.
    pub fn indirection(&self) -> Option<&[u32]> {
        self.indirection
    }

    /// Optional complete hash-key replacement.
    pub fn key(&self) -> Option<&[u8]> {
        self.key
    }
}

/// Packet flow type used by ethtool RSS field selection.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EthtoolRssFlowType(u32);

impl EthtoolRssFlowType {
    pub const TCP_V4: Self = Self(bindings::TCP_V4_FLOW);
    pub const UDP_V4: Self = Self(bindings::UDP_V4_FLOW);
    pub const TCP_V6: Self = Self(bindings::TCP_V6_FLOW);
    pub const UDP_V6: Self = Self(bindings::UDP_V6_FLOW);
    pub const IP_V4: Self = Self(bindings::IPV4_FLOW);
    pub const IP_V6: Self = Self(bindings::IPV6_FLOW);

    /// Construct from an arbitrary networking-core flow identifier.
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Raw networking-core flow identifier.
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// Input fields selected for one RSS flow type.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EthtoolRssFlowFields(u32);

impl EthtoolRssFlowFields {
    pub const DISCARD: Self = Self(bindings::RXH_DISCARD);
    pub const IP_SOURCE: Self = Self(bindings::RXH_IP_SRC);
    pub const IP_DESTINATION: Self = Self(bindings::RXH_IP_DST);
    pub const L4_BYTES_0_1: Self = Self(bindings::RXH_L4_B_0_1);
    pub const L4_BYTES_2_3: Self = Self(bindings::RXH_L4_B_2_3);

    /// No selected fields.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Construct from networking-core bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Raw networking-core bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for EthtoolRssFlowFields {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Kind of NAPI registration required by a network queue.
pub enum NapiKind {
    /// Receive NAPI with persistent per-device configuration at `config_index`.
    Receive { config_index: u32 },
    /// Transmit-only NAPI, excluded from the receive busy-poll hash.
    Transmit,
}

/// Network queue direction used by `netif_queue_set_napi`.
#[derive(Clone, Copy)]
pub enum QueueType {
    /// Receive queue.
    Receive,
    /// Transmit queue.
    Transmit,
}

/// Validated options for converting one completed virtio-net buffer into an skb.
#[derive(Clone, Copy)]
pub struct VirtioRxOptions {
    header_len: u32,
    little_endian: bool,
    mergeable_buffers: bool,
    hash_report: bool,
    tunnel_header_negotiated: bool,
    tunnel_checksum_negotiated: bool,
    queue_index: u32,
}

impl VirtioRxOptions {
    /// Create options for a negotiated virtio-net header.
    pub fn new(header_len: u32, little_endian: bool) -> Result<Self> {
        if !(10..=24).contains(&header_len) {
            return Err(EINVAL);
        }
        Ok(Self {
            header_len,
            little_endian,
            mergeable_buffers: false,
            hash_report: false,
            tunnel_header_negotiated: false,
            tunnel_checksum_negotiated: false,
            queue_index: 0,
        })
    }

    /// Use the mergeable-buffer native-XDP header and metadata contract.
    pub fn mergeable_buffers(mut self, enabled: bool) -> Self {
        self.mergeable_buffers = enabled;
        self
    }

    /// Interpret the negotiated hash-report extension.
    pub fn hash_report(mut self, enabled: bool) -> Self {
        self.hash_report = enabled;
        self
    }

    /// Interpret the negotiated UDP tunnel-header extension.
    pub fn tunnel_header(mut self, enabled: bool) -> Self {
        self.tunnel_header_negotiated = enabled;
        self
    }

    /// Accept the negotiated UDP tunnel checksum-valid flag.
    pub fn tunnel_checksum(mut self, enabled: bool) -> Self {
        self.tunnel_checksum_negotiated = enabled;
        self
    }

    /// Record the receive queue selected by the device.
    pub fn queue(mut self, index: u32) -> Self {
        self.queue_index = index;
        self
    }
}

impl QueueType {
    fn as_raw(self) -> bindings::netdev_queue_type {
        match self {
            Self::Receive => bindings::netdev_queue_type_NETDEV_QUEUE_TYPE_RX,
            Self::Transmit => bindings::netdev_queue_type_NETDEV_QUEUE_TYPE_TX,
        }
    }
}

/// Callback-scoped view of one live NAPI context.
pub struct NapiContext<'a> {
    raw: NonNull<bindings::napi_struct>,
    context: u32,
    _lifetime: PhantomData<&'a bindings::napi_struct>,
}

impl NapiContext<'_> {
    /// Driver-defined queue/context identifier supplied at registration.
    pub fn context(&self) -> u32 {
        self.context
    }

    /// Networking-core NAPI identifier.
    pub fn id(&self) -> u32 {
        // SAFETY: This view exists only for the duration of a live poll callback.
        unsafe { (*self.raw.as_ptr()).napi_id }
    }

    /// Try to lock one transmit queue without blocking this NAPI poll.
    pub fn try_lock_tx_queue<'a, T: Operations>(
        &'a self,
        device: &'a Device<T>,
        index: u32,
    ) -> Result<Option<TxQueueTryGuard<'a, T>>> {
        let mut raw = core::ptr::null_mut();
        // SAFETY: A `NapiContext` exists only inside a live networking poll, which provides the
        // bottom-half exclusion required by `__netif_tx_trylock`. The helper validates `index`
        // and leaves `raw` null on contention. A non-null guard is tied to both callback borrows.
        to_result(unsafe { bindings::netdev_tx_queue_trylock(device.as_raw(), index, &mut raw) })?;
        Ok(NonNull::new(raw).map(|raw| TxQueueTryGuard {
            raw,
            _device: PhantomData,
            _not_send: PhantomData,
        }))
    }

    /// Complete a poll cycle after `work_done` items.
    pub fn complete_done(&self, work_done: u32) -> bool {
        let work_done = work_done.min(c_int::MAX as u32) as c_int;
        // SAFETY: `raw` is the live NAPI context currently being polled.
        unsafe { bindings::napi_complete_done(self.raw.as_ptr(), work_done) }
    }

    /// Copy a completed virtio-net frame into an skb, validate negotiated
    /// checksum/GSO/hash/tunnel metadata, and transfer it to GRO.
    pub fn receive_virtio<T: Operations>(
        &self,
        device: &Device<T>,
        buffer: &[u8],
        options: VirtioRxOptions,
    ) -> Result {
        let length = u32::try_from(buffer.len()).map_err(|_| EOVERFLOW)?;
        if length < options.header_len {
            return Err(EINVAL);
        }
        // SAFETY: The helper consumes the slices synchronously, validates all
        // header-dependent accesses, and transfers any successfully built skb
        // directly to this live NAPI context.
        to_result(unsafe {
            bindings::napi_receive_virtio(
                self.raw.as_ptr(),
                device.as_raw(),
                buffer.as_ptr(),
                length,
                options.header_len,
                options.little_endian,
                options.hash_report,
                options.tunnel_header_negotiated,
                options.tunnel_checksum_negotiated,
                options.queue_index,
            )
        })
    }

    /// Build an skb from an owned, completed page-backed virtio-net frame and transfer it to GRO.
    ///
    /// The frame remains owned by Rust for the synchronous helper call. Networking core takes an
    /// additional page reference for every range attached to the skb, so dropping the frame after
    /// return is balanced on both success and failure paths.
    pub fn receive_virtio_pages<T: Operations>(
        &self,
        device: &Device<T>,
        frame: crate::virtio::RxPageFrame,
        options: VirtioRxOptions,
    ) -> Result {
        if frame.len() < options.header_len as usize + bindings::ETH_HLEN as usize {
            return Err(EINVAL);
        }
        let count = u32::try_from(frame.fragments().len()).map_err(|_| EOVERFLOW)?;
        if count == 0 {
            return Err(EINVAL);
        }
        let mut pages = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut offsets = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut lengths = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut truesizes = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        for fragment in frame.fragments() {
            pages.push(fragment.page().as_ptr(), GFP_ATOMIC)?;
            offsets.push(fragment.offset, GFP_ATOMIC)?;
            lengths.push(fragment.length, GFP_ATOMIC)?;
            truesizes.push(fragment.truesize, GFP_ATOMIC)?;
        }
        // SAFETY: Every array has exactly `count` initialized entries. The frame owns every live
        // page reference for the duration of this synchronous call; ranges were produced from
        // checked DMA mappings, and the helper takes separate references before attaching pages.
        to_result(unsafe {
            bindings::napi_receive_virtio_pages(
                self.raw.as_ptr(),
                device.as_raw(),
                pages.as_ptr(),
                offsets.as_ptr(),
                lengths.as_ptr(),
                truesizes.as_ptr(),
                count,
                options.header_len,
                options.little_endian,
                options.hash_report,
                options.tunnel_header_negotiated,
                options.tunnel_checksum_negotiated,
                options.queue_index,
            )
        })
    }

    /// Run one completed page-backed virtio-net frame through a native XDP program.
    ///
    /// The helper copies an order-0 XDP head from the borrowed frame. Programs without fragment
    /// support receive a linearized packet; fragment-capable programs retain mergeable-buffer
    /// boundaries as copied order-0 XDP fragments. The original Rust owner therefore remains
    /// balanced on every action. PASS transfers all copied pages through an skb, TX returns a
    /// unique [`XdpFrame`], REDIRECT transfers them to XDP core, and every failure releases them
    /// before returning.
    pub fn receive_virtio_xdp_pages<T: Operations>(
        &self,
        device: &Device<T>,
        rxq: &XdpRxQueue,
        program: &XdpProgram,
        frame: crate::virtio::RxPageFrame,
        options: VirtioRxOptions,
    ) -> Result<XdpReceive> {
        if frame.len() < options.header_len as usize + bindings::ETH_HLEN as usize {
            return Err(EINVAL);
        }
        let count = u32::try_from(frame.fragments().len()).map_err(|_| EOVERFLOW)?;
        if count == 0 {
            return Err(EINVAL);
        }
        let mut pages = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut offsets = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut lengths = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        let mut truesizes = KVec::with_capacity(count as usize, GFP_ATOMIC)?;
        for fragment in frame.fragments() {
            pages.push(fragment.page().as_ptr(), GFP_ATOMIC)?;
            offsets.push(fragment.offset, GFP_ATOMIC)?;
            lengths.push(fragment.length, GFP_ATOMIC)?;
            truesizes.push(fragment.truesize, GFP_ATOMIC)?;
        }

        let mut tx_frame = core::ptr::null_mut();
        let mut packet_len = 0u32;
        let result = rxq.with_raw(|raw_rxq| {
            // SAFETY: Every array has exactly `count` entries and `frame` owns all page references
            // for this synchronous call. `rxq` pins its registration and `program` owns its BPF
            // reference. The helper fully resolves ownership of every copied XDP page before
            // return.
            unsafe {
                bindings::napi_receive_virtio_xdp_pages(
                    self.raw.as_ptr(),
                    device.as_raw(),
                    raw_rxq,
                    program.raw.as_ptr(),
                    pages.as_ptr(),
                    offsets.as_ptr(),
                    lengths.as_ptr(),
                    truesizes.as_ptr(),
                    count,
                    options.header_len,
                    options.mergeable_buffers,
                    options.little_endian,
                    options.hash_report,
                    options.tunnel_header_negotiated,
                    options.tunnel_checksum_negotiated,
                    options.queue_index,
                    &mut tx_frame,
                    &mut packet_len,
                )
            }
        })?;
        if result < 0 {
            return Err(Error::from_errno(result));
        }
        match result {
            0 => Ok(XdpReceive::Pass { packet_len }),
            1 => Ok(XdpReceive::Drop),
            // SAFETY: The TX result contract returns one newly owned non-null frame.
            2 => Ok(XdpReceive::Transmit(unsafe {
                XdpFrame::from_raw(tx_frame)?
            })),
            3 => Ok(XdpReceive::Redirect),
            _ => Err(EIO),
        }
    }

    /// Consume one completed AF_XDP frame, optionally run native XDP, and resolve ownership.
    ///
    /// PASS copies the adjusted packet into an skb and returns every UMEM buffer to its pool. TX
    /// converts the single zero-copy buffer into an independently owned order-0 [`XdpFrame`]. A
    /// successful redirect transfers the buffer to XDP core. The helper frees the complete vector
    /// on every drop and error path; mergeable frames with more than one buffer intentionally
    /// preserve the C driver's current behavior of aborting when a program is attached.
    pub fn receive_virtio_xsk<T: Operations>(
        &self,
        device: &Device<T>,
        program: Option<&XdpProgram>,
        frame: VirtioXskRxFrame,
        options: VirtioRxOptions,
    ) -> Result<XdpReceive> {
        let count = frame.buffers.len();
        if count == 0
            || count > u32::MAX as usize
            || frame.pool.header_len != options.header_len
            || frame
                .buffers
                .iter()
                .any(|buffer| buffer.raw.is_none() || buffer.used_length == 0)
        {
            return Err(EINVAL);
        }
        let mut raw_buffers = KVec::with_capacity(count, GFP_ATOMIC)?;
        let mut used_lengths = KVec::with_capacity(count, GFP_ATOMIC)?;
        raw_buffers.resize(count, core::ptr::null_mut(), GFP_ATOMIC)?;
        used_lengths.resize(count, 0, GFP_ATOMIC)?;
        for (index, buffer) in frame.buffers.iter().enumerate() {
            used_lengths[index] = buffer.used_length;
        }

        let VirtioXskRxFrame { pool, buffers } = frame;
        let mut extracted = 0;
        for (index, buffer) in buffers.into_iter().enumerate() {
            match VirtioXskRxBuffer::take_raw(buffer) {
                Ok(raw) => {
                    raw_buffers[index] = raw;
                    extracted += 1;
                }
                Err(error) => {
                    for raw in &raw_buffers[..extracted] {
                        // SAFETY: These values were detached from their wrappers but have not
                        // been transferred to the consuming C helper.
                        unsafe { bindings::virtio_xsk_free_rx(*raw) };
                    }
                    return Err(error);
                }
            }
        }

        let mut tx_frame = core::ptr::null_mut();
        let mut packet_len = 0;
        // SAFETY: Every array entry is an independently owned pool buffer. Ownership of the full
        // vector transfers to the helper, which frees or transfers every entry on all returns;
        // `pool` pins the mapping and XSK RXQ until the synchronous call completes.
        let result = unsafe {
            bindings::napi_receive_virtio_xsk(
                self.raw.as_ptr(),
                device.as_raw(),
                pool.raw.as_ptr(),
                program.map_or(core::ptr::null_mut(), |program| program.raw.as_ptr()),
                raw_buffers.as_mut_ptr(),
                used_lengths.as_ptr(),
                count as u32,
                options.mergeable_buffers,
                options.little_endian,
                options.hash_report,
                options.tunnel_header_negotiated,
                options.tunnel_checksum_negotiated,
                options.queue_index,
                &mut tx_frame,
                &mut packet_len,
            )
        };
        if result < 0 {
            return Err(Error::from_errno(result));
        }
        match result {
            0 => Ok(XdpReceive::Pass { packet_len }),
            1 => Ok(XdpReceive::Drop),
            // SAFETY: The TX result owns one non-null order-0 frame independent of the XSK pool.
            2 => Ok(XdpReceive::Transmit(unsafe {
                XdpFrame::from_raw(tx_frame)?
            })),
            3 => Ok(XdpReceive::Redirect),
            _ => Err(EIO),
        }
    }

    /// Schedule this context, running `before_schedule` after winning the schedule bit and before
    /// publishing it to softirq. Virtio drivers use the closure to disable queue callbacks.
    pub fn schedule_after(&self, before_schedule: impl FnOnce()) -> bool {
        // SAFETY: `raw` is live for this callback and NAPI schedule preparation is atomic.
        if unsafe { bindings::napi_schedule_prep(self.raw.as_ptr()) } {
            before_schedule();
            // SAFETY: A successful prepare reserves the right to schedule exactly once.
            unsafe { bindings::__napi_schedule(self.raw.as_ptr()) };
            true
        } else {
            false
        }
    }
}

/// Revocable shared storage for one registered NAPI object.
///
/// `napi` is first so the C poll pointer can be cast back to this generic storage. The allocation
/// is held by every [`Napi`] handle even after unregister; `active` prevents stale handles from
/// calling C, while `users` closes the check/revoke race.
#[repr(C)]
struct NapiToken<T: Operations> {
    napi: Opaque<bindings::napi_struct>,
    dev: NonNull<bindings::net_device>,
    context: u32,
    active: AtomicBool,
    enabled: AtomicBool,
    users: AtomicUsize,
    _state: PhantomData<T>,
}

// SAFETY: Network-core/NAPI primitives serialize the embedded C state; the atomics revoke stale
// handles before the registration is removed.
unsafe impl<T: Operations> Send for NapiToken<T> {}
unsafe impl<T: Operations> Sync for NapiToken<T> {}

impl<T: Operations> NapiToken<T> {
    fn begin_use(&self) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        self.users.fetch_add(1, Ordering::AcqRel);
        if self.active.load(Ordering::Acquire) {
            true
        } else {
            self.users.fetch_sub(1, Ordering::Release);
            false
        }
    }

    fn end_use(&self) {
        self.users.fetch_sub(1, Ordering::Release);
    }

    fn revoke(&self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        while self.users.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        if self.enabled.swap(false, Ordering::AcqRel) {
            // SAFETY: Revocation owns the still-registered NAPI object and waits for disable.
            unsafe { bindings::napi_disable(self.napi.get()) };
        }
        // SAFETY: The object was added exactly once and is now disabled with no handle users.
        unsafe { bindings::netif_napi_del(self.napi.get()) };
    }
}

struct NapiVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> NapiVTable<T> {
    unsafe extern "C" fn poll_callback(raw: *mut bindings::napi_struct, budget: c_int) -> c_int {
        if raw.is_null() || budget <= 0 {
            return 0;
        }
        // SAFETY: `NapiToken::napi` is the first field and this callback is installed only on
        // `NapiToken<T>` allocations owned by `Registration<T>`.
        let token = unsafe { &*raw.cast::<NapiToken<T>>() };
        // SAFETY: The NAPI object remains attached to the live typed network device during poll.
        let device = unsafe { Device::<T>::from_raw(token.dev.as_ptr()) };
        let state = device.state();
        // SAFETY: `raw` is non-null and live for this callback.
        let napi = NapiContext {
            raw: unsafe { NonNull::new_unchecked(raw) },
            context: token.context,
            _lifetime: PhantomData,
        };
        state.poll(device, &napi, budget as u32).min(budget as u32) as c_int
    }
}

/// Revocable handle to a NAPI context owned by [`Registration`].
pub struct Napi<T: Operations> {
    token: Arc<NapiToken<T>>,
}

impl<T: Operations> Clone for Napi<T> {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
        }
    }
}

impl<T: Operations> Napi<T> {
    /// Driver-defined queue/context identifier supplied at registration.
    pub fn context(&self) -> u32 {
        self.token.context
    }

    /// Current poll weight, including zero for a callback-only TX context.
    pub fn weight(&self) -> Result<u32> {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        // SAFETY: The active token pins the registered NAPI object for this read.
        let weight = unsafe { (*self.token.napi.get()).weight as u32 };
        self.token.end_use();
        Ok(weight)
    }

    /// Replace the poll weight while this NAPI context is disabled.
    pub fn set_weight(&self, weight: u32) -> Result {
        if weight > c_int::MAX as u32 {
            return Err(EINVAL);
        }
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        let result = if self.token.enabled.load(Ordering::Acquire) {
            Err(EBUSY)
        } else {
            // SAFETY: The active token pins a disabled NAPI object; networking core permits its
            // weight to be changed before the next enable.
            unsafe { (*self.token.napi.get()).weight = weight as c_int };
            Ok(())
        };
        self.token.end_use();
        result
    }

    /// Enable polling. Returns an error for a revoked or already-enabled handle.
    pub fn enable(&self) -> Result {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        let result = if self.token.enabled.swap(true, Ordering::AcqRel) {
            Err(EBUSY)
        } else {
            // SAFETY: The active token owns a registered, currently disabled NAPI object.
            unsafe { bindings::napi_enable(self.token.napi.get()) };
            Ok(())
        };
        self.token.end_use();
        result
    }

    /// Disable polling and wait for an active poll to finish. Idempotent after revocation.
    pub fn disable(&self) {
        if !self.token.begin_use() {
            return;
        }
        if self.token.enabled.swap(false, Ordering::AcqRel) {
            // SAFETY: The active token owns this enabled NAPI object.
            unsafe { bindings::napi_disable(self.token.napi.get()) };
        }
        self.token.end_use();
    }

    /// Associate this enabled NAPI context with a visible RX or TX queue.
    pub fn associate_queue(&self, queue_index: u32, queue_type: QueueType) -> Result {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        let result = if !self.token.enabled.load(Ordering::Acquire) {
            Err(EINVAL)
        } else {
            // SAFETY: The token pins both the live netdev pointer and registered NAPI object.
            unsafe {
                bindings::netif_queue_set_napi(
                    self.token.dev.as_ptr(),
                    queue_index,
                    queue_type.as_raw(),
                    self.token.napi.get(),
                )
            };
            Ok(())
        };
        self.token.end_use();
        result
    }

    /// Remove a visible RX or TX queue association before disabling NAPI.
    pub fn clear_queue(&self, queue_index: u32, queue_type: QueueType) {
        if !self.token.begin_use() {
            return;
        }
        // SAFETY: The active token pins the live netdev; NULL removes the association.
        unsafe {
            bindings::netif_queue_set_napi(
                self.token.dev.as_ptr(),
                queue_index,
                queue_type.as_raw(),
                core::ptr::null_mut(),
            )
        };
        self.token.end_use();
    }

    /// Schedule polling, allowing a bus-specific callback suppression action in the race window.
    pub fn schedule_after(&self, before_schedule: impl FnOnce()) -> bool {
        if !self.token.begin_use() {
            return false;
        }
        if !self.token.enabled.load(Ordering::Acquire) {
            self.token.end_use();
            return false;
        }
        // SAFETY: The token is active and pins an enabled registered NAPI object.
        let scheduled = if unsafe { bindings::napi_schedule_prep(self.token.napi.get()) } {
            before_schedule();
            // SAFETY: Successful preparation reserves one normal-context schedule.
            unsafe { bindings::__napi_schedule(self.token.napi.get()) };
            true
        } else {
            false
        };
        self.token.end_use();
        scheduled
    }

    /// Schedule this NAPI context for a virtqueue, or mark an already-running poll as missed.
    ///
    /// This is the process-context wakeup protocol used by AF_XDP: queue callbacks are disabled
    /// only when this call wins the schedule bit, and a concurrent poll is forced to run again.
    pub fn schedule_virtqueue_or_mark_missed(&self, queue: &crate::virtio::VirtQueue) -> Result {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        // SAFETY: The active token pins the registered NAPI object and `queue` is a live
        // transport-owned virtqueue handle. The helper balances bottom-half exclusion and either
        // schedules exactly once or atomically marks the current poll missed.
        let result = to_result(unsafe {
            bindings::virtqueue_napi_schedule_or_mark_missed(queue.as_raw(), self.token.napi.get())
        });
        self.token.end_use();
        result
    }

    /// IRQ-off variant of [`Self::schedule_after`].
    pub fn schedule_irqoff_after(&self, before_schedule: impl FnOnce()) -> bool {
        if !self.token.begin_use() {
            return false;
        }
        if !self.token.enabled.load(Ordering::Acquire) {
            self.token.end_use();
            return false;
        }
        // SAFETY: The token is active and the caller is in an IRQ-off context.
        let scheduled = if unsafe { bindings::napi_schedule_prep(self.token.napi.get()) } {
            before_schedule();
            // SAFETY: Successful preparation reserves one IRQ-off schedule.
            unsafe { bindings::__napi_schedule_irqoff(self.token.napi.get()) };
            true
        } else {
            false
        };
        self.token.end_use();
        scheduled
    }
}

struct XdpRxQueueToken {
    raw: NonNull<bindings::xdp_rxq_info>,
    dev: NonNull<bindings::net_device>,
    napi: NonNull<bindings::napi_struct>,
    queue_index: u32,
    active: AtomicBool,
    registered: AtomicBool,
    transition: AtomicBool,
    users: AtomicUsize,
}

// SAFETY: The registered XDP RXQ is immutable while active; `users` closes the race between a
// NAPI invocation and synchronous revocation.
unsafe impl Send for XdpRxQueueToken {}
unsafe impl Sync for XdpRxQueueToken {}

impl XdpRxQueueToken {
    fn begin_use(&self) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        self.users.fetch_add(1, Ordering::AcqRel);
        if self.active.load(Ordering::Acquire) {
            true
        } else {
            self.users.fetch_sub(1, Ordering::Release);
            false
        }
    }

    fn end_use(&self) {
        self.users.fetch_sub(1, Ordering::Release);
    }

    fn lock_transition(&self) {
        while self
            .transition
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock_transition(&self) {
        self.transition.store(false, Ordering::Release);
    }

    fn revoke(&self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        while self.users.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        self.lock_transition();
        if self.registered.swap(false, Ordering::AcqRel) {
            // SAFETY: Callback users drained and this token performed the matching registration.
            unsafe { bindings::xdp_rxq_info_disable(self.raw.as_ptr()) };
        }
        // SAFETY: Revocation is unique, all callback users drained, and `raw` was registered by
        // `xdp_rxq_info_create` exactly once. It is unregistered before destruction.
        unsafe { bindings::xdp_rxq_info_destroy(self.raw.as_ptr()) };
        self.unlock_transition();
    }

    fn enable(&self) -> Result {
        if !self.begin_use() {
            return Err(ENODEV);
        }
        self.lock_transition();
        if self.registered.load(Ordering::Acquire) {
            self.unlock_transition();
            self.end_use();
            return Ok(());
        }
        let result = to_result(unsafe {
            // SAFETY: The active token pins the allocated RXQ, netdev and NAPI registrations.
            // Control-plane serialization prevents a concurrent enable/disable operation.
            bindings::xdp_rxq_info_enable(
                self.raw.as_ptr(),
                self.dev.as_ptr(),
                self.queue_index,
                self.napi.as_ptr(),
            )
        });
        if result.is_ok() {
            self.registered.store(true, Ordering::Release);
        }
        self.unlock_transition();
        self.end_use();
        result
    }

    fn disable(&self) {
        if !self.begin_use() {
            return;
        }
        self.lock_transition();
        if !self.registered.swap(false, Ordering::AcqRel) {
            self.unlock_transition();
            self.end_use();
            return;
        }
        self.end_use();
        while self.users.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        // SAFETY: No callback user remains and this token performed the matching enable.
        unsafe { bindings::xdp_rxq_info_disable(self.raw.as_ptr()) };
        self.unlock_transition();
    }
}

impl Drop for XdpRxQueueToken {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Revocable handle to one registered native-XDP receive queue.
pub struct XdpRxQueue {
    token: Arc<XdpRxQueueToken>,
}

impl Clone for XdpRxQueue {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
        }
    }
}

impl XdpRxQueue {
    /// Register this RXQ and its order-0 XDP memory model before enabling the paired NAPI context.
    pub fn enable(&self) -> Result {
        self.token.enable()
    }

    /// Unregister this RXQ after disabling the paired NAPI context.
    pub fn disable(&self) {
        self.token.disable();
    }

    fn with_raw<R>(&self, callback: impl FnOnce(*mut bindings::xdp_rxq_info) -> R) -> Result<R> {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        if !self.token.registered.load(Ordering::Acquire) {
            self.token.end_use();
            return Err(ENODEV);
        }
        let result = callback(self.token.raw.as_ptr());
        self.token.end_use();
        Ok(result)
    }
}

/// Revocable shared storage for one receive DIM instance.
///
/// `dim` is first so networking core's embedded work pointer can be recovered as this token. The
/// registration keeps the allocation alive and synchronously cancels its work before revocation.
#[cfg(CONFIG_DIMLIB)]
#[repr(C)]
struct RxDimToken<T: Operations> {
    dim: Opaque<bindings::dim>,
    dev: NonNull<bindings::net_device>,
    context: u32,
    active: AtomicBool,
    users: AtomicUsize,
    _state: PhantomData<T>,
}

#[cfg(CONFIG_DIMLIB)]
// SAFETY: Networking core serializes the embedded DIM work. Atomics close the handle/revocation
// race, and revocation synchronously cancels work before registration releases its ownership.
unsafe impl<T: Operations> Send for RxDimToken<T> {}
#[cfg(CONFIG_DIMLIB)]
// SAFETY: The same synchronization and revocation rules permit shared access to the token.
unsafe impl<T: Operations> Sync for RxDimToken<T> {}

#[cfg(CONFIG_DIMLIB)]
impl<T: Operations> RxDimToken<T> {
    fn begin_use(&self) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        self.users.fetch_add(1, Ordering::AcqRel);
        if self.active.load(Ordering::Acquire) {
            true
        } else {
            self.users.fetch_sub(1, Ordering::Release);
            false
        }
    }

    fn end_use(&self) {
        self.users.fetch_sub(1, Ordering::Release);
    }

    fn revoke(&self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        while self.users.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        // SAFETY: No handle can enter after revocation, and the registration still owns the
        // initialized DIM object while cancellation drains any scheduled callback.
        unsafe { bindings::net_dim_work_cancel(self.dim.get()) };
    }
}

#[cfg(CONFIG_DIMLIB)]
struct RxDimVTable<T: Operations>(PhantomData<T>);

#[cfg(CONFIG_DIMLIB)]
impl<T: Operations> RxDimVTable<T> {
    unsafe extern "C" fn work_callback(raw: *mut bindings::work_struct) {
        if raw.is_null() {
            return;
        }
        // SAFETY: `net_dim_setting` initialized this exact embedded work item.
        let dim = unsafe { container_of!(raw, bindings::dim, work) };
        // SAFETY: `RxDimToken::dim` is its first field and this callback is installed only for
        // tokens owned by `Registration<T>`.
        let token = unsafe { &*dim.cast::<RxDimToken<T>>() };
        if !token.begin_use() {
            return;
        }
        // SAFETY: An active token is canceled and revoked before the typed netdev is unregistered.
        let device = unsafe { Device::<T>::from_raw(token.dev.as_ptr()) };
        // SAFETY: The netdev's IRQ moderation profile and this DIM instance remain live for the
        // active token. Networking core returns the selected profile by value.
        let raw_moderation = unsafe { bindings::net_dim_get_rx_irq_moder(device.as_raw(), dim) };
        device.state().rx_dim_moderation(
            device,
            token.context,
            RxDimModeration {
                usecs: raw_moderation.usec,
                packets: raw_moderation.pkts,
            },
        );
        // SAFETY: The callback exclusively completes this DIM work cycle before allowing another
        // measurement, matching networking core's consumer contract.
        unsafe { (*dim).state = bindings::dim_state_DIM_START_MEASURE as u8 };
        token.end_use();
    }
}

/// Revocable handle to one receive dynamic-interrupt-moderation instance.
#[cfg(CONFIG_DIMLIB)]
pub struct RxDim<T: Operations> {
    token: Arc<RxDimToken<T>>,
}

#[cfg(CONFIG_DIMLIB)]
impl<T: Operations> Clone for RxDim<T> {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
        }
    }
}

#[cfg(CONFIG_DIMLIB)]
impl<T: Operations> RxDim<T> {
    /// Driver-defined queue/context identifier supplied at registration.
    pub fn context(&self) -> u32 {
        self.token.context
    }

    /// Feed one cumulative receive sample to networking core's DIM algorithm.
    pub fn sample(&self, event_count: u16, packets: u64, bytes: u64) -> Result {
        if !self.token.begin_use() {
            return Err(ENODEV);
        }
        let sample = bindings::dim_sample {
            // SAFETY: `ktime_get` has no caller-side preconditions.
            time: unsafe { bindings::ktime_get() },
            pkt_ctr: packets as u32,
            byte_ctr: bytes as u32,
            event_ctr: event_count,
            comp_ctr: 0,
        };
        // SAFETY: The active token pins an initialized DIM object and `sample` remains borrowed for
        // the synchronous algorithm call. Counter truncation exactly matches `dim_update_sample`.
        unsafe { bindings::net_dim(self.token.dim.get(), &sample) };
        self.token.end_use();
        Ok(())
    }

    /// Synchronously cancel a scheduled moderation update while keeping this instance reusable.
    pub fn cancel(&self) {
        if !self.token.begin_use() {
            return;
        }
        // SAFETY: The active token pins an initialized DIM object until cancellation completes.
        unsafe { bindings::net_dim_work_cancel(self.token.dim.get()) };
        self.token.end_use();
    }
}

/// Borrowed view of a live `struct net_device`.
///
/// Values of this type are created only while the owning [`Registration`] is
/// alive.  The registration keeps an [`Arc<T>`] in `netdev_priv`, so `state()`
/// remains valid for the duration of every callback.
#[repr(transparent)]
pub struct Device<T: Operations> {
    inner: bindings::net_device,
    _state: PhantomData<T>,
}

// SAFETY: Network-core synchronization controls access to `net_device`; this
// wrapper exposes no unsynchronised mutable reference to it.
unsafe impl<T: Operations> Sync for Device<T> {}

/// A reference-counted handle that keeps a network-device allocation alive.
///
/// Registration state may already be quiescing when a deferred worker runs;
/// drivers must separately prevent new work and drain it before teardown.
pub struct DeviceRef<T: Operations> {
    raw: NonNull<bindings::net_device>,
    _state: PhantomData<fn() -> T>,
}

/// Same-CPU guard for one networking transmit queue lock.
pub struct TxQueueGuard<'a, T: Operations> {
    raw: NonNull<bindings::netdev_queue>,
    _device: PhantomData<&'a Device<T>>,
    _not_send: PhantomData<*mut ()>,
}

/// Same-CPU guard returned after a non-blocking transmit-queue lock succeeds.
pub struct TxQueueTryGuard<'a, T: Operations> {
    raw: NonNull<bindings::netdev_queue>,
    _device: PhantomData<&'a Device<T>>,
    _not_send: PhantomData<*mut ()>,
}

impl<T: Operations> Drop for TxQueueGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: Construction acquired this exact queue with the matching helper.
        unsafe { bindings::netdev_tx_queue_unlock(self.raw.as_ptr()) };
    }
}

impl<T: Operations> Drop for TxQueueTryGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: Construction acquired this exact queue with the matching try-lock helper.
        unsafe { bindings::netdev_tx_queue_tryunlock(self.raw.as_ptr()) };
    }
}

// SAFETY: The reference pins the allocation and `Device` exposes only
// networking-core synchronized operations.
unsafe impl<T: Operations> Send for DeviceRef<T> {}
unsafe impl<T: Operations> Sync for DeviceRef<T> {}

impl<T: Operations> DeviceRef<T> {
    /// Borrow the pinned device allocation.
    pub fn device(&self) -> &Device<T> {
        // SAFETY: This handle owns a live netdev reference of the expected type.
        unsafe { Device::from_raw(self.raw.as_ptr()) }
    }
}

impl<T: Operations> Clone for DeviceRef<T> {
    fn clone(&self) -> Self {
        // SAFETY: The current handle proves the device allocation is live.
        unsafe { bindings::netdev_ref_get(self.raw.as_ptr()) };
        Self {
            raw: self.raw,
            _state: PhantomData,
        }
    }
}

impl<T: Operations> Drop for DeviceRef<T> {
    fn drop(&mut self) {
        // SAFETY: Balance exactly one reference held by this handle.
        unsafe { bindings::netdev_ref_put(self.raw.as_ptr()) };
    }
}

impl<T: Operations> Device<T> {
    /// Borrow the state attached to this network device.
    pub fn state(&self) -> ArcBorrow<'_, T> {
        // SAFETY: `Registration::new_ethernet` reserves a pointer-sized private
        // area and stores exactly one `Arc<T>::into_foreign` value there before
        // the device can be registered.  It is removed only after unregister.
        unsafe {
            let slot = bindings::netdev_priv(self.as_raw()).cast::<*mut c_void>();
            <Arc<T> as ForeignOwnable>::borrow(*slot)
        }
    }

    /// Keep this device allocation alive beyond the current callback.
    pub fn hold(&self) -> DeviceRef<T> {
        // SAFETY: A borrowed live device may acquire one additional reference.
        unsafe { bindings::netdev_ref_get(self.as_raw()) };
        DeviceRef {
            raw: unsafe { NonNull::new_unchecked(self.as_raw()) },
            _state: PhantomData,
        }
    }

    /// Copy the current Ethernet address.
    pub fn ethernet_address(&self) -> Result<EthernetAddress> {
        let mut address = [0u8; 6];
        // SAFETY: The output has exactly Ethernet address length and this device is live.
        unsafe { bindings::eth_hw_addr_copy(self.as_raw(), address.as_mut_ptr()) };
        EthernetAddress::new(address)
    }

    /// Take one allocation-owned, lock-consistent receive-mode snapshot.
    pub fn receive_mode(&self, flags: Flags) -> Result<ReceiveMode> {
        let mut unicast: KVec<[u8; 6]> = KVec::new();
        let mut multicast: KVec<[u8; 6]> = KVec::new();

        for _ in 0..4 {
            let mut promiscuous = false;
            let mut all_multicast = false;
            let mut unicast_count = 0u32;
            let mut multicast_count = 0u32;
            // SAFETY: Both vectors contain initialized six-byte elements. The helper copies no
            // more than the supplied lengths and returns the required lengths under the same
            // address-list lock when either vector is too small.
            let result = unsafe {
                bindings::netdev_receive_mode_snapshot(
                    self.as_raw(),
                    &mut promiscuous,
                    &mut all_multicast,
                    unicast.as_mut_ptr().cast::<u8>(),
                    unicast.len() as u32,
                    &mut unicast_count,
                    multicast.as_mut_ptr().cast::<u8>(),
                    multicast.len() as u32,
                    &mut multicast_count,
                )
            };
            if result == -(bindings::ENOSPC as c_int) {
                unicast.resize(unicast_count as usize, [0u8; 6], flags)?;
                multicast.resize(multicast_count as usize, [0u8; 6], flags)?;
                continue;
            }
            to_result(result)?;
            unicast.truncate(unicast_count as usize);
            multicast.truncate(multicast_count as usize);
            return Ok(ReceiveMode {
                promiscuous,
                all_multicast,
                unicast,
                multicast,
            });
        }

        Err(EAGAIN)
    }

    /// Current networking feature set, read with the kernel's publication ordering.
    pub fn features(&self) -> Features {
        // SAFETY: This wrapper points to a live netdev and the helper uses READ_ONCE.
        Features::from_bits(unsafe { bindings::netdev_features(self.as_raw()) })
    }

    /// Current configured MTU.
    pub fn mtu(&self) -> u32 {
        // SAFETY: Networking core publishes this scalar under its configuration serialization.
        unsafe { (*self.as_raw()).mtu }
    }

    /// Publish this device as an XDP redirect target after program resources are ready.
    pub fn set_xdp_redirect_target(&self, scatter_gather: bool) {
        // SAFETY: XDP setup callbacks execute under networking core's control-plane serialization.
        unsafe { bindings::xdp_set_redirect_target(self.as_raw(), scatter_gather) };
    }

    /// Remove this device from the XDP redirect-target set before resources are released.
    pub fn clear_xdp_redirect_target(&self) {
        // SAFETY: XDP setup callbacks execute under networking core's control-plane serialization.
        unsafe { bindings::xdp_clear_redirect_target(self.as_raw()) };
    }

    /// Whether the interface is administratively running.
    pub fn is_running(&self) -> bool {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_running(self.as_raw()) }
    }

    /// Whether userspace has set `IFF_UP`.
    pub fn is_up(&self) -> bool {
        // SAFETY: This wrapper points to a live netdev and the helper uses READ_ONCE.
        unsafe { bindings::netif_is_up(self.as_raw()) }
    }

    /// Whether userspace has configured an RSS indirection table or key.
    pub fn is_rxfh_configured(&self) -> bool {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_is_rxfh_configured(self.as_raw()) }
    }

    /// Transactionally publish active transmit and receive queue counts on a live netdev.
    pub fn set_real_queue_counts(&self, tx_queues: u32, rx_queues: u32) -> Result {
        if tx_queues == 0 || rx_queues == 0 {
            return Err(EINVAL);
        }
        // SAFETY: This live device is serialized by networking core for queue-count changes.
        let old_tx = unsafe { (*self.as_raw()).real_num_tx_queues };
        to_result(unsafe { bindings::netif_set_real_num_tx_queues(self.as_raw(), tx_queues) })?;
        // SAFETY: Same live-device serialization; the core validates the allocated RX bound.
        let result =
            to_result(unsafe { bindings::netif_set_real_num_rx_queues(self.as_raw(), rx_queues) });
        if result.is_err() {
            // SAFETY: Restore the prior valid TX count before exposing a failed transaction.
            let rollback = unsafe { bindings::netif_set_real_num_tx_queues(self.as_raw(), old_tx) };
            debug_assert_eq!(rollback, 0);
        }
        result
    }

    /// Publish only the active receive-queue count on a live netdev.
    ///
    /// Native-XDP drivers use this when adding receive queue pairs whose transmit halves are
    /// reserved for XDP and must not become ordinary networking transmit queues.
    pub fn set_real_rx_queue_count(&self, rx_queues: u32) -> Result {
        if rx_queues == 0 {
            return Err(EINVAL);
        }
        // SAFETY: This live device is serialized by networking core for queue-count changes; the
        // core validates the count against the receive queues allocated with the netdev.
        to_result(unsafe { bindings::netif_set_real_num_rx_queues(self.as_raw(), rx_queues) })
    }

    /// Replace the CPU transmit-packet-steering mask for one queue.
    pub fn set_xps_queue(&self, mask: &Cpumask, index: u16) -> Result {
        // SAFETY: `mask` is a live cpumask and networking core validates the queue index.
        to_result(unsafe {
            bindings::netif_set_xps_queue_compat(self.as_raw(), mask.as_raw(), index)
        })
    }

    /// Mark carrier present and publish the link transition.
    pub fn carrier_on(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_carrier_on(self.as_raw()) };
    }

    /// Mark carrier absent and publish the link transition.
    pub fn carrier_off(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_carrier_off(self.as_raw()) };
    }

    /// Notify peers after a link announcement.
    pub fn notify_peers(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netdev_notify_peers(self.as_raw()) };
    }

    /// Stop every transmit queue.
    pub fn stop_all_tx_queues(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_tx_stop_all_queues(self.as_raw()) };
    }

    /// Wake every transmit queue that can accept packets.
    pub fn wake_all_tx_queues(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_tx_wake_all_queues(self.as_raw()) };
    }

    /// Stop one allocated transmit subqueue selected by its networking index.
    pub fn stop_tx_queue(&self, index: u32) -> Result {
        // SAFETY: The helper validates `index` against the live allocated TX queue count.
        to_result(unsafe { bindings::netdev_tx_stop_queue(self.as_raw(), index) })
    }

    /// Wake one stopped allocated transmit subqueue selected by its networking index.
    pub fn wake_tx_queue(&self, index: u32) -> Result {
        // SAFETY: The helper validates `index` against the live real TX queue count.
        to_result(unsafe { bindings::netdev_tx_wake_queue(self.as_raw(), index) })
    }

    /// Whether one allocated transmit subqueue is currently stopped.
    pub fn tx_queue_stopped(&self, index: u32) -> Result<bool> {
        let mut stopped = false;
        // SAFETY: The helper validates `index`; `stopped` is writable for one bool.
        to_result(unsafe {
            bindings::netdev_tx_queue_stopped(self.as_raw(), index, &mut stopped)
        })?;
        Ok(stopped)
    }

    /// Account one queued BQL packet and decide whether this batch should kick.
    pub fn tx_sent(&self, index: u32, bytes: u32, more: bool) -> Result<bool> {
        let mut kick = false;
        // SAFETY: The helper validates `index`; `kick` is writable for one bool.
        to_result(unsafe {
            bindings::netdev_tx_sent_queue(self.as_raw(), index, bytes, more, &mut kick)
        })?;
        Ok(kick)
    }

    /// Complete a BQL batch previously accounted by [`Self::tx_sent`].
    pub fn tx_completed(&self, index: u32, packets: u32, bytes: u32) -> Result {
        // SAFETY: The helper validates `index`; the counters are driver-owned batch totals.
        to_result(unsafe {
            bindings::netdev_tx_completed_queue(self.as_raw(), index, packets, bytes)
        })
    }

    /// Reset one transmit queue's byte-queue-limits accounting after ring replacement.
    pub fn reset_tx_queue(&self, index: u32) -> Result {
        // SAFETY: The helper validates `index` and resets only the selected live TX queue.
        to_result(unsafe { bindings::netdev_tx_reset_queue(self.as_raw(), index) })
    }

    /// Refresh one transmit queue's watchdog timestamp after driver-side packet progress.
    pub fn tx_trans_cond_update(&self, index: u32) -> Result {
        // SAFETY: The helper validates `index` and updates only the selected live TX queue.
        to_result(unsafe { bindings::netdev_tx_trans_cond_update(self.as_raw(), index) })
    }

    /// Return microseconds elapsed since the selected TX queue last made watchdog progress.
    pub fn tx_timeout_elapsed_usecs(&self, index: u32) -> Result<u32> {
        let mut usecs = 0;
        // SAFETY: The helper validates the queue index and writes one initialized scalar.
        to_result(unsafe {
            bindings::netdev_tx_timeout_elapsed(self.as_raw(), index, &mut usecs)
        })?;
        Ok(usecs)
    }

    /// Lock one transmit queue and keep bottom halves disabled until guard drop.
    pub fn lock_tx_queue(&self, index: u32) -> Result<TxQueueGuard<'_, T>> {
        let mut raw = core::ptr::null_mut();
        // SAFETY: The helper validates `index`, acquires the queue and initializes `raw` on
        // success. The returned guard is tied to this device borrow and cannot move CPUs.
        to_result(unsafe { bindings::netdev_tx_queue_lock(self.as_raw(), index, &mut raw) })?;
        Ok(TxQueueGuard {
            // SAFETY: A successful helper call always returns its non-null validated queue.
            raw: unsafe { NonNull::new_unchecked(raw) },
            _device: PhantomData,
            _not_send: PhantomData,
        })
    }

    /// Detach the interface from the networking stack during freeze or removal.
    pub fn detach(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_device_detach(self.as_raw()) };
    }

    /// Reattach an interface after queues and device state have been restored.
    pub fn attach(&self) {
        // SAFETY: This wrapper points to a live netdev.
        unsafe { bindings::netif_device_attach(self.as_raw()) };
    }

    /// Read one atomically maintained core statistic.
    pub fn core_stat(&self, stat: CoreStat) -> u64 {
        // SAFETY: This wrapper points to a live netdev and the helper uses DEV_STATS_READ.
        unsafe { bindings::netdev_core_stat_read(self.as_raw(), stat.as_raw()) }
    }

    /// Atomically increment one core statistic.
    pub fn increment_core_stat(&self, stat: CoreStat) {
        // SAFETY: `CoreStat` maps only to helper-supported values.
        let result = unsafe { bindings::netdev_core_stat_inc(self.as_raw(), stat.as_raw()) };
        debug_assert_eq!(result, 0);
    }

    pub(crate) fn as_raw(&self) -> *mut bindings::net_device {
        core::ptr::from_ref(&self.inner).cast_mut()
    }

    /// Convert a network-core callback argument into a borrowed typed view.
    ///
    /// # Safety
    ///
    /// `raw` must point to a live network device allocated by
    /// [`Registration::<T>::new_ethernet`].
    unsafe fn from_raw<'a>(raw: *mut bindings::net_device) -> &'a Self {
        // SAFETY: Guaranteed by the caller; `Device<T>` is transparent over
        // `bindings::net_device` and adds no data fields.
        unsafe { &*raw.cast::<Self>() }
    }
}

/// An skb whose ownership was transferred to `ndo_start_xmit`.
///
/// Dropping the value consumes and frees the packet.  A queue-submission API
/// takes this value by ownership when the packet is handed to hardware.  A
/// driver that cannot accept it returns [`TxResult::Busy`] with the same value,
/// which transfers ownership back to the networking core.
pub struct TxPacket(NonNull<bindings::sk_buff>);

impl TxPacket {
    /// Packet length in bytes.
    pub fn len(&self) -> u32 {
        // SAFETY: The type invariant guarantees a live skb.
        unsafe { (*self.0.as_ptr()).len }
    }

    /// Transmit queue selected by networking core.
    pub fn queue_mapping(&self) -> u16 {
        // SAFETY: The type invariant guarantees a live skb.
        unsafe { bindings::skb_get_queue_mapping(self.0.as_ptr()) }
    }

    /// Whether networking core has another packet ready for this CPU's transmit batch.
    pub fn xmit_more(&self) -> bool {
        // SAFETY: This is the inline networking-core query wrapped for Rust modules.
        unsafe { bindings::netdev_xmit_more() }
    }

    /// Record the requested software/hardware transmit timestamp before submission.
    pub fn timestamp(&mut self) {
        // SAFETY: This value exclusively owns the live skb.
        unsafe { bindings::skb_tx_timestamp(self.0.as_ptr()) };
    }

    /// Release socket ownership and conntrack state before non-NAPI queue ownership transfer.
    pub fn orphan_and_reset_conntrack(&mut self) {
        // SAFETY: This value exclusively owns the live skb.
        unsafe { bindings::skb_orphan_and_reset_ct(self.0.as_ptr()) };
    }

    /// Consume a completed packet through NAPI's batching-aware free path.
    pub fn consume_in_napi(self, budget: u32) {
        let budget = budget.min(c_int::MAX as u32) as c_int;
        // SAFETY: Ownership is transferred exactly once to `napi_consume_skb`.
        unsafe { bindings::napi_consume_skb(self.0.as_ptr(), budget) };
        mem::forget(self);
    }

    pub(crate) fn as_raw(&self) -> *mut bindings::sk_buff {
        self.0.as_ptr()
    }

    /// Construct the owning wrapper at the `ndo_start_xmit` boundary.
    ///
    /// # Safety
    ///
    /// `raw` must be a non-null skb whose ownership has been transferred to the
    /// driver by the networking core.
    pub(crate) unsafe fn from_raw(raw: *mut bindings::sk_buff) -> Self {
        // SAFETY: Guaranteed by the callback contract.
        Self(unsafe { NonNull::new_unchecked(raw) })
    }
}

impl Drop for TxPacket {
    fn drop(&mut self) {
        // SAFETY: This value owns the live skb and has not transferred it to a
        // virtqueue or back to the networking core.
        unsafe { bindings::kfree_skb(self.0.as_ptr()) };
    }
}

/// Result of `ndo_start_xmit` with skb ownership represented explicitly.
pub enum TxResult {
    /// The driver consumed the packet (queued it or intentionally dropped it).
    Ok,
    /// The queue cannot accept the packet; ownership returns to the core.
    Busy(TxPacket),
}

fn copy_ethtool_text(destination: &mut [ffi::c_char], source: &CStr) {
    if destination.is_empty() {
        return;
    }
    let bytes = source.to_bytes();
    let copied = bytes.len().min(destination.len() - 1);
    for (output, input) in destination[..copied].iter_mut().zip(&bytes[..copied]) {
        *output = *input as ffi::c_char;
    }
    destination[copied] = 0;
}

struct EthtoolVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> EthtoolVTable<T> {
    unsafe fn read_coalesce(input: *const bindings::ethtool_coalesce) -> EthtoolCoalesce {
        // SAFETY: The caller supplies initialized callback storage.
        unsafe {
            EthtoolCoalesce {
                rx_coalesce_usecs: (*input).rx_coalesce_usecs,
                rx_max_coalesced_frames: (*input).rx_max_coalesced_frames,
                tx_coalesce_usecs: (*input).tx_coalesce_usecs,
                tx_max_coalesced_frames: (*input).tx_max_coalesced_frames,
                use_adaptive_rx_coalesce: (*input).use_adaptive_rx_coalesce != 0,
            }
        }
    }

    unsafe fn write_coalesce(output: *mut bindings::ethtool_coalesce, coalesce: EthtoolCoalesce) {
        // SAFETY: The caller supplies exclusive callback output storage.
        unsafe {
            (*output).rx_coalesce_usecs = coalesce.rx_coalesce_usecs;
            (*output).rx_max_coalesced_frames = coalesce.rx_max_coalesced_frames;
            (*output).tx_coalesce_usecs = coalesce.tx_coalesce_usecs;
            (*output).tx_max_coalesced_frames = coalesce.tx_max_coalesced_frames;
            (*output).use_adaptive_rx_coalesce = u32::from(coalesce.use_adaptive_rx_coalesce);
        }
    }

    unsafe extern "C" fn driver_info_callback(
        raw: *mut bindings::net_device,
        output: *mut bindings::ethtool_drvinfo,
    ) {
        if output.is_null() {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        let info = state.ethtool_driver_info(device);
        // SAFETY: Networking core supplies exclusive writable output for the callback duration.
        unsafe {
            copy_ethtool_text(&mut (*output).driver, info.driver);
            copy_ethtool_text(&mut (*output).version, info.version);
            copy_ethtool_text(&mut (*output).bus_info, info.bus_info);
        }
    }

    unsafe extern "C" fn ring_parameters_callback(
        raw: *mut bindings::net_device,
        output: *mut bindings::ethtool_ringparam,
        _kernel_output: *mut bindings::kernel_ethtool_ringparam,
        _extack: *mut bindings::netlink_ext_ack,
    ) {
        if output.is_null() {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let parameters = device.state().ethtool_ring_parameters(device);
        // SAFETY: Networking core supplies exclusive writable output for the callback duration.
        unsafe {
            (*output).rx_max_pending = parameters.rx_max_pending;
            (*output).rx_mini_max_pending = parameters.rx_mini_max_pending;
            (*output).rx_jumbo_max_pending = parameters.rx_jumbo_max_pending;
            (*output).tx_max_pending = parameters.tx_max_pending;
            (*output).rx_pending = parameters.rx_pending;
            (*output).rx_mini_pending = parameters.rx_mini_pending;
            (*output).rx_jumbo_pending = parameters.rx_jumbo_pending;
            (*output).tx_pending = parameters.tx_pending;
        }
    }

    unsafe extern "C" fn set_ring_parameters_callback(
        raw: *mut bindings::net_device,
        input: *mut bindings::ethtool_ringparam,
        _kernel_input: *mut bindings::kernel_ethtool_ringparam,
        _extack: *mut bindings::netlink_ext_ack,
    ) -> c_int {
        if input.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies initialized callback input for the live device.
        let parameters = unsafe {
            EthtoolRingParameters {
                rx_max_pending: (*input).rx_max_pending,
                rx_mini_max_pending: (*input).rx_mini_max_pending,
                rx_jumbo_max_pending: (*input).rx_jumbo_max_pending,
                tx_max_pending: (*input).tx_max_pending,
                rx_pending: (*input).rx_pending,
                rx_mini_pending: (*input).rx_mini_pending,
                rx_jumbo_pending: (*input).rx_jumbo_pending,
                tx_pending: (*input).tx_pending,
            }
        };
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            device
                .state()
                .ethtool_set_ring_parameters(device, parameters)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn channels_callback(
        raw: *mut bindings::net_device,
        output: *mut bindings::ethtool_channels,
    ) {
        if output.is_null() {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let channels = device.state().ethtool_channels(device);
        // SAFETY: Networking core supplies exclusive writable output for the callback duration.
        unsafe {
            (*output).max_rx = channels.max_rx;
            (*output).max_tx = channels.max_tx;
            (*output).max_other = channels.max_other;
            (*output).max_combined = channels.max_combined;
            (*output).rx_count = channels.rx_count;
            (*output).tx_count = channels.tx_count;
            (*output).other_count = channels.other_count;
            (*output).combined_count = channels.combined_count;
        }
    }

    unsafe extern "C" fn set_channels_callback(
        raw: *mut bindings::net_device,
        input: *mut bindings::ethtool_channels,
    ) -> c_int {
        if input.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies initialized callback input for the live device.
        let channels = unsafe {
            EthtoolChannels {
                max_rx: (*input).max_rx,
                max_tx: (*input).max_tx,
                max_other: (*input).max_other,
                max_combined: (*input).max_combined,
                rx_count: (*input).rx_count,
                tx_count: (*input).tx_count,
                other_count: (*input).other_count,
                combined_count: (*input).combined_count,
            }
        };
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            device.state().ethtool_set_channels(device, channels)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn get_coalesce_callback(
        raw: *mut bindings::net_device,
        output: *mut bindings::ethtool_coalesce,
        _kernel_output: *mut bindings::kernel_ethtool_coalesce,
        _extack: *mut bindings::netlink_ext_ack,
    ) -> c_int {
        if output.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            let coalesce = device.state().ethtool_coalesce(device)?;
            // SAFETY: `output` is exclusive callback storage.
            unsafe { Self::write_coalesce(output, coalesce) };
            Ok(0)
        })
    }

    unsafe extern "C" fn set_coalesce_callback(
        raw: *mut bindings::net_device,
        input: *mut bindings::ethtool_coalesce,
        _kernel_input: *mut bindings::kernel_ethtool_coalesce,
        _extack: *mut bindings::netlink_ext_ack,
    ) -> c_int {
        if input.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies initialized callback input.
        let coalesce = unsafe { Self::read_coalesce(input) };
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            device.state().ethtool_set_coalesce(device, coalesce)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn get_per_queue_coalesce_callback(
        raw: *mut bindings::net_device,
        queue: u32,
        output: *mut bindings::ethtool_coalesce,
    ) -> c_int {
        if output.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            let coalesce = device.state().ethtool_per_queue_coalesce(device, queue)?;
            // SAFETY: `output` is exclusive callback storage.
            unsafe { Self::write_coalesce(output, coalesce) };
            Ok(0)
        })
    }

    unsafe extern "C" fn set_per_queue_coalesce_callback(
        raw: *mut bindings::net_device,
        queue: u32,
        input: *mut bindings::ethtool_coalesce,
    ) -> c_int {
        if input.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies initialized callback input.
        let coalesce = unsafe { Self::read_coalesce(input) };
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            device
                .state()
                .ethtool_set_per_queue_coalesce(device, queue, coalesce)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn get_link_settings_callback(
        raw: *mut bindings::net_device,
        output: *mut bindings::ethtool_link_ksettings,
    ) -> c_int {
        if output.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let settings = device.state().ethtool_link_settings(device);
        // SAFETY: Networking core supplies exclusive writable output for the callback duration.
        unsafe {
            (*output).base.speed = settings.speed;
            (*output).base.duplex = settings.duplex;
            (*output).base.port = settings.port;
        }
        0
    }

    unsafe extern "C" fn set_link_settings_callback(
        raw: *mut bindings::net_device,
        input: *const bindings::ethtool_link_ksettings,
    ) -> c_int {
        if input.is_null() {
            return EINVAL.to_errno();
        }
        let mut speed = 0u32;
        let mut duplex = 0u8;
        // SAFETY: `raw` and `input` are live callback arguments, while the two output scalars are
        // exclusively owned here. The helper validates every virtual-device setting before copy.
        let result = unsafe {
            bindings::ethtool_virtdev_set_link_ksettings(raw, input, &mut speed, &mut duplex)
        };
        if let Err(error) = to_result(result) {
            return error.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.ethtool_set_link_settings(
                device,
                EthtoolLinkSettings {
                    speed,
                    duplex,
                    port: bindings::PORT_OTHER as u8,
                },
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn rss_key_size_callback(raw: *mut bindings::net_device) -> u32 {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        device.state().ethtool_rss_key_size(device)
    }

    unsafe extern "C" fn rss_indirection_size_callback(raw: *mut bindings::net_device) -> u32 {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        device.state().ethtool_rss_indirection_size(device)
    }

    unsafe extern "C" fn rx_ring_count_callback(raw: *mut bindings::net_device) -> u32 {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        device.state().ethtool_rx_ring_count(device)
    }

    unsafe extern "C" fn get_rss_callback(
        raw: *mut bindings::net_device,
        parameters: *mut bindings::ethtool_rxfh_param,
    ) -> c_int {
        if parameters.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        let expected_indirection = state.ethtool_rss_indirection_size(device);
        let expected_key = state.ethtool_rss_key_size(device);
        // SAFETY: The callback owns `parameters`; field reads do not alias the optional buffers.
        let (indirection_ptr, indirection_size, key_ptr, key_size) = unsafe {
            (
                (*parameters).indir,
                (*parameters).indir_size,
                (*parameters).key,
                (*parameters).key_size,
            )
        };
        if (!indirection_ptr.is_null() && indirection_size != expected_indirection)
            || (!key_ptr.is_null() && key_size != expected_key)
        {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core allocated each non-NULL output for the corresponding size it
        // obtained from this same operation table, and lends both exclusively for this callback.
        let indirection = (!indirection_ptr.is_null()).then(|| unsafe {
            slice::from_raw_parts_mut(indirection_ptr, indirection_size as usize)
        });
        let key = (!key_ptr.is_null())
            .then(|| unsafe { slice::from_raw_parts_mut(key_ptr, key_size as usize) });
        from_result(|| {
            let hash_function = state.ethtool_get_rss(device, indirection, key)?;
            // SAFETY: `parameters` remains exclusive callback storage.
            unsafe { (*parameters).hfunc = hash_function.as_raw() };
            Ok(0)
        })
    }

    unsafe extern "C" fn set_rss_callback(
        raw: *mut bindings::net_device,
        parameters: *mut bindings::ethtool_rxfh_param,
        _extack: *mut bindings::netlink_ext_ack,
    ) -> c_int {
        if parameters.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        let expected_indirection = state.ethtool_rss_indirection_size(device);
        let expected_key = state.ethtool_rss_key_size(device);
        // SAFETY: The callback owns `parameters`; field reads do not mutate the input buffers.
        let (hash_function, indirection_ptr, indirection_size, key_ptr, key_size) = unsafe {
            (
                (*parameters).hfunc,
                (*parameters).indir,
                (*parameters).indir_size,
                (*parameters).key,
                (*parameters).key_size,
            )
        };
        if (!indirection_ptr.is_null() && indirection_size != expected_indirection)
            || (!key_ptr.is_null() && key_size != expected_key)
        {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core owns initialized inputs of the advertised sizes and lends them
        // immutably for the callback. NULL represents no change for that component.
        let indirection = (!indirection_ptr.is_null()).then(|| unsafe {
            slice::from_raw_parts(indirection_ptr.cast_const(), indirection_size as usize)
        });
        let key = (!key_ptr.is_null())
            .then(|| unsafe { slice::from_raw_parts(key_ptr.cast_const(), key_size as usize) });
        from_result(|| {
            state.ethtool_set_rss(
                device,
                EthtoolRssParameters {
                    hash_function: EthtoolRssHashFunction::from_raw(hash_function),
                    indirection,
                    key,
                },
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn get_rss_flow_fields_callback(
        raw: *mut bindings::net_device,
        information: *mut bindings::ethtool_rxfh_fields,
    ) -> c_int {
        if information.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        // SAFETY: `information` is initialized callback storage; `flow_type` is an input field.
        let flow_type = EthtoolRssFlowType::from_raw(unsafe { (*information).flow_type });
        from_result(|| {
            let fields = device
                .state()
                .ethtool_get_rss_flow_fields(device, flow_type)?;
            // SAFETY: Networking core supplies exclusive writable output for this callback.
            unsafe { (*information).data = fields.bits() };
            Ok(0)
        })
    }

    unsafe extern "C" fn set_rss_flow_fields_callback(
        raw: *mut bindings::net_device,
        information: *const bindings::ethtool_rxfh_fields,
        _extack: *mut bindings::netlink_ext_ack,
    ) -> c_int {
        if information.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        // SAFETY: Networking core supplies initialized immutable callback input.
        let (flow_type, fields) = unsafe { ((*information).flow_type, (*information).data) };
        from_result(|| {
            device.state().ethtool_set_rss_flow_fields(
                device,
                EthtoolRssFlowType::from_raw(flow_type),
                EthtoolRssFlowFields::from_bits(fields),
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn string_count_callback(
        raw: *mut bindings::net_device,
        string_set: c_int,
    ) -> c_int {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        from_result(|| {
            let count = device
                .state()
                .ethtool_string_count(device, EthtoolStringSet::from_raw(string_set as u32))?;
            c_int::try_from(count).map_err(|_| EOVERFLOW)
        })
    }

    unsafe extern "C" fn strings_callback(
        raw: *mut bindings::net_device,
        string_set: u32,
        data: *mut u8,
    ) {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        let string_set = EthtoolStringSet::from_raw(string_set);
        let Ok(count) = state.ethtool_string_count(device, string_set) else {
            return;
        };
        let Some(length) = (count as usize).checked_mul(bindings::ETH_GSTRING_LEN as usize) else {
            return;
        };
        if data.is_null() || length == 0 {
            return;
        }
        // SAFETY: Networking core allocates exactly count fixed-width slots after querying the
        // count from this same operation table and lends them exclusively for the callback.
        let bytes = unsafe { slice::from_raw_parts_mut(data, length) };
        bytes.fill(0);
        let mut output = EthtoolStrings { bytes, next: 0 };
        let _ = state.ethtool_strings(device, string_set, &mut output);
    }

    unsafe extern "C" fn stats_callback(
        raw: *mut bindings::net_device,
        _header: *mut bindings::ethtool_stats,
        data: *mut u64,
    ) {
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        let Ok(count) = state.ethtool_string_count(device, EthtoolStringSet::STATS) else {
            return;
        };
        if data.is_null() || count == 0 {
            return;
        }
        // SAFETY: Networking core allocates the count it obtained from this same operation table
        // and lends the value array exclusively for the callback duration.
        let output = unsafe { slice::from_raw_parts_mut(data, count as usize) };
        output.fill(0);
        state.ethtool_stats(device, output);
    }

    const VTABLE: bindings::ethtool_ops = {
        // SAFETY: A zeroed ethtool table has no optional callbacks. Selected typed adapters or
        // networking-core standard callbacks are installed before the table is published.
        let mut table: bindings::ethtool_ops = unsafe { core::mem::zeroed() };
        if T::HAS_ETHTOOL_DRIVER_INFO {
            table.get_drvinfo = Some(Self::driver_info_callback);
        }
        if T::HAS_ETHTOOL_LINK {
            table.get_link = Some(bindings::ethtool_op_get_link);
        }
        if T::HAS_ETHTOOL_RING_PARAMETERS {
            table.get_ringparam = Some(Self::ring_parameters_callback);
        }
        if T::HAS_ETHTOOL_SET_RING_PARAMETERS {
            table.set_ringparam = Some(Self::set_ring_parameters_callback);
        }
        if T::HAS_ETHTOOL_CHANNELS {
            table.get_channels = Some(Self::channels_callback);
        }
        if T::HAS_ETHTOOL_SET_CHANNELS {
            table.set_channels = Some(Self::set_channels_callback);
        }
        if T::HAS_ETHTOOL_COALESCE || T::HAS_ETHTOOL_PER_QUEUE_COALESCE {
            table.supported_coalesce_params = ETHTOOL_COALESCE_SUPPORTED;
        }
        if T::HAS_ETHTOOL_COALESCE {
            table.get_coalesce = Some(Self::get_coalesce_callback);
            table.set_coalesce = Some(Self::set_coalesce_callback);
        }
        if T::HAS_ETHTOOL_PER_QUEUE_COALESCE {
            table.get_per_queue_coalesce = Some(Self::get_per_queue_coalesce_callback);
            table.set_per_queue_coalesce = Some(Self::set_per_queue_coalesce_callback);
        }
        if T::HAS_ETHTOOL_TIMESTAMP_INFO {
            table.get_ts_info = Some(bindings::ethtool_op_get_ts_info);
        }
        if T::HAS_ETHTOOL_LINK_SETTINGS {
            table.get_link_ksettings = Some(Self::get_link_settings_callback);
            table.set_link_ksettings = Some(Self::set_link_settings_callback);
        }
        if T::HAS_ETHTOOL_RSS_KEY_SIZE {
            table.get_rxfh_key_size = Some(Self::rss_key_size_callback);
        }
        if T::HAS_ETHTOOL_RSS_INDIRECTION_SIZE {
            table.get_rxfh_indir_size = Some(Self::rss_indirection_size_callback);
        }
        if T::HAS_ETHTOOL_RX_RING_COUNT {
            table.get_rx_ring_count = Some(Self::rx_ring_count_callback);
        }
        if T::HAS_ETHTOOL_RSS {
            table.get_rxfh = Some(Self::get_rss_callback);
            table.set_rxfh = Some(Self::set_rss_callback);
        }
        if T::HAS_ETHTOOL_RSS_FLOW_FIELDS {
            table.get_rxfh_fields = Some(Self::get_rss_flow_fields_callback);
            table.set_rxfh_fields = Some(Self::set_rss_flow_fields_callback);
        }
        if T::HAS_ETHTOOL_STATS {
            table.get_sset_count = Some(Self::string_count_callback);
            table.get_strings = Some(Self::strings_callback);
            table.get_ethtool_stats = Some(Self::stats_callback);
        }
        table
    };
}

struct StatVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> StatVTable<T> {
    unsafe extern "C" fn queue_rx_callback(
        raw: *mut bindings::net_device,
        queue: c_int,
        output: *mut bindings::netdev_queue_stats_rx,
    ) {
        if output.is_null() || queue < 0 {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        device
            .state()
            .queue_stats_rx(device, queue as u32)
            .write_raw(output);
    }

    unsafe extern "C" fn queue_tx_callback(
        raw: *mut bindings::net_device,
        queue: c_int,
        output: *mut bindings::netdev_queue_stats_tx,
    ) {
        if output.is_null() || queue < 0 {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        device
            .state()
            .queue_stats_tx(device, queue as u32)
            .write_raw(output);
    }

    unsafe extern "C" fn base_callback(
        raw: *mut bindings::net_device,
        rx: *mut bindings::netdev_queue_stats_rx,
        tx: *mut bindings::netdev_queue_stats_tx,
    ) {
        if rx.is_null() || tx.is_null() {
            return;
        }
        // SAFETY: Networking core invokes this callback for the live device carrying this table.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let (rx_stats, tx_stats) = device.state().base_stats(device);
        rx_stats.write_raw(rx);
        tx_stats.write_raw(tx);
    }

    const VTABLE: bindings::netdev_stat_ops = {
        // SAFETY: A zeroed table contains no callbacks; all three typed adapters are installed
        // before the table is published through the netdev.
        let mut table: bindings::netdev_stat_ops = unsafe { core::mem::zeroed() };
        table.get_queue_stats_rx = Some(Self::queue_rx_callback);
        table.get_queue_stats_tx = Some(Self::queue_tx_callback);
        table.get_base_stats = Some(Self::base_callback);
        table
    };
}

struct XdpMetadataVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> XdpMetadataVTable<T> {
    unsafe extern "C" fn rx_hash_callback(
        raw_context: *const bindings::xdp_md,
        output_hash: *mut u32,
        output_type: *mut bindings::xdp_rss_hash_type,
    ) -> c_int {
        if output_hash.is_null() || output_type.is_null() {
            return EINVAL.to_errno();
        }
        from_result(|| {
            // SAFETY: XDP core invokes the installed metadata table with a callback-scoped
            // xdp_buff presented through its xdp_md ABI view.
            let context = unsafe { XdpMetadataContext::from_raw(raw_context) }?;
            let raw_device = context.device()?;
            // SAFETY: The RXQ belongs to the live netdev on which this generic table was installed.
            let device = unsafe { Device::<T>::from_raw(raw_device.as_ptr()) };
            let result = device.state().xdp_rx_hash(device, &context)?;
            // SAFETY: XDP core supplies both exclusive outputs for the callback duration. They are
            // written only after the driver returned a fully validated result.
            unsafe {
                output_hash.write(result.value());
                output_type.write(result.hash_type().bits());
            }
            Ok(0)
        })
    }

    const VTABLE: bindings::xdp_metadata_ops = {
        // SAFETY: A zeroed table disables all optional metadata callbacks; receive hash is the
        // only operation selected by this capability gate.
        let mut table: bindings::xdp_metadata_ops = unsafe { core::mem::zeroed() };
        if T::HAS_XDP_METADATA_RX_HASH {
            table.xmo_rx_hash = Some(Self::rx_hash_callback);
        }
        table
    };
}

struct RxQueueSysfsVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> RxQueueSysfsVTable<T> {
    unsafe extern "C" fn show_callback(
        raw_queue: *mut bindings::netdev_rx_queue,
        output: *mut ffi::c_char,
    ) -> isize {
        if raw_queue.is_null() || output.is_null() {
            return EINVAL.to_errno() as isize;
        }
        // SAFETY: Receive-queue sysfs invokes this callback only while the queue and its owning
        // registered netdev are live.
        let raw_device = unsafe { bindings::netdev_rx_queue_device(raw_queue) };
        if raw_device.is_null() {
            return ENODEV.to_errno() as isize;
        }
        let mut queue = 0;
        // SAFETY: The live queue belongs to `raw_device`; the helper validates both pointers and
        // copies the networking-core queue index into exclusive stack storage.
        if let Err(error) =
            to_result(unsafe { bindings::netdev_rx_queue_index(raw_queue, &mut queue) })
        {
            return error.to_errno() as isize;
        }
        // SAFETY: This generic group is installed only on a netdev carrying `T` in netdev_priv.
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let value = match device.state().rx_queue_sysfs_value(device, queue) {
            Ok(value) => value,
            Err(error) => return error.to_errno() as isize,
        };
        // SAFETY: Sysfs supplies a PAGE_SIZE output buffer for this callback; the helper emits one
        // bounded decimal `u32` and its newline.
        unsafe { bindings::sysfs_emit_u32(output, value) }
    }

    const ATTRIBUTE: bindings::rx_queue_attribute = {
        // SAFETY: A zeroed read-only queue attribute has no store callback. The name, mode and
        // typed show adapter are installed before networking core sees the containing group.
        let mut attribute: bindings::rx_queue_attribute = unsafe { core::mem::zeroed() };
        attribute.attr.name = as_char_ptr_in_const_context(T::RX_QUEUE_SYSFS_ATTRIBUTE_NAME);
        attribute.attr.mode = 0o444;
        attribute.show = Some(Self::show_callback);
        attribute
    };

    const ATTRIBUTES: [*const bindings::attribute; 2] = [
        core::ptr::from_ref(&Self::ATTRIBUTE.attr),
        core::ptr::null(),
    ];

    const GROUP: bindings::attribute_group = {
        // SAFETY: The zeroed group has no visibility or binary-attribute callbacks. Its two
        // pointers target monomorphized immutable constants with static promotion.
        let mut group: bindings::attribute_group = unsafe { core::mem::zeroed() };
        group.name = as_char_ptr_in_const_context(T::RX_QUEUE_SYSFS_GROUP_NAME);
        group.__bindgen_anon_2.attrs_const = Self::ATTRIBUTES.as_ptr();
        group
    };
}

struct OperationsVTable<T: Operations>(PhantomData<T>);

impl<T: Operations> OperationsVTable<T> {
    unsafe extern "C" fn open_callback(raw: *mut bindings::net_device) -> c_int {
        // SAFETY: The networking core invokes this vtable only for the live
        // device on which it was installed.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.open(device)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn stop_callback(raw: *mut bindings::net_device) -> c_int {
        // SAFETY: The networking core invokes this vtable only for the live
        // device on which it was installed.
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.stop(device)?;
            Ok(0)
        })
    }

    unsafe extern "C" fn start_xmit_callback(
        raw_packet: *mut bindings::sk_buff,
        raw_device: *mut bindings::net_device,
    ) -> bindings::netdev_tx_t {
        // SAFETY: `ndo_start_xmit` transfers one live skb to this callback and
        // supplies the live device carrying this vtable.
        let packet = unsafe { TxPacket::from_raw(raw_packet) };
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let state = device.state();
        match state.start_xmit(packet, device) {
            TxResult::Ok => bindings::netdev_tx_NETDEV_TX_OK,
            TxResult::Busy(packet) => {
                // Ownership returns to the networking core on BUSY.
                mem::forget(packet);
                bindings::netdev_tx_NETDEV_TX_BUSY
            }
        }
    }

    unsafe extern "C" fn set_mac_address_callback(
        raw_device: *mut bindings::net_device,
        raw_address: *mut c_void,
    ) -> c_int {
        if raw_device.is_null() || raw_address.is_null() {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies a live Ethernet device and sockaddr for this callback.
        if let Err(error) =
            to_result(unsafe { bindings::eth_prepare_mac_addr_change(raw_device, raw_address) })
        {
            return error.to_errno();
        }
        let mut bytes = [0u8; 6];
        // SAFETY: Successful Ethernet validation proves at least six address bytes are readable.
        unsafe {
            let address = &*raw_address.cast::<bindings::sockaddr>();
            core::ptr::copy_nonoverlapping(
                address.sa_data.as_ptr().cast::<u8>(),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let state = device.state();
        from_result(|| {
            state.set_mac_address(device, EthernetAddress(bytes))?;
            // SAFETY: The request remains live and was prepared for this device; commit happens
            // only after the driver's hardware/configuration update succeeded.
            unsafe { bindings::eth_commit_mac_addr_change(raw_device, raw_address) };
            Ok(0)
        })
    }

    unsafe extern "C" fn set_rx_mode_callback(raw: *mut bindings::net_device) {
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        state.set_rx_mode(device);
    }

    unsafe extern "C" fn get_stats64_callback(
        raw: *mut bindings::net_device,
        storage: *mut bindings::rtnl_link_stats64,
    ) {
        if storage.is_null() {
            return;
        }
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        // SAFETY: Networking core supplies writable storage exclusively for this callback.
        unsafe { storage.write(state.get_stats64(device).into_raw()) };
    }

    unsafe extern "C" fn vlan_rx_add_callback(
        raw: *mut bindings::net_device,
        protocol: bindings::__be16,
        id: u16,
    ) -> c_int {
        if id >= 4096 {
            return EINVAL.to_errno();
        }
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.vlan_rx_add(
                device,
                VlanTag {
                    protocol: u16::from_be(protocol),
                    id,
                },
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn vlan_rx_kill_callback(
        raw: *mut bindings::net_device,
        protocol: bindings::__be16,
        id: u16,
    ) -> c_int {
        if id >= 4096 {
            return EINVAL.to_errno();
        }
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.vlan_rx_kill(
                device,
                VlanTag {
                    protocol: u16::from_be(protocol),
                    id,
                },
            )?;
            Ok(0)
        })
    }

    unsafe extern "C" fn get_phys_port_name_callback(
        raw: *mut bindings::net_device,
        output: *mut u8,
        output_len: usize,
    ) -> c_int {
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            let name = state.get_phys_port_name(device)?;
            let bytes = name.as_bytes();
            if output.is_null() || bytes.len() + 1 > output_len {
                return Err(EOPNOTSUPP);
            }
            // SAFETY: The callback contract supplies `output_len` writable bytes; the explicit
            // bound check reserves room for the trailing NUL.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
                output.add(bytes.len()).write(0);
            }
            Ok(0)
        })
    }

    unsafe extern "C" fn set_features_callback(
        raw: *mut bindings::net_device,
        features: bindings::netdev_features_t,
    ) -> c_int {
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        from_result(|| {
            state.set_features(device, Features::from_bits(features))?;
            Ok(0)
        })
    }

    unsafe extern "C" fn tx_timeout_callback(raw: *mut bindings::net_device, queue: u32) {
        let device = unsafe { Device::<T>::from_raw(raw) };
        let state = device.state();
        state.tx_timeout(device, queue);
    }

    unsafe extern "C" fn xdp_callback(
        raw_device: *mut bindings::net_device,
        raw_request: *mut bindings::netdev_bpf,
    ) -> c_int {
        if raw_device.is_null() || raw_request.is_null() {
            return EINVAL.to_errno();
        }
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let state = device.state();
        // SAFETY: Networking core supplies a live request and the command selects the active
        // union member for the duration of this callback.
        match unsafe { (*raw_request).command } {
            bindings::bpf_netdev_command_XDP_SETUP_PROG if T::HAS_XDP => {
                let request = unsafe { (*raw_request).__bindgen_anon_1.__bindgen_anon_1 };
                let setup = XdpProgramSetup {
                    program: NonNull::new(request.prog),
                    extack: request.extack,
                    _lifetime: PhantomData,
                };
                from_result(|| {
                    state.xdp_setup_program(device, setup)?;
                    Ok(0)
                })
            }
            bindings::bpf_netdev_command_XDP_SETUP_XSK_POOL if T::HAS_XSK => {
                let request = unsafe { (*raw_request).__bindgen_anon_1.xsk };
                let setup = XskPoolSetup {
                    pool: NonNull::new(request.pool),
                    queue_id: request.queue_id,
                    _lifetime: PhantomData,
                };
                from_result(|| {
                    state.xsk_pool_setup(device, setup)?;
                    Ok(0)
                })
            }
            _ => EINVAL.to_errno(),
        }
    }

    unsafe extern "C" fn xsk_wakeup_callback(
        raw_device: *mut bindings::net_device,
        queue_id: u32,
        flags: u32,
    ) -> c_int {
        if raw_device.is_null() {
            return EINVAL.to_errno();
        }
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let state = device.state();
        from_result(|| {
            state.xsk_wakeup(device, queue_id, XskWakeupFlags::from_bits(flags))?;
            Ok(0)
        })
    }

    unsafe extern "C" fn xdp_xmit_callback(
        raw_device: *mut bindings::net_device,
        count: c_int,
        raw_frames: *mut *mut bindings::xdp_frame,
        flags: u32,
    ) -> c_int {
        if raw_device.is_null() || count < 0 || (count != 0 && raw_frames.is_null()) {
            return EINVAL.to_errno();
        }
        // SAFETY: Networking core supplies exactly `count` writable frame pointers for this
        // callback. The batch validates every element before exposing submission.
        let frames = if count == 0 {
            &mut []
        } else {
            // SAFETY: Nonzero counts require a non-null array with exactly `count` entries.
            unsafe { slice::from_raw_parts_mut(raw_frames, count as usize) }
        };
        let mut batch = match XdpFrameBatch::new(frames) {
            Ok(batch) => batch,
            Err(error) => return error.to_errno(),
        };
        let device = unsafe { Device::<T>::from_raw(raw_device) };
        let state = device.state();
        let result = state.xdp_xmit(device, &mut batch, XdpXmitFlags::from_bits(flags));
        let accepted = batch.accepted();
        if accepted != 0 {
            accepted.min(c_int::MAX as usize) as c_int
        } else {
            match result {
                Ok(()) => 0,
                Err(error) => error.to_errno(),
            }
        }
    }

    unsafe extern "C" fn setup_callback(raw: *mut bindings::net_device) {
        // SAFETY: `alloc_netdev_mqs` supplies a newly allocated net_device.
        unsafe {
            bindings::ether_setup(raw);
            (*raw).netdev_ops = &Self::VTABLE;
            if T::HAS_ETHTOOL_OPS {
                (*raw).ethtool_ops = &EthtoolVTable::<T>::VTABLE;
            }
            if T::HAS_QUEUE_STATS {
                (*raw).stat_ops = core::ptr::from_ref(&StatVTable::<T>::VTABLE).cast_mut();
            }
        }
    }

    const VTABLE: bindings::net_device_ops = {
        // SAFETY: A zeroed operations table means every optional callback is
        // absent; the three fields below are then installed before publication.
        let mut table: bindings::net_device_ops = unsafe { core::mem::zeroed() };
        table.ndo_open = Some(Self::open_callback);
        table.ndo_stop = Some(Self::stop_callback);
        table.ndo_start_xmit = Some(Self::start_xmit_callback);
        table.ndo_validate_addr = Some(bindings::eth_validate_addr);
        if T::HAS_SET_MAC_ADDRESS {
            table.ndo_set_mac_address = Some(Self::set_mac_address_callback);
        }
        if T::HAS_SET_RX_MODE {
            table.ndo_set_rx_mode = Some(Self::set_rx_mode_callback);
        }
        if T::HAS_GET_STATS64 {
            table.ndo_get_stats64 = Some(Self::get_stats64_callback);
        }
        if T::HAS_VLAN_RX {
            table.ndo_vlan_rx_add_vid = Some(Self::vlan_rx_add_callback);
            table.ndo_vlan_rx_kill_vid = Some(Self::vlan_rx_kill_callback);
        }
        if T::HAS_PASSTHRU_FEATURES_CHECK {
            table.ndo_features_check = Some(bindings::passthru_features_check);
        }
        if T::HAS_GET_PHYS_PORT_NAME {
            table.ndo_get_phys_port_name = Some(Self::get_phys_port_name_callback);
        }
        if T::HAS_SET_FEATURES {
            table.ndo_set_features = Some(Self::set_features_callback);
        }
        if T::HAS_TX_TIMEOUT {
            table.ndo_tx_timeout = Some(Self::tx_timeout_callback);
        }
        if T::HAS_XDP || T::HAS_XSK {
            table.ndo_bpf = Some(Self::xdp_callback);
        }
        if T::HAS_XDP_XMIT {
            table.ndo_xdp_xmit = Some(Self::xdp_xmit_callback);
        }
        if T::HAS_XSK {
            table.ndo_xsk_wakeup = Some(Self::xsk_wakeup_callback);
        }
        table
    };
}

struct RtnlGuard(PhantomData<*mut ()>);

impl RtnlGuard {
    fn lock() -> Self {
        // SAFETY: This guard balances the lock exactly once in `Drop`.
        unsafe { bindings::rtnl_lock() };
        Self(PhantomData)
    }
}

impl Drop for RtnlGuard {
    fn drop(&mut self) {
        // SAFETY: Construction acquired RTNL on this thread. `PhantomData<*mut ()>` keeps this
        // guard non-`Send`, so destruction and the matching unlock happen on that same thread.
        unsafe { bindings::rtnl_unlock() };
    }
}

/// A registered network device borrowed while its registration transaction holds RTNL.
///
/// The context is deliberately non-`Send`; operations that mutate registration-time fields are
/// available only here, so their locking precondition cannot be omitted by a safe caller.
pub struct RegistrationContext<'a, T: Operations> {
    device: &'a Device<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<T: Operations> RegistrationContext<'_, T> {
    /// Borrow the device while RTNL remains held by the registration transaction.
    pub fn device(&self) -> &Device<T> {
        self.device
    }

    /// Remove hardware features after a fallible post-registration capability handshake.
    pub fn clear_hardware_features(&self, features: Features) {
        // SAFETY: `RegistrationContext` exists only inside `register_transaction`, which holds
        // RTNL for its entire lifetime, and its registration exclusively owns the live netdev.
        unsafe {
            bindings::netdev_hw_features_clear(self.device.as_raw(), features.bits());
        }
    }
}

/// Owning registration for an Ethernet `struct net_device`.
pub struct Registration<T: Operations> {
    raw: NonNull<bindings::net_device>,
    state: *mut c_void,
    registered: bool,
    max_tx_queues: u32,
    max_rx_queues: u32,
    bootstrap_parent: Option<NonNull<bindings::device>>,
    #[cfg(CONFIG_NET_FAILOVER)]
    net_failover: Option<NonNull<bindings::failover>>,
    napis: KVec<Arc<NapiToken<T>>>,
    xdp_rxqs: KVec<Arc<XdpRxQueueToken>>,
    #[cfg(CONFIG_DIMLIB)]
    rx_dim_initialized: bool,
    #[cfg(CONFIG_DIMLIB)]
    rx_dims: KVec<Arc<RxDimToken<T>>>,
    _state: PhantomData<Arc<T>>,
}

// SAFETY: The network core owns callback serialization, the attached state is
// `Send + Sync`, and moving the registration does not move the C net_device.
unsafe impl<T: Operations> Send for Registration<T> {}
unsafe impl<T: Operations> Sync for Registration<T> {}

impl<T: Operations> Registration<T> {
    /// Allocate an Ethernet device with `tx_queues` TX queues and `rx_queues`
    /// RX queues, attaching one reference-counted driver state.
    pub fn new_ethernet(
        name: &CStr,
        tx_queues: u32,
        rx_queues: u32,
        state: Arc<T>,
    ) -> Result<Self> {
        if tx_queues == 0 || rx_queues == 0 {
            return Err(EINVAL);
        }

        // SAFETY: The setup callback initializes the newly allocated device;
        // queue counts are nonzero and the name is a static C string.
        let raw = unsafe {
            bindings::alloc_netdev_mqs(
                size_of::<*mut c_void>() as c_int,
                name.as_char_ptr(),
                bindings::NET_NAME_UNKNOWN as u8,
                Some(OperationsVTable::<T>::setup_callback),
                tx_queues,
                rx_queues,
            )
        };
        let raw = NonNull::new(raw).ok_or(ENOMEM)?;
        let state = state.into_foreign();

        // SAFETY: The allocation reserves a pointer-sized private area and is
        // not registered yet, so this is exclusive initialization.
        unsafe {
            let slot = bindings::netdev_priv(raw.as_ptr()).cast::<*mut c_void>();
            slot.write(state);
        }

        Ok(Self {
            raw,
            state,
            registered: false,
            max_tx_queues: tx_queues,
            max_rx_queues: rx_queues,
            bootstrap_parent: None,
            #[cfg(CONFIG_NET_FAILOVER)]
            net_failover: None,
            napis: KVec::new(),
            xdp_rxqs: KVec::new(),
            #[cfg(CONFIG_DIMLIB)]
            rx_dim_initialized: false,
            #[cfg(CONFIG_DIMLIB)]
            rx_dims: KVec::new(),
            _state: PhantomData,
        })
    }

    /// Apply all basic Ethernet fields while the device is still unpublished.
    pub fn configure(&mut self, config: EthernetConfig) -> Result {
        if self.registered {
            return Err(EBUSY);
        }
        if config.xdp_rx_hash_metadata && !T::HAS_XDP_METADATA_RX_HASH {
            return Err(EOPNOTSUPP);
        }
        if config.rx_queue_sysfs
            && (!T::HAS_RX_QUEUE_SYSFS
                || T::RX_QUEUE_SYSFS_GROUP_NAME.is_empty()
                || T::RX_QUEUE_SYSFS_ATTRIBUTE_NAME.is_empty())
        {
            return Err(EOPNOTSUPP);
        }
        // SAFETY: `&mut self` exclusively owns the unpublished netdev configuration.
        unsafe {
            let raw = self.raw.as_ptr();
            bindings::netdev_add_priv_flags(raw, config.private_flags.bits() as ffi::c_ulong);
            (*raw).features = config.features.bits();
            (*raw).hw_features = config.hardware_features.bits();
            (*raw).hw_enc_features = config.hardware_encapsulation_features.bits();
            (*raw).vlan_features = config.vlan_features.bits();
            (*raw).xdp_features = config.xdp_features.bits();
            (*raw).xdp_metadata_ops = if config.xdp_rx_hash_metadata {
                &XdpMetadataVTable::<T>::VTABLE
            } else {
                core::ptr::null()
            };
            (*raw).sysfs_rx_queue_group = if config.rx_queue_sysfs {
                core::ptr::from_ref(&RxQueueSysfsVTable::<T>::GROUP)
            } else {
                core::ptr::null()
            };
            (*raw).min_mtu = config.min_mtu;
            (*raw).max_mtu = config.max_mtu;
            (*raw).mtu = config.mtu;
            (*raw).needed_headroom = config.needed_headroom;
        }
        Ok(())
    }

    /// Attach the physical/bus parent before registration.
    pub fn set_parent<Ctx: crate::device::DeviceContext>(
        &mut self,
        parent: &crate::device::Device<Ctx>,
    ) -> Result {
        if self.registered {
            return Err(EBUSY);
        }
        self.release_bootstrap_parent();
        let raw_parent = parent.as_raw();
        // SAFETY: `parent` is live, and the extra reference pins it until registration transfers
        // parent ownership to device core or this unpublished registration is dropped.
        unsafe { bindings::get_device(raw_parent) };
        self.bootstrap_parent = NonNull::new(raw_parent);
        // SAFETY: The unpublished netdev is exclusively owned and the stored reference pins parent.
        unsafe { (*self.raw.as_ptr()).dev.parent = raw_parent };
        Ok(())
    }

    /// Install a validated Ethernet address before registration.
    pub fn set_ethernet_address(&mut self, address: EthernetAddress) -> Result {
        if self.registered {
            return Err(EBUSY);
        }
        // SAFETY: The helper copies six bytes into the exclusively owned Ethernet netdev.
        unsafe { bindings::eth_hw_addr_set(self.raw.as_ptr(), address.as_bytes().as_ptr()) };
        Ok(())
    }

    /// Assign a locally administered random Ethernet address before registration.
    pub fn randomize_ethernet_address(&mut self) -> Result<EthernetAddress> {
        if self.registered {
            return Err(EBUSY);
        }
        // SAFETY: The unpublished Ethernet netdev is exclusively owned.
        unsafe { bindings::eth_hw_addr_random(self.raw.as_ptr()) };
        let mut bytes = [0u8; 6];
        // SAFETY: The netdev is unpublished and exclusively borrowed; helper copies six bytes.
        unsafe { bindings::eth_hw_addr_copy(self.raw.as_ptr(), bytes.as_mut_ptr()) };
        EthernetAddress::new(bytes)
    }

    /// Select active TX/RX queue counts within the allocated maxima before publication.
    pub fn set_real_queue_counts(&mut self, tx_queues: u32, rx_queues: u32) -> Result {
        if self.registered
            || tx_queues == 0
            || rx_queues == 0
            || tx_queues > self.max_tx_queues
            || rx_queues > self.max_rx_queues
        {
            return Err(EINVAL);
        }
        // SAFETY: The device is unpublished and counts were bounded by its allocations.
        let old_tx = unsafe { (*self.raw.as_ptr()).real_num_tx_queues };
        to_result(unsafe { bindings::netif_set_real_num_tx_queues(self.raw.as_ptr(), tx_queues) })?;
        // SAFETY: Same exclusive pre-publication guarantee as the TX update.
        let result = to_result(unsafe {
            bindings::netif_set_real_num_rx_queues(self.raw.as_ptr(), rx_queues)
        });
        if result.is_err() {
            // SAFETY: Restore the prior valid TX count before returning a failed transaction.
            let rollback =
                unsafe { bindings::netif_set_real_num_tx_queues(self.raw.as_ptr(), old_tx) };
            debug_assert_eq!(rollback, 0);
        }
        result
    }

    fn release_bootstrap_parent(&mut self) {
        if let Some(parent) = self.bootstrap_parent.take() {
            // SAFETY: This is exactly the extra reference acquired by `set_parent`.
            unsafe { bindings::put_device(parent.as_ptr()) };
        }
    }

    /// Add a pinned NAPI context before publishing the network device.
    ///
    /// Receive contexts use persistent `napi_config` indexing; transmit contexts use the TX-only
    /// registration that avoids receive busy-poll hashing. `context` is returned to
    /// [`Operations::poll`] and is independent from networking-core NAPI indices.
    pub fn add_napi(
        &mut self,
        kind: NapiKind,
        context: u32,
        weight: u32,
        flags: kernel::alloc::Flags,
    ) -> Result<Napi<T>> {
        if self.registered || weight > c_int::MAX as u32 {
            return Err(EINVAL);
        }
        if let NapiKind::Receive { config_index } = &kind {
            if weight == 0 || *config_index > c_int::MAX as u32 {
                return Err(EINVAL);
            }
        }

        let token = Arc::new(
            NapiToken {
                napi: Opaque::zeroed(),
                dev: self.raw,
                context,
                active: AtomicBool::new(false),
                enabled: AtomicBool::new(false),
                users: AtomicUsize::new(0),
                _state: PhantomData,
            },
            flags,
        )?;

        // Reserve ownership before C registration. If allocation fails, no NAPI object was added.
        self.napis.push(token.clone(), flags)?;
        match kind {
            NapiKind::Receive { config_index } => {
                // SAFETY: The Arc pins `napi`; the netdev is allocated but unpublished, and the
                // generic callback matches the state stored in netdev_priv.
                unsafe {
                    bindings::netif_napi_add_config_weight(
                        self.raw.as_ptr(),
                        token.napi.get(),
                        Some(NapiVTable::<T>::poll_callback),
                        config_index as c_int,
                        weight as c_int,
                    )
                };
            }
            NapiKind::Transmit => {
                // SAFETY: Same pinned allocation and typed callback guarantees as RX registration.
                unsafe {
                    bindings::netif_napi_add_tx_weight(
                        self.raw.as_ptr(),
                        token.napi.get(),
                        Some(NapiVTable::<T>::poll_callback),
                        weight as c_int,
                    )
                };
            }
        }
        token.active.store(true, Ordering::Release);
        Ok(Napi { token })
    }

    /// Register one native-XDP receive queue against an existing receive NAPI context.
    pub fn add_xdp_rx_queue(
        &mut self,
        queue_index: u32,
        napi: &Napi<T>,
        flags: Flags,
    ) -> Result<XdpRxQueue> {
        if self.registered
            || napi.token.dev != self.raw
            || !napi.token.active.load(Ordering::Acquire)
            || queue_index >= self.max_rx_queues
        {
            return Err(EINVAL);
        }
        // SAFETY: The helper returns a fresh unregistered allocation or ERR_PTR.
        let raw = from_err_ptr(unsafe { bindings::xdp_rxq_info_create() })?;
        let token = Arc::new(
            XdpRxQueueToken {
                // SAFETY: `from_err_ptr` rejected both error pointers; the helper never returns
                // NULL on success.
                raw: NonNull::new(raw).ok_or(ENOMEM)?,
                dev: self.raw,
                // SAFETY: A successfully added NAPI token has pinned non-null embedded storage.
                napi: unsafe { NonNull::new_unchecked(napi.token.napi.get()) },
                queue_index,
                active: AtomicBool::new(true),
                registered: AtomicBool::new(false),
                transition: AtomicBool::new(false),
                users: AtomicUsize::new(0),
            },
            flags,
        )?;
        self.xdp_rxqs.push(token.clone(), flags)?;
        Ok(XdpRxQueue { token })
    }

    /// Allocate networking core's receive DIM profile before adding queue instances.
    #[cfg(CONFIG_DIMLIB)]
    pub fn init_rx_dim(&mut self) -> Result {
        if self.registered || self.rx_dim_initialized {
            return Err(EBUSY);
        }
        if !T::HAS_RX_DIM {
            return Err(EOPNOTSUPP);
        }
        // SAFETY: The netdev is allocated and unpublished. The typed work callback remains valid
        // for the static operation type, and registration teardown frees the resulting profile.
        to_result(unsafe {
            bindings::net_dim_init_irq_moder(
                self.raw.as_ptr(),
                DIM_PROFILE_RX,
                DIM_COALESCE_USEC_PKTS,
                bindings::dim_cq_period_mode_DIM_CQ_PERIOD_MODE_START_FROM_EQE as u8,
                0,
                Some(RxDimVTable::<T>::work_callback),
                None,
            )
        })?;
        self.rx_dim_initialized = true;
        Ok(())
    }

    /// Add one pinned receive DIM instance before publishing the network device.
    #[cfg(CONFIG_DIMLIB)]
    pub fn add_rx_dim(&mut self, context: u32, flags: Flags) -> Result<RxDim<T>> {
        if self.registered || !self.rx_dim_initialized {
            return Err(EINVAL);
        }
        let token = Arc::new(
            RxDimToken {
                dim: Opaque::zeroed(),
                dev: self.raw,
                context,
                active: AtomicBool::new(false),
                users: AtomicUsize::new(0),
                _state: PhantomData,
            },
            flags,
        )?;
        self.rx_dims.push(token.clone(), flags)?;
        // SAFETY: The Arc pins the zeroed DIM object, IRQ moderation was initialized above, and
        // the typed callback remains installed until synchronous revocation.
        unsafe { bindings::net_dim_setting(self.raw.as_ptr(), token.dim.get(), false) };
        token.active.store(true, Ordering::Release);
        Ok(RxDim { token })
    }

    #[cfg(CONFIG_DIMLIB)]
    fn release_rx_dims(&mut self) {
        for dim in &self.rx_dims {
            dim.revoke();
        }
        self.rx_dims.clear();
        if self.rx_dim_initialized {
            let _guard = RtnlGuard::lock();
            // SAFETY: RTNL is held, every DIM work item is synchronously canceled, and this
            // registration owns the netdev's IRQ moderation allocation.
            unsafe { bindings::net_dim_free_irq_moder(self.raw.as_ptr()) };
            self.rx_dim_initialized = false;
        }
    }

    /// Publish the network device and run a fallible initialization closure before releasing RTNL.
    ///
    /// `ndo_open` and other RTNL-serialized control paths cannot observe the device between
    /// registration and `post_register`. If the closure fails, the device is unregistered before
    /// this method returns.
    pub fn register_transaction<F>(&mut self, post_register: F) -> Result
    where
        F: FnOnce(&RegistrationContext<'_, T>) -> Result,
    {
        if self.registered {
            return Err(EINVAL);
        }
        let _guard = RtnlGuard::lock();
        // SAFETY: RTNL is held and the device plus its operations/private state are fully
        // initialized and remain owned by this registration.
        to_result(unsafe { bindings::register_netdevice(self.raw.as_ptr()) })?;
        self.registered = true;
        // Device core now owns the registered child's parent reference.
        self.release_bootstrap_parent();
        let context = RegistrationContext {
            device: self.device(),
            _not_send: PhantomData,
        };
        if let Err(error) = post_register(&context) {
            // SAFETY: RTNL remains held, and this registration owns the published device.
            unsafe { bindings::unregister_netdevice(self.raw.as_ptr()) };
            self.registered = false;
            return Err(error);
        }
        Ok(())
    }

    /// Publish the network device. On success callbacks may begin immediately.
    pub fn register(&mut self) -> Result {
        self.register_transaction(|_| Ok(()))
    }

    /// Create a net-failover master and then publish this standby device.
    ///
    /// The failover master copies the fully configured, unpublished standby identity. A failed
    /// standby registration destroys the master before returning; successful teardown always
    /// unregisters the standby first and destroys the master second.
    #[cfg(CONFIG_NET_FAILOVER)]
    pub fn register_with_net_failover(&mut self) -> Result {
        self.register_with_net_failover_transaction(|_| Ok(()))
    }

    /// Create a net-failover master, publish the standby, and initialize it under RTNL.
    #[cfg(CONFIG_NET_FAILOVER)]
    pub fn register_with_net_failover_transaction<F>(&mut self, post_register: F) -> Result
    where
        F: FnOnce(&RegistrationContext<'_, T>) -> Result,
    {
        if self.registered || self.net_failover.is_some() || self.bootstrap_parent.is_none() {
            return Err(EINVAL);
        }
        // SAFETY: This registration exclusively owns a fully configured but unpublished Ethernet
        // netdev. Its parent and address remain pinned for the entire create/register transaction.
        let failover = from_err_ptr(unsafe { bindings::net_failover_create(self.raw.as_ptr()) })?;
        self.net_failover = Some(NonNull::new(failover).ok_or(ENOMEM)?);
        if let Err(error) = self.register_transaction(post_register) {
            self.release_net_failover();
            return Err(error);
        }
        Ok(())
    }

    /// Return `EOPNOTSUPP` when this kernel has no net-failover implementation.
    #[cfg(not(CONFIG_NET_FAILOVER))]
    pub fn register_with_net_failover(&mut self) -> Result {
        Err(EOPNOTSUPP)
    }

    /// Return `EOPNOTSUPP` when this kernel has no net-failover implementation.
    #[cfg(not(CONFIG_NET_FAILOVER))]
    pub fn register_with_net_failover_transaction<F>(&mut self, _post_register: F) -> Result
    where
        F: FnOnce(&RegistrationContext<'_, T>) -> Result,
    {
        Err(EOPNOTSUPP)
    }

    #[cfg(CONFIG_NET_FAILOVER)]
    fn release_net_failover(&mut self) {
        if let Some(failover) = self.net_failover.take() {
            // SAFETY: This registration created and uniquely owns the failover instance. The
            // standby has already been unregistered when it was ever published.
            unsafe { bindings::net_failover_destroy(failover.as_ptr()) };
        }
    }

    /// Unregister the device and wait for networking callbacks to quiesce.
    pub fn unregister(&mut self) {
        #[cfg(CONFIG_DIMLIB)]
        self.release_rx_dims();
        if self.registered {
            // SAFETY: This registration owns the published device.
            unsafe { bindings::unregister_netdev(self.raw.as_ptr()) };
            self.registered = false;
        }
        #[cfg(CONFIG_NET_FAILOVER)]
        self.release_net_failover();
        for rxq in &self.xdp_rxqs {
            rxq.revoke();
        }
        self.xdp_rxqs.clear();
        for napi in &self.napis {
            napi.revoke();
        }
        self.napis.clear();
    }

    /// Borrow the live device.
    pub fn device(&self) -> &Device<T> {
        // SAFETY: The registration owns this allocation for `self`'s lifetime.
        unsafe { Device::from_raw(self.raw.as_ptr()) }
    }
}

impl<T: Operations> Drop for Registration<T> {
    fn drop(&mut self) {
        self.unregister();
        self.release_bootstrap_parent();
        // SAFETY: `self.state` is the unique foreign reference created by
        // `new_ethernet`; unregister has drained callbacks borrowing it.
        drop(unsafe { <Arc<T> as ForeignOwnable>::from_foreign(self.state) });
        // SAFETY: The network device is unregistered and owned by this object.
        unsafe { bindings::free_netdev(self.raw.as_ptr()) };
    }
}
