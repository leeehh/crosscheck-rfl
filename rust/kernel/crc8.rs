// SPDX-License-Identifier: GPL-2.0

//! CRC-8 helpers.
//!
//! C header: [`include/linux/crc8.h`](srctree/include/linux/crc8.h)

/// Number of entries in a CRC-8 lookup table.
pub const TABLE_SIZE: usize = 256;

/// The canonical CRC-8 seed used by most in-tree consumers.
///
/// Equals the C `CRC8_INIT_VALUE` (`0xff`) from `include/linux/crc8.h`. Pass this to
/// [`Table::checksum`] unless the device datasheet specifies a different initial value.
pub const CRC8_INIT_VALUE: u8 = 0xff;

/// A zero seed for CRC-8 computation.
///
/// This is *not* the value `include/linux/crc8.h` defines as `CRC8_INIT_VALUE` (which is
/// [`CRC8_INIT_VALUE`], i.e. `0xff`). Linux's `crc8()` helper takes the seed as a parameter and
/// bakes in no default; a zero seed is only correct for callers whose protocol specifies it. Use
/// [`CRC8_INIT_VALUE`] to match the common kernel convention.
pub const INIT_VALUE: u8 = 0;

/// A CRC-8 lookup table.
#[derive(Clone)]
pub struct Table([u8; TABLE_SIZE]);

impl Table {
    /// Build an MSB-first CRC-8 table for `polynomial`.
    pub fn new_msb(polynomial: u8) -> Self {
        let mut table = [0u8; TABLE_SIZE];

        for (i, slot) in table.iter_mut().enumerate() {
            let mut crc = i as u8;
            for _ in 0..8 {
                crc = if crc & 0x80 != 0 {
                    (crc << 1) ^ polynomial
                } else {
                    crc << 1
                };
            }
            *slot = crc;
        }

        Self(table)
    }

    /// Calculate CRC-8 over `data`, starting with `crc`.
    pub fn checksum(&self, data: &[u8], mut crc: u8) -> u8 {
        for byte in data {
            crc = self.0[(crc ^ *byte) as usize];
        }

        crc
    }
}
