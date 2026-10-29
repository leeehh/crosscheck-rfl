// SPDX-License-Identifier: GPL-2.0

//! Small kernel utility helpers.

use crate::prelude::*;

/// Return the index of the entry closest to `value`.
///
/// `values` must be sorted in ascending order, matching the contract of the C
/// `find_closest()` macro in `include/linux/util_macros.h`. On unsorted or descending input the
/// returned index may differ from the C macro (which assumes ascending order and bisects on
/// adjacent midpoints).
pub fn find_closest(value: i64, values: &[u32]) -> Result<usize> {
    if values.is_empty() {
        return Err(EINVAL);
    }

    let mut best = 0usize;
    let mut best_delta = (value - values[0] as i64).abs();

    for (index, item) in values.iter().enumerate().skip(1) {
        let delta = (value - *item as i64).abs();
        if delta < best_delta {
            best = index;
            best_delta = delta;
        }
    }

    Ok(best)
}
