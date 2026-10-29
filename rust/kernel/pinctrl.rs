// SPDX-License-Identifier: GPL-2.0

//! Pin control subsystem helpers.
//!
//! C headers: [`include/linux/pinctrl/pinconf-generic.h`](srctree/include/linux/pinctrl/pinconf-generic.h).

use crate::{bindings, prelude::*};

/// Generic pin configuration helpers.
pub mod pinconf {
    use super::*;

    /// Generic pin configuration parameter.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Param(bindings::pin_config_param);

    impl Param {
        /// Disable pin bias.
        pub const BIAS_DISABLE: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_BIAS_DISABLE);
        /// Use the pin's default pull (whatever the hardware powers up with).
        pub const BIAS_PULL_PIN_DEFAULT: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_BIAS_PULL_PIN_DEFAULT);
        /// Pull the pin down.
        pub const BIAS_PULL_DOWN: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_BIAS_PULL_DOWN);
        /// Pull the pin up.
        pub const BIAS_PULL_UP: Self = Self(bindings::pin_config_param_PIN_CONFIG_BIAS_PULL_UP);
        /// Drive the pin open-drain.
        pub const DRIVE_OPEN_DRAIN: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_DRIVE_OPEN_DRAIN);
        /// Drive the pin open-source.
        pub const DRIVE_OPEN_SOURCE: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_DRIVE_OPEN_SOURCE);
        /// Drive the pin push-pull.
        pub const DRIVE_PUSH_PULL: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_DRIVE_PUSH_PULL);
        /// Enable output mode.
        pub const OUTPUT_ENABLE: Self =
            Self(bindings::pin_config_param_PIN_CONFIG_OUTPUT_ENABLE);

        /// Return the raw kernel enum value.
        pub const fn as_raw(self) -> bindings::pin_config_param {
            self.0
        }
    }

    /// A packed generic pin configuration word.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Config(c_ulong);

    impl Config {
        /// Wrap a raw pin configuration word.
        pub const fn from_raw(raw: c_ulong) -> Self {
            Self(raw)
        }

        /// Return the configuration parameter.
        pub const fn param(self) -> Param {
            Param((self.0 & 0xff) as bindings::pin_config_param)
        }

        /// Return the configuration argument.
        pub const fn argument(self) -> u32 {
            ((self.0 >> 8) & 0x00ff_ffff) as u32
        }
    }
}
