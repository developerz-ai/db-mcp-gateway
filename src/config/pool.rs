//! `pool:` — per-server and per-database target pool sizing (spec 08). Every
//! field is optional; exec merges database → server → built-in default per
//! field.

use std::num::{NonZeroU32, NonZeroU64};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Ceiling on open connections. Zero is unrepresentable: it would time
    /// out every acquire.
    #[serde(default)]
    pub max_connections: Option<NonZeroU32>,
    /// Connections kept open while idle. `0` is valid (fully lazy).
    #[serde(default)]
    pub min_connections: Option<u32>,
    /// Seconds an idle connection above `min_connections` lives.
    #[serde(default)]
    pub idle_timeout_s: Option<NonZeroU64>,
}

impl PoolConfig {
    /// `min_connections` above `max_connections` when both are set here.
    /// (A min inherited from one level and a max from another is checked by
    /// exec after the merge.)
    pub(crate) fn min_exceeds_max(&self) -> bool {
        matches!(
            (self.min_connections, self.max_connections),
            (Some(min), Some(max)) if min > max.get()
        )
    }
}
