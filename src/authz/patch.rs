//! Per-key constraint patch for `PATCH /admin/v1/grants/:id`.
//!
//! Each key is tri-state: absent keeps the stored value, `null` clears it,
//! a value sets it. Replacing the whole object instead would let a PATCH
//! that names only `row_limit` silently drop `require_reason` — loosening a
//! constraint the caller never mentioned. Pure; proofs in `patch_proptests`.

use serde::{Deserialize, Deserializer};

use crate::config::Constraints;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintsPatch {
    #[serde(default, deserialize_with = "present")]
    pub require_reason: Option<Option<bool>>,
    #[serde(default, deserialize_with = "present")]
    pub row_limit: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub statement_timeout_ms: Option<Option<u32>>,
}

impl ConstraintsPatch {
    /// Names no key — applying it changes nothing.
    pub fn is_empty(&self) -> bool {
        self.require_reason.is_none()
            && self.row_limit.is_none()
            && self.statement_timeout_ms.is_none()
    }

    /// The stored constraints with this patch's named keys applied. A cleared
    /// `require_reason` is `false`, its schema default.
    pub fn apply(&self, current: &Constraints) -> Constraints {
        Constraints {
            require_reason: match self.require_reason {
                Some(value) => value.unwrap_or(false),
                None => current.require_reason,
            },
            row_limit: self.row_limit.unwrap_or(current.row_limit),
            statement_timeout_ms: self
                .statement_timeout_ms
                .unwrap_or(current.statement_timeout_ms),
        }
    }
}

/// A key that is present deserializes to `Some(_)` — `Some(None)` for an
/// explicit `null`. An absent key never reaches this and stays `None` via
/// `#[serde(default)]`.
fn present<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}
