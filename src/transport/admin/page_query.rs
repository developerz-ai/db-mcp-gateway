//! Shared `?limit=&offset=` parsing for the admin list endpoints.
//!
//! The three list handlers previously fetched every live row (#136). They now
//! take a bounded window; this is the query-string half of that, kept in one
//! place so `/users`, `/databases` and `/grants` can't drift apart on defaults
//! or clamping.

use serde::Deserialize;

use super::error::AdminError;
use crate::state::permissions::Page;

/// A malformed `?limit=`/`?offset=` (or any unparseable query string) on an
/// admin list endpoint. Shared by all three so the wording stays identical.
pub fn invalid_query(request_id: &str) -> AdminError {
    AdminError::invalid("invalid query parameters").with_request_id(request_id)
}

/// `?limit=&offset=` on a list endpoint. Both optional.
///
/// Out-of-range `limit` is clamped rather than rejected (see [`Page::new`]),
/// matching how the gateway treats every other caller-supplied bound. A
/// non-numeric value is a genuine client mistake and surfaces as Axum's
/// `Query` rejection, which handlers translate to `invalid_request`.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

impl PageQuery {
    pub fn to_page(&self) -> Page {
        Page::new(self.limit, self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_params_use_the_default_window() {
        let page = PageQuery::default().to_page();
        assert_eq!(page.limit(), i64::from(Page::DEFAULT_LIMIT));
        assert_eq!(page.offset(), 0);
    }

    #[test]
    fn oversized_limit_is_clamped_not_rejected() {
        let page = PageQuery {
            limit: Some(u32::MAX),
            offset: None,
        }
        .to_page();
        assert_eq!(page.limit(), i64::from(Page::MAX_LIMIT));
    }

    /// A zero limit would spend a round trip to return nothing; clamp it to a
    /// usable minimum instead.
    #[test]
    fn zero_limit_is_clamped_to_one() {
        let page = PageQuery {
            limit: Some(0),
            offset: None,
        }
        .to_page();
        assert_eq!(page.limit(), 1);
    }

    #[test]
    fn offset_passes_through() {
        let page = PageQuery {
            limit: Some(10),
            offset: Some(250),
        }
        .to_page();
        assert_eq!((page.limit(), page.offset()), (10, 250));
    }
}
