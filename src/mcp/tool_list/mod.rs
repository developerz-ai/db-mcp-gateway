//! The advertised `tools/list`: one name, title, description, input schema
//! and annotations per tool `crate::tools::dispatch_call` routes, in the
//! order an agent uses them. Wire contract:
//! website/docs/initial-idea/03-mcp-tools.md.

mod catalog;
mod query;

use super::protocol::ToolsListResult;

const REASON_DESCRIPTION: &str =
    "Why you are making this call; required when the grant sets require_reason.";
/// `db_activity` and `cancel_query`.
const RUN_SCOPED_DESCRIPTION: &str = "Service accounts only: true refuses the call \
                                      (invalid_arguments) unless it carries x-dbmcp-run-id, so \
                                      it covers that run's statements only. The run id is \
                                      unverified: a filter, not isolation.";

impl ToolsListResult {
    pub(super) fn build() -> Self {
        Self {
            tools: vec![
                catalog::list_servers(),
                catalog::list_databases(),
                catalog::describe_schema(),
                query::sample_table(),
                query::explain(),
                query::run_query(),
                catalog::get_query_history(),
                catalog::table_stats(),
                catalog::db_activity(),
                query::cancel_query(),
                catalog::whoami(),
            ],
        }
    }
}
