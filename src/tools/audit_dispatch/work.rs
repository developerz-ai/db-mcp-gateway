//! Running a dispatch's work so that a panic inside it still ends in an
//! audited answer.

use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures::FutureExt;
use sqlx::PgPool;

use crate::audit::intent::WRITE_MAY_HAVE_COMMITTED;

use super::cancel_guard::intent_wrote;
use super::metric_names::HANDLER_PANICS;
use super::{Outcome, OutcomeCode, RequestContext, WriteEffect, WriteState, error_outcome};

/// What the client and the row are told; the panic payload never is.
const PANICKED: &str = "internal error";

/// Await the tool's work. A panic inside it — a defect, e.g. a decoder that
/// meets a value it cannot represent — becomes an `internal` outcome, so the
/// call is still audited as completed and answered, not reported as
/// `cancelled` with the connection dropped. A write may have committed
/// before the panic, so its row says so, as a dropped write's does. The work
/// future is discarded after the panic and never polled again, so unwind
/// safety is moot.
pub(super) async fn run_work<Fut>(
    work: Fut,
    request_ctx: &RequestContext,
    tool: &'static str,
    state_db: &PgPool,
) -> Outcome
where
    Fut: Future<Output = Outcome>,
{
    match AssertUnwindSafe(work).catch_unwind().await {
        Ok(outcome) => outcome,
        Err(_) => {
            // The panic payload is not logged: it may quote target data.
            tracing::error!(
                request_id = %request_ctx.request_id,
                tool,
                "tool work panicked; answering internal"
            );
            metrics::counter!(HANDLER_PANICS, "layer" => "tool_work").increment(1);
            let request_id = request_ctx.request_id.to_string();
            if !intent_wrote(state_db, &request_id).await {
                return error_outcome(OutcomeCode::Internal, PANICKED);
            }
            let mut outcome = error_outcome(
                OutcomeCode::Internal,
                &format!("{PANICKED} ({WRITE_MAY_HAVE_COMMITTED})"),
            );
            outcome.write = Some(WriteEffect {
                rows_affected: None,
                state: WriteState::Unknown,
            });
            outcome
        }
    }
}
