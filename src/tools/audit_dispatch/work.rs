//! Running a dispatch's work so that a panic inside it still ends in an
//! audited answer.

use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures::FutureExt;
use sqlx::PgPool;

use super::cancel_guard::flag_if_write;
use super::{Outcome, OutcomeCode, RequestContext, error_outcome};

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
            let request_id = request_ctx.request_id.to_string();
            let message = flag_if_write(state_db, &request_id, PANICKED).await;
            error_outcome(OutcomeCode::Internal, &message)
        }
    }
}
