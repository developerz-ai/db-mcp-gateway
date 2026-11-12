//! Spec 03 outcome codes as a closed set. Tools pick a variant; the string
//! form exists only at the edges — the client error payload, the metric
//! label, the log line and the audit row.

/// `"success"` or a spec 03 error code. `Cancelled` is never returned by a
/// tool: the drop guard stamps it on a row whose work never finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeCode {
    Success,
    Forbidden,
    ForbiddenSql,
    InvalidArguments,
    ReasonRequired,
    Timeout,
    SyntaxError,
    Unavailable,
    Internal,
    Cancelled,
}

impl OutcomeCode {
    /// The wire / `audit_calls.outcome` spelling (spec 03 §Errors).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Forbidden => "forbidden",
            Self::ForbiddenSql => "forbidden_sql",
            Self::InvalidArguments => "invalid_arguments",
            Self::ReasonRequired => "reason_required",
            Self::Timeout => "timeout",
            Self::SyntaxError => "syntax_error",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::Cancelled => "cancelled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OutcomeCode;

    /// Pins every spelling against spec 03 §Errors — a renamed variant must
    /// not silently change what lands in `audit_calls.outcome`.
    #[test]
    fn spellings_match_spec_03() {
        let expected = [
            (OutcomeCode::Success, "success"),
            (OutcomeCode::Forbidden, "forbidden"),
            (OutcomeCode::ForbiddenSql, "forbidden_sql"),
            (OutcomeCode::InvalidArguments, "invalid_arguments"),
            (OutcomeCode::ReasonRequired, "reason_required"),
            (OutcomeCode::Timeout, "timeout"),
            (OutcomeCode::SyntaxError, "syntax_error"),
            (OutcomeCode::Unavailable, "unavailable"),
            (OutcomeCode::Internal, "internal"),
            (OutcomeCode::Cancelled, "cancelled"),
        ];
        for (code, spelling) in expected {
            assert_eq!(code.as_str(), spelling);
        }
    }
}
