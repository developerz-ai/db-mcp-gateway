//! Spec 03 outcome codes as a closed set. Tools pick a variant; the string
//! form exists only at the edges — the client error payload, the metric
//! label, the log line and the `audit_calls.outcome` column.

/// `"success"` or a spec 03 error code. Three variants are never returned by
/// a tool: `Cancelled` (the drop guard stamps it on a row whose work never
/// finished), `Abandoned` (the reaper stamps it on an intent that never got a
/// completion row) and `AuditUnavailable` (the chokepoint answers it when the
/// audit store refuses a write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeCode {
    Success,
    Forbidden,
    ForbiddenSql,
    PermissionDenied,
    UndefinedObject,
    InvalidArguments,
    ReasonRequired,
    Timeout,
    SyntaxError,
    Unavailable,
    Internal,
    Cancelled,
    Abandoned,
    AuditUnavailable,
}

impl OutcomeCode {
    const ALL: [Self; 14] = [
        Self::Success,
        Self::Forbidden,
        Self::ForbiddenSql,
        Self::PermissionDenied,
        Self::UndefinedObject,
        Self::InvalidArguments,
        Self::ReasonRequired,
        Self::Timeout,
        Self::SyntaxError,
        Self::Unavailable,
        Self::Internal,
        Self::Cancelled,
        Self::Abandoned,
        Self::AuditUnavailable,
    ];

    /// The wire / `audit_calls.outcome` spelling (spec 03 §Errors).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Forbidden => "forbidden",
            Self::ForbiddenSql => "forbidden_sql",
            Self::PermissionDenied => "permission_denied",
            Self::UndefinedObject => "undefined_object",
            Self::InvalidArguments => "invalid_arguments",
            Self::ReasonRequired => "reason_required",
            Self::Timeout => "timeout",
            Self::SyntaxError => "syntax_error",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }

    /// Inverse of [`Self::as_str`], for reading `audit_calls.outcome` back.
    pub fn parse(spelling: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == spelling)
    }
}

impl std::fmt::Display for OutcomeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lets tests compare a row's outcome against the spec spelling directly.
impl PartialEq<&str> for OutcomeCode {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
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
            (OutcomeCode::PermissionDenied, "permission_denied"),
            (OutcomeCode::UndefinedObject, "undefined_object"),
            (OutcomeCode::InvalidArguments, "invalid_arguments"),
            (OutcomeCode::ReasonRequired, "reason_required"),
            (OutcomeCode::Timeout, "timeout"),
            (OutcomeCode::SyntaxError, "syntax_error"),
            (OutcomeCode::Unavailable, "unavailable"),
            (OutcomeCode::Internal, "internal"),
            (OutcomeCode::Cancelled, "cancelled"),
            (OutcomeCode::Abandoned, "abandoned"),
            (OutcomeCode::AuditUnavailable, "audit_unavailable"),
        ];
        assert_eq!(expected.len(), OutcomeCode::ALL.len());
        for (code, spelling) in expected {
            assert_eq!(code.as_str(), spelling);
            assert_eq!(OutcomeCode::parse(spelling), Some(code));
            // The serde form feeds the stream sinks; it must match the column.
            assert_eq!(
                serde_json::to_value(code).unwrap(),
                serde_json::Value::from(spelling)
            );
        }
        assert_eq!(OutcomeCode::parse("ok"), None);
    }
}
