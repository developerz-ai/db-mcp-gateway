//! `params` of `run_query` and `explain`: the JSON values bound to the
//! statement's `$1..$n`, checked once at the tool edge. A param is a value
//! to the target, never SQL text: the guard reads `sql` alone.

use serde_json::Value;

use crate::config::ServerKind;
use crate::exec::QueryParam;

/// Most params one statement binds.
pub(super) const MAX_PARAMS: usize = 100;

/// Longest one param's JSON may be.
pub(super) const MAX_PARAM_BYTES: usize = 64 * 1024;

/// 2^63: a float this large is an integer the JSON parser could not hold
/// exactly, or a float written past int8 — either way not bound as given.
const INT8_BOUND: f64 = 9_223_372_036_854_775_808.0;

const PAST_INT8: &str = "integer past int8; pass it as a string and cast it, e.g. `$1::numeric`";

/// `raw` as typed params, or the `invalid_arguments` message naming the
/// first one refused.
pub(super) fn parse_params(raw: &[Value]) -> Result<Vec<QueryParam>, String> {
    if raw.len() > MAX_PARAMS {
        return Err(format!(
            "`params`: at most {MAX_PARAMS} values, got {}",
            raw.len()
        ));
    }
    raw.iter()
        .enumerate()
        .map(|(at, value)| {
            parse_param(value).map_err(|why| format!("`params[{at}]` (${}): {why}", at + 1))
        })
        .collect()
}

fn parse_param(value: &Value) -> Result<QueryParam, String> {
    let bytes = value.to_string().len();
    if bytes > MAX_PARAM_BYTES {
        return Err(format!("{bytes} bytes of JSON; at most {MAX_PARAM_BYTES}"));
    }
    Ok(match value {
        Value::Null => QueryParam::Null,
        Value::Bool(flag) => QueryParam::Bool(*flag),
        Value::Number(number) => {
            let float = number.as_f64().ok_or("not a number")?;
            if let Some(int) = number.as_i64() {
                QueryParam::Int(int)
            } else if number.is_u64() || float.abs() >= INT8_BOUND {
                // An integer token past u64 or below i64 arrives already
                // rounded to a float: refused like one in u64.
                return Err(PAST_INT8.to_owned());
            } else {
                QueryParam::Float(float)
            }
        }
        Value::String(text) => QueryParam::Text(text.clone()),
        Value::Array(_) | Value::Object(_) => QueryParam::Json(value.clone()),
    })
}

/// Why `kind` refuses `params`, if it does: only Postgres binds positional
/// placeholders.
pub(super) fn unsupported_for(kind: ServerKind) -> Option<String> {
    match kind {
        ServerKind::Postgres => None,
        other => Some(format!(
            "`params` is not supported for {}",
            super::db_type_label(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn each_json_type_binds_as_its_sql_type() {
        let parsed = parse_params(&[
            json!(null),
            json!(true),
            json!(-7),
            json!(1.5),
            json!("x"),
            json!([1, 2]),
            json!({"a": 1}),
        ])
        .expect("parses");
        assert_eq!(
            parsed,
            vec![
                QueryParam::Null,
                QueryParam::Bool(true),
                QueryParam::Int(-7),
                QueryParam::Float(1.5),
                QueryParam::Text("x".into()),
                QueryParam::Json(json!([1, 2])),
                QueryParam::Json(json!({"a": 1})),
            ]
        );
    }

    #[test]
    fn an_integer_past_int8_is_refused_not_rounded() {
        let err = parse_params(&[json!(1), json!(u64::MAX)]).unwrap_err();
        assert!(
            err.starts_with("`params[1]` ($2): integer past int8"),
            "{err}"
        );
        // Past u64 (or below i64) the JSON parser already holds a rounded
        // float: refused all the same, signed and unsigned.
        let parsed: Vec<Value> =
            serde_json::from_str("[18446744073709551617, -9223372036854775809, 1e19]")
                .expect("JSON");
        for (at, value) in parsed.iter().enumerate() {
            let err = parse_params(std::slice::from_ref(value)).unwrap_err();
            assert!(err.contains("integer past int8"), "{at}: {err}");
        }
        // Inside the range a float stays a float.
        assert_eq!(
            parse_params(&[json!(-9.2e18), json!(4.5e15)]),
            Ok(vec![QueryParam::Float(-9.2e18), QueryParam::Float(4.5e15)])
        );
    }

    #[test]
    fn the_count_and_size_caps_hold() {
        let too_many = vec![json!(1); MAX_PARAMS + 1];
        assert!(parse_params(&too_many).unwrap_err().contains("at most 100"));
        assert!(parse_params(&vec![json!(1); MAX_PARAMS]).is_ok());

        // A string's JSON adds its two quotes.
        let at_cap = json!("x".repeat(MAX_PARAM_BYTES - 2));
        assert!(parse_params(&[at_cap]).is_ok());
        let past = json!("x".repeat(MAX_PARAM_BYTES - 1));
        assert!(parse_params(&[past]).unwrap_err().contains("at most 65536"));
    }

    #[test]
    fn only_postgres_takes_params() {
        assert_eq!(unsupported_for(ServerKind::Postgres), None);
        assert_eq!(
            unsupported_for(ServerKind::Mongo).as_deref(),
            Some("`params` is not supported for mongo")
        );
        assert!(unsupported_for(ServerKind::Redis).is_some());
    }
}
