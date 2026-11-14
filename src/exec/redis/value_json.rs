//! RESP reply values → JSON. Bulk strings that are not UTF-8 become
//! `{"base64": "…"}` rather than lossy text, so a binary value is never
//! silently corrupted.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use redis::Value as Reply;
use serde_json::{Map, Number, Value};

use super::super::adapter::ExecError;

/// One reply value as JSON. A nested server error (only reachable through
/// `EXEC`, which the allowlist refuses) or an unknown variant is a decode
/// failure, never `null`.
pub(super) fn to_json(reply: Reply) -> Result<Value, ExecError> {
    Ok(match reply {
        Reply::Nil => Value::Null,
        Reply::Int(n) => Value::from(n),
        Reply::BulkString(bytes) => bytes_to_json(bytes),
        Reply::SimpleString(s) => Value::String(s),
        Reply::Okay => Value::String("OK".to_string()),
        Reply::Boolean(b) => Value::Bool(b),
        // JSON has no infinity or NaN: those keep Redis' own spelling.
        Reply::Double(d) => Number::from_f64(d).map_or_else(|| double_text(d), Value::Number),
        Reply::VerbatimString { text, .. } => Value::String(text),
        Reply::BigNumber(digits) => bytes_to_json(digits),
        Reply::Array(items) | Reply::Set(items) | Reply::Push { data: items, .. } => {
            Value::Array(items.into_iter().map(to_json).collect::<Result<_, _>>()?)
        }
        Reply::Map(pairs) => {
            let mut object = Map::with_capacity(pairs.len());
            for (key, value) in pairs {
                object.insert(key_text(key)?, to_json(value)?);
            }
            Value::Object(object)
        }
        Reply::Attribute { data, .. } => to_json(*data)?,
        // `redis::Value` is non-exhaustive: a variant added later is not
        // guessed at.
        Reply::ServerError(_) | _ => return Err(ExecError::Decode),
    })
}

/// A value used as a JSON object key (a stream field name, a RESP3 map key):
/// its text, with a non-UTF-8 name spelled `base64:<encoded>` because a JSON
/// key cannot be an object.
pub(super) fn key_text(reply: Reply) -> Result<String, ExecError> {
    match reply {
        Reply::BulkString(bytes) => Ok(String::from_utf8(bytes)
            .unwrap_or_else(|err| format!("base64:{}", STANDARD.encode(err.into_bytes())))),
        Reply::SimpleString(s) | Reply::VerbatimString { text: s, .. } => Ok(s),
        Reply::Int(n) => Ok(n.to_string()),
        Reply::Double(d) => Ok(d.to_string()),
        Reply::Boolean(b) => Ok(b.to_string()),
        _ => Err(ExecError::Decode),
    }
}

fn bytes_to_json(bytes: Vec<u8>) -> Value {
    match String::from_utf8(bytes) {
        Ok(text) => Value::String(text),
        Err(err) => {
            let mut object = Map::with_capacity(1);
            object.insert(
                "base64".to_string(),
                Value::String(STANDARD.encode(err.into_bytes())),
            );
            Value::Object(object)
        }
    }
}

fn double_text(d: f64) -> Value {
    let text = if d.is_nan() {
        "nan"
    } else if d.is_sign_positive() {
        "inf"
    } else {
        "-inf"
    };
    Value::String(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalars_map_one_to_one() {
        assert_eq!(to_json(Reply::Nil).unwrap(), Value::Null);
        assert_eq!(to_json(Reply::Int(-7)).unwrap(), json!(-7));
        assert_eq!(to_json(Reply::Okay).unwrap(), json!("OK"));
        assert_eq!(to_json(Reply::Boolean(true)).unwrap(), json!(true));
        assert_eq!(to_json(Reply::Double(1.5)).unwrap(), json!(1.5));
        assert_eq!(to_json(Reply::Double(f64::INFINITY)).unwrap(), json!("inf"));
        assert_eq!(
            to_json(Reply::BulkString(b"caf\xc3\xa9".to_vec())).unwrap(),
            json!("café")
        );
    }

    #[test]
    fn non_utf8_bulk_strings_are_base64_never_lossy() {
        let reply = Reply::BulkString(vec![0xff, 0x00, 0xfe]);
        assert_eq!(to_json(reply).unwrap(), json!({"base64": "/wD+"}));
        let key = key_text(Reply::BulkString(vec![0xff])).unwrap();
        assert_eq!(key, "base64:/w==");
    }

    #[test]
    fn nested_values_keep_their_structure() {
        let reply = Reply::Array(vec![
            Reply::Int(1),
            Reply::Map(vec![(
                Reply::BulkString(b"k".to_vec()),
                Reply::Array(vec![Reply::Nil]),
            )]),
        ]);
        assert_eq!(to_json(reply).unwrap(), json!([1, {"k": [null]}]));
    }

    #[test]
    fn a_nested_server_error_is_a_decode_failure() {
        let reply = redis::parse_redis_value(b"*1\r\n-ERR boom\r\n").expect("parses");
        assert!(matches!(to_json(reply), Err(ExecError::Decode)));
    }
}
