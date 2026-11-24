use serde_json::json;

use super::*;
use crate::exec::adapter::MAX_RESULT_BYTES;
use crate::exec::budget::ResultBudget;

/// A one-dimensional wire array of `items` (`None` is NULL).
fn wire_array(items: &[Option<&[u8]>]) -> Vec<u8> {
    let len = i32::try_from(items.len()).expect("short array");
    let mut out = Vec::new();
    for header in [1, 1, 16, len, 1] {
        out.extend(i32::to_be_bytes(header));
    }
    for item in items {
        match item {
            Some(bytes) => {
                out.extend(i32::try_from(bytes.len()).expect("short").to_be_bytes());
                out.extend(*bytes);
            }
            None => out.extend((-1i32).to_be_bytes()),
        }
    }
    out
}

fn decode_array(element: Scalar, wire: &[u8]) -> Result<Value, Refused> {
    let budget = ResultBudget::new(1);
    array(element, wire, &mut RowWeight::new(&budget))
}

#[test]
fn an_array_keeps_its_nulls() {
    let wire = wire_array(&[Some(&[1]), None, Some(&[0])]);
    assert_eq!(
        decode_array(Scalar::Bool, &wire),
        Ok(json!([true, null, false]))
    );
    let empty: Vec<u8> = [0i32, 0, 16]
        .into_iter()
        .flat_map(i32::to_be_bytes)
        .collect();
    assert_eq!(decode_array(Scalar::Bool, &empty), Ok(json!([])));
}

#[test]
fn an_array_that_is_not_what_it_says_is_refused() {
    let good = wire_array(&[Some(&[1]), Some(&[0])]);
    for cut in 0..good.len() {
        assert_eq!(
            decode_array(Scalar::Bool, &good[..cut]),
            Err(Refused::Undecodable),
            "cut at {cut}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        decode_array(Scalar::Bool, &trailing),
        Err(Refused::Undecodable)
    );
    // An item of the wrong width, and a length the bytes do not back.
    let wide = wire_array(&[Some(&[1, 1])]);
    assert_eq!(decode_array(Scalar::Bool, &wide), Err(Refused::Undecodable));
    let mut lying = wire_array(&[]);
    lying[12..16].copy_from_slice(&i32::MAX.to_be_bytes());
    assert_eq!(
        decode_array(Scalar::Bool, &lying),
        Err(Refused::Undecodable)
    );
    let mut nested = good;
    nested[0..4].copy_from_slice(&2i32.to_be_bytes());
    assert_eq!(
        decode_array(Scalar::Bool, &nested),
        Err(Refused::Undecodable)
    );
}

#[test]
fn an_array_stops_at_the_item_that_does_not_fit() {
    let items = vec![Some(&[1u8][..]); 8];
    let wire = wire_array(&items);
    let budget = ResultBudget::new(1);
    let mut weight = RowWeight::new(&budget);
    assert!(weight.charge(MAX_RESULT_BYTES - 3 * size_of::<Value>()));
    assert_eq!(
        array(Scalar::Bool, &wire, &mut weight),
        Err(Refused::OverBudget)
    );
}

#[test]
fn fixed_width_types_refuse_any_other_width() {
    let budget = ResultBudget::new(1);
    let mut weight = RowWeight::new(&budget);
    for scalar in [
        Scalar::Int4,
        Scalar::Oid,
        Scalar::Float8,
        Scalar::Uuid,
        Scalar::Date,
    ] {
        assert_eq!(
            scalar.decode(&[0; 3], &mut weight),
            Err(Refused::Undecodable)
        );
    }
    assert_eq!(
        Scalar::Oid.decode(&[0xff; 4], &mut weight),
        Ok(json!(u32::MAX))
    );
    assert_eq!(
        Scalar::Xid8.decode(&[0xff; 8], &mut weight),
        Ok(json!(u64::MAX))
    );
    assert_eq!(
        Scalar::Text.decode(&[0xff], &mut weight),
        Err(Refused::Undecodable)
    );
}
