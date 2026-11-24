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

/// A weight with only `left` bytes of the result budget still unclaimed.
fn weight_with(budget: &ResultBudget, left: usize) -> RowWeight<'_> {
    let mut weight = RowWeight::new(budget);
    assert!(weight.charge(MAX_RESULT_BYTES - left));
    weight
}

#[test]
fn expanded_text_is_charged_before_it_is_built() {
    let budget = ResultBudget::new(1);
    // `\x` plus two hex digits a byte: 202 bytes rendered from 100 sent.
    let bytea = [0xab; 100];
    assert_eq!(
        Scalar::Bytea.decode(&bytea, &mut weight_with(&budget, 201)),
        Err(Refused::OverBudget)
    );
    assert!(
        Scalar::Bytea
            .decode(&bytea, &mut weight_with(&budget, 202))
            .is_ok()
    );

    let mut tsvector = 1u32.to_be_bytes().to_vec();
    tsvector.extend(b"''''\0");
    tsvector.extend(0u16.to_be_bytes());
    // `'` doubled four times, inside quotes: ten bytes rendered.
    assert_eq!(
        Scalar::TsVector.decode(&tsvector, &mut weight_with(&budget, 9)),
        Err(Refused::OverBudget)
    );
    assert_eq!(
        Scalar::TsVector.decode(&tsvector, &mut weight_with(&budget, 10)),
        Ok(json!("''''''''''"))
    );
}

#[test]
fn an_array_charges_its_items_text_and_storage() {
    let budget = ResultBudget::new(1);
    let item = [0xab; 100];
    let wire = wire_array(&[Some(&item[..]), Some(&item[..])]);
    let nodes = 2 * size_of::<Value>();
    assert_eq!(
        array(Scalar::Bytea, &wire, &mut weight_with(&budget, nodes + 202)),
        Err(Refused::OverBudget)
    );
    assert!(array(Scalar::Bytea, &wire, &mut weight_with(&budget, nodes + 404)).is_ok());
    // Every item's storage is claimed before any item is decoded.
    let bools = wire_array(&[Some(&[1u8][..]); 4]);
    assert_eq!(
        array(
            Scalar::Bool,
            &bools,
            &mut weight_with(&budget, 3 * size_of::<Value>())
        ),
        Err(Refused::OverBudget)
    );
}

#[test]
fn every_scalar_still_decodes_through_its_own_path() {
    let budget = ResultBudget::new(1);
    let mut weight = RowWeight::new(&budget);
    // numeric 1.5: one digit group before the point, one after.
    let numeric = [0, 2, 0, 0, 0, 0, 0, 1, 0, 1, 0x13, 0x88];
    assert_eq!(
        Scalar::Numeric.decode(&numeric, &mut weight),
        Ok(json!("1.5"))
    );
    assert_eq!(Scalar::Text.decode(b"hi", &mut weight), Ok(json!("hi")));
    assert_eq!(
        Scalar::Bytea.decode(&[0x0a], &mut weight),
        Ok(json!("\\x0a"))
    );
}
