//! The row cap pushed to the server.

use super::*;

#[test]
fn find_limit_is_capped_but_a_smaller_one_kept() {
    let mut cmd = doc! { "find": "c", "limit": 1000 };
    cap_server_side(&mut cmd, "find", 10);
    assert_eq!(cmd.get_i64("limit").ok(), Some(11));
    assert_eq!(cmd.get_i64("batchSize").ok(), Some(11));

    let mut cmd = doc! { "find": "c", "limit": 3 };
    cap_server_side(&mut cmd, "find", 10);
    assert_eq!(cmd.get_i64("limit").ok(), Some(3));

    // `limit: 0` means "no limit" to mongo — never pass it through.
    let mut cmd = doc! { "find": "c", "limit": 0 };
    cap_server_side(&mut cmd, "find", 0);
    assert_eq!(cmd.get_i64("limit").ok(), Some(1));
}

#[test]
fn aggregate_gets_a_trailing_limit_stage() {
    let mut cmd = doc! { "aggregate": "c", "pipeline": [ { "$match": {} } ], "cursor": {} };
    cap_server_side(&mut cmd, "aggregate", 4);
    let pipeline = cmd.get_array("pipeline").expect("pipeline");
    assert_eq!(
        pipeline.last(),
        Some(&Bson::Document(doc! { "$limit": 5_i64 }))
    );
    assert_eq!(
        cmd.get_document("cursor")
            .expect("cursor")
            .get_i64("batchSize")
            .ok(),
        // One past the limit, so the first reply closes the cursor.
        Some(6)
    );
}
