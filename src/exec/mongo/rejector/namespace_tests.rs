use super::*;

/// Every collection an aggregation reads besides its own — `$lookup` /
/// `$graphLookup` `from`, `$unionWith` — at any depth, nested pipelines and
/// `$facet` branches included.
#[test]
fn secondary_namespaces() {
    let cases: &[(&str, &str, Result<(), RejectReason>)] = &[
        (
            "$lookup from system.profile denied",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":"system.profile","pipeline":[],"as":"p"}}],"cursor":{}}"#,
            Err(RejectReason::SystemCollection("aggregate".into())),
        ),
        (
            "$graphLookup from system.js denied",
            r#"{"aggregate":"users","pipeline":[{"$graphLookup":{"from":"system.js","startWith":"$a","connectFromField":"a","connectToField":"b","as":"g"}}],"cursor":{}}"#,
            Err(RejectReason::SystemCollection("aggregate".into())),
        ),
        (
            "$unionWith a system collection by name denied",
            r#"{"aggregate":"users","pipeline":[{"$unionWith":"system.views"}],"cursor":{}}"#,
            Err(RejectReason::SystemCollection("aggregate".into())),
        ),
        (
            "$unionWith coll nested in a $lookup pipeline denied",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":"orders","as":"o","pipeline":[{"$unionWith":{"coll":"system.profile","pipeline":[]}}]}}],"cursor":{}}"#,
            Err(RejectReason::SystemCollection("aggregate".into())),
        ),
        (
            "$lookup in a $facet branch denied",
            r#"{"aggregate":"users","pipeline":[{"$facet":{"a":[{"$lookup":{"from":"system.users","localField":"x","foreignField":"y","as":"z"}}]}}],"cursor":{}}"#,
            Err(RejectReason::SystemCollection("aggregate".into())),
        ),
        (
            "$lookup from another database denied",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":{"db":"admin","coll":"users"},"localField":"x","foreignField":"y","as":"z"}}],"cursor":{}}"#,
            Err(RejectReason::ForeignNamespace("$lookup")),
        ),
        (
            "$lookup with a non-string from denied",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":1,"as":"z","pipeline":[]}}],"cursor":{}}"#,
            Err(RejectReason::ForeignNamespace("$lookup")),
        ),
        (
            "$lookup, $graphLookup and $unionWith on app collections allowed",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":"orders","localField":"id","foreignField":"user_id","as":"o"}},{"$graphLookup":{"from":"users","startWith":"$boss","connectFromField":"boss","connectToField":"id","as":"chain"}},{"$unionWith":{"coll":"archive","pipeline":[{"$match":{}}]}},{"$unionWith":"more"}],"cursor":{}}"#,
            Ok(()),
        ),
        (
            "$documents-only $unionWith (no coll) allowed",
            r#"{"aggregate":1,"pipeline":[{"$unionWith":{"pipeline":[{"$documents":[{"a":1}]}]}}],"cursor":{}}"#,
            Ok(()),
        ),
    ];

    for (label, input, expected) in cases {
        let actual = validate_command(input);
        assert_eq!(
            actual.as_ref().map_err(|e| e.clone()),
            expected.as_ref().map_err(|e| e.clone()),
            "case {label:?}: input={input:?}, got {actual:?}",
        );
    }
}
