use super::*;

/// Table-driven coverage of the allow / deny matrix. One row = one
/// case; the assertion is the same shape for all so a future addition
/// (e.g. listCollections in #58) is one line.
fn field(command: &str, field: &str) -> RejectReason {
    RejectReason::DisallowedField {
        command: command.to_string(),
        field: field.to_string(),
    }
}

#[test]
fn rejector_matrix() {
    let cases: &[(&str, &str, Result<(), RejectReason>)] = &[
        // --- allowed reads -------------------------------------------------
        (
            "find allowed",
            r#"{"find":"users","filter":{"active":true},"limit":10}"#,
            Ok(()),
        ),
        (
            "aggregate allowed",
            r#"{"aggregate":"users","pipeline":[{"$match":{"active":true}},{"$group":{"_id":"$role","n":{"$sum":1}}}],"cursor":{}}"#,
            Ok(()),
        ),
        (
            "count allowed",
            r#"{"count":"users","query":{"active":true}}"#,
            Ok(()),
        ),
        (
            "distinct allowed",
            r#"{"distinct":"users","key":"role"}"#,
            Ok(()),
        ),
        // --- writes denied by command allow-list ---------------------------
        (
            "insert denied",
            r#"{"insert":"users","documents":[{"x":1}]}"#,
            Err(RejectReason::DisallowedCommand("insert".to_string())),
        ),
        (
            "update denied",
            r#"{"update":"users","updates":[{"q":{},"u":{"$set":{"x":1}}}]}"#,
            Err(RejectReason::DisallowedCommand("update".to_string())),
        ),
        (
            "delete denied",
            r#"{"delete":"users","deletes":[{"q":{},"limit":1}]}"#,
            Err(RejectReason::DisallowedCommand("delete".to_string())),
        ),
        (
            "findAndModify denied",
            r#"{"findAndModify":"users","query":{},"update":{"$set":{"x":1}}}"#,
            Err(RejectReason::DisallowedCommand("findAndModify".to_string())),
        ),
        (
            "bulkWrite denied",
            r#"{"bulkWrite":"users","ops":[]}"#,
            Err(RejectReason::DisallowedCommand("bulkWrite".to_string())),
        ),
        (
            "drop denied",
            r#"{"drop":"users"}"#,
            Err(RejectReason::DisallowedCommand("drop".to_string())),
        ),
        // --- operators denied at any depth ---------------------------------
        (
            "$out in pipeline denied",
            r#"{"aggregate":"users","pipeline":[{"$out":"snap"}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$out")),
        ),
        (
            "$merge in pipeline denied",
            r#"{"aggregate":"users","pipeline":[{"$merge":{"into":"snap"}}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$merge")),
        ),
        (
            "$function in projection denied",
            r#"{"aggregate":"users","pipeline":[{"$project":{"name":{"$function":{"body":"function(){return 1}","args":[],"lang":"js"}}}}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$function")),
        ),
        (
            "$where in find denied",
            r#"{"find":"users","filter":{"$where":"this.role == 'admin'"}}"#,
            Err(RejectReason::DisallowedOperator("$where")),
        ),
        (
            "$out deeply nested inside $facet denied",
            r#"{"aggregate":"users","pipeline":[{"$facet":{"snap":[{"$out":"target"}]}}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$out")),
        ),
        (
            "$where inside $lookup sub-pipeline denied",
            r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":"orders","let":{},"pipeline":[{"$match":{"$where":"true"}}],"as":"o"}}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$where")),
        ),
        (
            "$accumulator nested in $group denied",
            r#"{"aggregate":"users","pipeline":[{"$group":{"_id":null,"x":{"$accumulator":{"init":"function(){return 0}","accumulate":"function(s){return s}","accumulateArgs":[],"merge":"function(a,b){return a}","lang":"js"}}}}],"cursor":{}}"#,
            Err(RejectReason::DisallowedOperator("$accumulator")),
        ),
        // --- top-level fields outside the command's allow-list -------------
        (
            "$db re-targeting another database denied",
            r#"{"find":"users","filter":{},"$db":"admin"}"#,
            Err(field("find", "$db")),
        ),
        (
            "$readPreference denied",
            r#"{"count":"users","$readPreference":{"mode":"secondary"}}"#,
            Err(field("count", "$readPreference")),
        ),
        (
            "lsid denied",
            r#"{"find":"users","lsid":{"id":1}}"#,
            Err(field("find", "lsid")),
        ),
        (
            "txnNumber denied",
            r#"{"aggregate":"users","pipeline":[],"cursor":{},"txnNumber":1}"#,
            Err(field("aggregate", "txnNumber")),
        ),
        (
            "autocommit denied",
            r#"{"distinct":"users","key":"role","autocommit":false}"#,
            Err(field("distinct", "autocommit")),
        ),
        (
            "startTransaction denied",
            r#"{"find":"users","startTransaction":true}"#,
            Err(field("find", "startTransaction")),
        ),
        (
            "writeConcern denied",
            r#"{"aggregate":"users","pipeline":[],"cursor":{},"writeConcern":{"w":1}}"#,
            Err(field("aggregate", "writeConcern")),
        ),
        (
            "tailable cursor denied",
            r#"{"find":"users","tailable":true}"#,
            Err(field("find", "tailable")),
        ),
        (
            "find with every listed read option allowed",
            r#"{"find":"users","filter":{},"sort":{"a":1},"projection":{"a":1},"skip":1,"limit":5,"batchSize":5,"collation":{"locale":"en"}}"#,
            Ok(()),
        ),
        // --- malformed / empty inputs --------------------------------------
        (
            "non-JSON rejected",
            "definitely not JSON",
            Err(RejectReason::Malformed),
        ),
        (
            "JSON array rejected (not an object)",
            "[1,2,3]",
            Err(RejectReason::EmptyCommand),
        ),
        (
            "empty object rejected",
            "{}",
            Err(RejectReason::EmptyCommand),
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

/// `RejectReason::Display` carries only the operator-facing message —
/// never the command's *values* (which can include user PII / queries).
/// Audit logs get the structured reason; renderings get the safe text.
#[test]
fn display_never_leaks_command_values() {
    let secret_filter = r#"{"find":"users","filter":{"$where":"this.ssn == '123-45-6789'"}}"#;
    let err = validate_command(secret_filter).unwrap_err();
    let rendered = format!("{err}");
    assert!(rendered.contains("$where"));
    assert!(!rendered.contains("123-45-6789"), "leaked SSN: {rendered}");
    assert!(!rendered.contains("ssn"), "leaked field name: {rendered}");
}
