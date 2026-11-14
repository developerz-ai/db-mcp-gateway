//! Rejector contract: deny by default, case-insensitive, `*SCAN` `COUNT`
//! clamped, malformed argv told apart from policy refusals.

use super::*;
use crate::exec::redis::ScanItem;

fn args(command: &Command) -> Vec<&str> {
    command.args.iter().map(String::as_str).collect()
}

#[test]
fn writes_and_admin_commands_are_refused_before_anything_else() {
    for argv in [
        r#"["SET","k","v"]"#,
        r#"["DEL","k"]"#,
        r#"["FLUSHALL"]"#,
        r#"["KEYS","*"]"#,
        r#"["SORT","k"]"#,
        r#"["EVAL","return 1","0"]"#,
        r#"["FCALL","f","0"]"#,
        r#"["CONFIG","GET","*"]"#,
        r#"["CLIENT","LIST"]"#,
        r#"["SELECT","1"]"#,
        r#"["AUTH","u","p"]"#,
        r#"["MULTI"]"#,
        r#"["BLPOP","k","0"]"#,
        r#"["SUBSCRIBE","c"]"#,
        r#"["MONITOR"]"#,
        r#"["INFO"]"#,
        r#"["ZRANGESTORE","d","s","0","-1"]"#,
        r#"["JSON.GET","k"]"#,
        r#"["SORT_RO","k"]"#,
    ] {
        let err = validate_command(argv).expect_err(argv);
        assert!(
            matches!(err, RejectReason::DisallowedCommand(_)),
            "{argv}: {err:?}"
        );
        assert!(!err.is_malformed(), "{argv}");
    }
}

#[test]
fn the_refusal_names_the_command_as_sent_but_never_an_argument() {
    let err = validate_command(r#"["set","secret-key","secret-value"]"#).expect_err("SET");
    let message = err.to_string();
    assert!(message.contains("`set`"), "{message}");
    assert!(message.contains("read-only allowlist"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn an_oversized_command_name_is_cut_in_the_echo() {
    let name = "X".repeat(500);
    let err = validate_command(&format!(r#"["{name}"]"#)).expect_err("unknown");
    assert!(err.to_string().len() < 120, "{err}");
}

#[test]
fn allowed_reads_pass_in_any_case_and_are_sent_canonical() {
    for (argv, name) in [
        (r#"["get","k"]"#, "GET"),
        (r#"["HgetAll","user:1"]"#, "HGETALL"),
        (r#"["zrange","z","0","-1","withscores"]"#, "ZRANGE"),
        (r#"["XRANGE","s","-","+"]"#, "XRANGE"),
        (r#"["dbsize"]"#, "DBSIZE"),
    ] {
        let command = validate_command(argv).expect(argv);
        assert_eq!(command.name, name, "{argv}");
    }
}

#[test]
fn numbers_are_sent_as_their_decimal_text() {
    let command = validate_command(r#"["LRANGE","l",0,-1]"#).expect("LRANGE");
    assert_eq!(args(&command), ["l", "0", "-1"]);
}

#[test]
fn malformed_argv_is_told_apart_from_a_refusal() {
    for (argv, want) in [
        ("GET k", RejectReason::Malformed),
        (r#"{"GET":"k"}"#, RejectReason::Malformed),
        ("[]", RejectReason::EmptyCommand),
        (r#"["GET",null]"#, RejectReason::NonStringArgument(1)),
        (r#"["GET",["k"]]"#, RejectReason::NonStringArgument(1)),
        (r#"[true]"#, RejectReason::NonStringArgument(0)),
    ] {
        let err = validate_command(argv).expect_err(argv);
        assert_eq!(err, want, "{argv}");
        assert!(err.is_malformed(), "{argv}");
    }
}

#[test]
fn scan_count_is_injected_when_absent() {
    let command = validate_command(r#"["SCAN","0","MATCH","app:*"]"#).expect("SCAN");
    assert_eq!(args(&command), ["0", "MATCH", "app:*", "COUNT", "1000"]);
    let command = validate_command(r#"["SSCAN","s","0"]"#).expect("SSCAN");
    assert_eq!(args(&command), ["s", "0", "COUNT", "1000"]);
}

#[test]
fn scan_count_is_clamped_and_a_smaller_one_kept() {
    let command = validate_command(r#"["scan","0","count","999999"]"#).expect("SCAN");
    assert_eq!(args(&command), ["0", "count", "1000"]);
    let command = validate_command(r#"["HSCAN","h","0","COUNT",10]"#).expect("HSCAN");
    assert_eq!(args(&command), ["h", "0", "COUNT", "10"]);
}

/// Redis honours the last `COUNT`, so every one is clamped — a second
/// `COUNT` cannot smuggle a large page past the first.
#[test]
fn a_repeated_count_cannot_escape_the_clamp() {
    let argv = r#"["ZSCAN","z","0","COUNT","5","MATCH","COUNT","COUNT","50000"]"#;
    let command = validate_command(argv).expect("ZSCAN");
    assert_eq!(
        args(&command),
        ["z", "0", "COUNT", "5", "MATCH", "COUNT", "COUNT", "1000"]
    );
}

#[test]
fn scan_options_are_policed() {
    let refused = |argv: &str| validate_command(argv).expect_err(argv);
    assert!(matches!(
        refused(r#"["HSCAN","h","0","NOVALUES"]"#),
        RejectReason::DisallowedOption {
            command: "HSCAN",
            ..
        }
    ));
    // `TYPE` is a `SCAN` option only.
    assert!(validate_command(r#"["SCAN","0","TYPE","hash"]"#).is_ok());
    assert!(matches!(
        refused(r#"["SSCAN","s","0","TYPE","hash"]"#),
        RejectReason::DisallowedOption { .. }
    ));
    for argv in [
        r#"["SCAN"]"#,
        r#"["HSCAN","h"]"#,
        r#"["SCAN","0","MATCH"]"#,
        r#"["SCAN","0","COUNT","0"]"#,
        r#"["SCAN","0","COUNT","-5"]"#,
        r#"["SCAN","0","COUNT","lots"]"#,
    ] {
        assert!(refused(argv).is_malformed(), "{argv}");
    }
}

#[test]
fn the_shape_follows_the_command_and_its_flags() {
    let shape = |argv: &str| validate_command(argv).expect(argv).shape;
    assert_eq!(shape(r#"["GET","k"]"#), Shape::Value);
    assert_eq!(shape(r#"["HGETALL","h"]"#), Shape::FieldValue);
    assert_eq!(
        shape(r#"["HRANDFIELD","h","2","WITHVALUES"]"#),
        Shape::FieldValue
    );
    assert_eq!(shape(r#"["HRANDFIELD","h","2"]"#), Shape::Value);
    assert_eq!(
        shape(r#"["ZRANGE","z","0","-1","WithScores"]"#),
        Shape::MemberScore
    );
    assert_eq!(shape(r#"["ZRANGE","z","0","-1"]"#), Shape::Value);
    assert_eq!(
        shape(r#"["ZRANDMEMBER","z","3","WITHSCORES"]"#),
        Shape::MemberScore
    );
    assert_eq!(shape(r#"["SCAN","0"]"#), Shape::Scan(ScanItem::Key));
    assert_eq!(
        shape(r#"["HSCAN","h","0"]"#),
        Shape::Scan(ScanItem::FieldValue)
    );
    assert_eq!(
        shape(r#"["ZSCAN","z","0"]"#),
        Shape::Scan(ScanItem::MemberScore)
    );
    assert_eq!(shape(r#"["XREVRANGE","s","+","-"]"#), Shape::Stream);
    // A key literally named WITHSCORES is a key, not the flag.
    assert_eq!(shape(r#"["ZRANGE","WITHSCORES","0","-1"]"#), Shape::Value);
}

#[test]
fn a_random_count_must_be_an_integer() {
    for argv in [
        r#"["SRANDMEMBER","s","lots"]"#,
        r#"["HRANDFIELD","h","1.5","WITHVALUES"]"#,
        r#"["ZRANDMEMBER","z","-"]"#,
    ] {
        let err = validate_command(argv).expect_err(argv);
        assert!(
            matches!(err, RejectReason::NonIntegerCount(_)),
            "{argv}: {err:?}"
        );
        assert!(err.is_malformed(), "{argv}");
    }
    assert!(validate_command(r#"["SRANDMEMBER","s","-2000000000"]"#).is_ok());
    assert!(validate_command(r#"["SRANDMEMBER","s"]"#).is_ok());
}
