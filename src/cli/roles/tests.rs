use super::*;

fn args() -> RolesArgs {
    RolesArgs {
        config: ConfigArg {
            config: "unused.yaml".into(),
        },
        server: None,
        database: None,
        owner: "app_owner".into(),
        schemas: vec!["public".into()],
    }
}

fn rendered(yaml: &str) -> Vec<Result<String, CliError>> {
    let config = ConfigFile::from_yaml_str(yaml).unwrap();
    selected(&config, None, None)
        .into_iter()
        .map(|(server, db)| render(server, db, &args()))
        .collect()
}

const PG: &str = "servers:
  - name: prod
    kind: postgres
    host: db.internal
    databases:
      - { name: \"app\\nDROP DATABASE app;\", role: ro, password: x, write_role: rw, write_password: y }
permissions: []
";

#[test]
fn a_line_break_in_a_name_cannot_escape_a_comment_or_meta_command() {
    let err = rendered(PG).remove(0).unwrap_err();
    assert!(matches!(err, CliError::Invalid(_)), "{err}");
    let yaml = PG.replace("\\nDROP DATABASE app;", "");
    let yaml = yaml.replace("name: prod", "name: \"prod\\nDROP ROLE x;\"");
    let sql = rendered(&yaml).remove(0).unwrap();
    assert!(!sql.lines().any(|line| line.starts_with("DROP")), "{sql}");
    assert!(sql.starts_with("-- server `prod\\nDROP ROLE x;`"), "{sql}");
}

#[test]
fn every_database_local_grant_follows_a_connect_to_that_database() {
    let yaml = PG.replace("\\nDROP DATABASE app;", "");
    let sql = rendered(&yaml).remove(0).unwrap();
    let lines: Vec<&str> = sql.lines().collect();
    for (role, grant) in [("\"ro\"", "GRANT USAGE"), ("\"rw\"", "GRANT USAGE")] {
        let connect = lines
            .iter()
            .position(|l| l.starts_with("GRANT CONNECT") && l.ends_with(&format!("{role};")))
            .unwrap();
        assert_eq!(
            lines[connect + 1],
            r"\connect -reuse-previous=on 'dbname=''app'''",
            "{sql}"
        );
        let usage = lines
            .iter()
            .position(|l| l.starts_with(grant) && l.ends_with(&format!("{role};")))
            .unwrap();
        assert!(usage > connect + 1, "{sql}");
    }
}

#[test]
fn mongo_selects_its_database_as_data() {
    let yaml = "servers:
  - name: docs
    kind: mongo
    host: mongo.internal
    databases:
      - { name: \"app\\ndb.dropDatabase()\", role: ro, password: x }
permissions: []
";
    let script = rendered(yaml).remove(0).unwrap();
    assert!(
        !script.lines().any(|l| l.starts_with("db.dropDatabase")),
        "{script}"
    );
    assert!(
        script.contains("db = db.getSiblingDB(\"app\\ndb.dropDatabase()\")"),
        "{script}"
    );
}

#[test]
fn redis_acl_is_an_allowlist_without_key_enumeration() {
    let yaml = "servers:
  - name: cache
    kind: redis
    host: cache.internal
    databases:
      - { name: \"0\", role: gateway_ro, password: x }
permissions: []
";
    let acl = rendered(yaml).remove(0).unwrap();
    let setuser = acl.lines().find(|l| l.starts_with("ACL SETUSER")).unwrap();
    let rules: Vec<&str> = setuser.split(' ').collect();
    // An existing user's rules and selectors are cleared before the allowlist.
    assert_eq!(rules[3], "reset", "{acl}");
    assert!(rules.contains(&"-@all") && rules.contains(&"+get"), "{acl}");
    for denied in ["+scan", "+keys", "+dbsize", "+@read", "+@keyspace"] {
        assert!(!rules.contains(&denied), "{denied} in {acl}");
    }
}

/// These lines were run through psql 16 against a server without these
/// databases: each failed as `database "<the literal name>" does not exist`,
/// never as a connection-option parse (a bare `\connect "a=b"` fails with
/// `invalid connection option "a"`).
#[test]
fn a_database_name_never_reaches_psql_as_a_connection_string() {
    assert_eq!(
        psql_connect(r"a=b x\y'q"),
        "\\connect -reuse-previous=on 'dbname=''a=b x\\\\\\\\y\\\\''q'''\n"
    );
    assert_eq!(
        psql_connect("postgresql://h/x"),
        "\\connect -reuse-previous=on 'dbname=''postgresql://h/x'''\n"
    );
}

#[test]
fn identifiers_are_quoted_and_escaped() {
    assert_eq!(quote_ident("AppRo"), "\"AppRo\"");
    assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
}
