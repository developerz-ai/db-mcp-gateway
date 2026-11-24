//! Parse + boot-validation tests for the plan-101 O13 config shapes, each
//! through the production entry point (`ConfigFile::from_yaml_str`).

use crate::auth::{Identity, IdentityKind, SessionId};
use crate::authz::{Decision, evaluate};
use crate::config::schema::Subject;
use crate::config::{Action, ConfigFile};

fn parse(yaml: &str) -> Result<ConfigFile, String> {
    ConfigFile::from_yaml_str(yaml).map_err(|e| e.to_string())
}

fn err(yaml: &str) -> String {
    match parse(yaml) {
        Ok(_) => panic!("expected a boot error for:\n{yaml}"),
        Err(e) => e,
    }
}

const SERVER: &str = "servers:\n  - name: s\n    kind: postgres\n    host: h\n";

fn with_dbs(dbs: &str, permissions: &str) -> String {
    format!("{SERVER}    role: gw_ro\n    password: pw\n    databases: {dbs}\n{permissions}")
}

fn sso(sub: &str, groups: &[&str]) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: "u@example.com".to_string(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    }
}

#[test]
fn connect_name_overrides_the_connected_database_only() {
    let config = parse(&with_dbs(
        "[{ name: app, connect_name: app_prod_v2 }, { name: other }]",
        "",
    ))
    .unwrap();
    let dbs = &config.servers[0].databases;
    assert_eq!(dbs[0].name, "app");
    assert_eq!(dbs[0].connect_name(), "app_prod_v2");
    assert_eq!(dbs[1].connect_name(), "other", "absent → logical name");
    assert!(err(&with_dbs("[{ name: app, connect_name: ' ' }]", "")).contains("connect_name"));
    let redis = "servers:\n  - { name: r, kind: redis, host: h, role: redis_ro, password: pw, \
                 databases: [{ name: '0', connect_name: x }] }\n";
    assert!(err(redis).contains("connect_name"));
}

#[test]
fn databases_inherit_server_role_and_password_and_their_own_win() {
    let config = parse(&with_dbs("[{ name: app }, { name: bi, role: bi_ro }]", "")).unwrap();
    let dbs = &config.servers[0].databases;
    assert_eq!(dbs[0].role, "gw_ro");
    assert_eq!(dbs[1].role, "bi_ro");
    let no_default = format!("{SERVER}    databases: [{{ name: app, password: pw }}]\n");
    let message = err(&no_default);
    assert!(message.contains("has no `role`"), "{message}");
}

#[test]
fn database_list_shorthand_names_take_server_defaults() {
    let config = parse(&with_dbs("[app, { name: billing, role: billing_ro }]", "")).unwrap();
    let names: Vec<_> = config.servers[0]
        .databases
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    assert_eq!(names, ["app", "billing"]);
    assert_eq!(config.servers[0].databases[0].role, "gw_ro");
    let redis = "servers:\n  - { name: r, kind: redis, host: h, role: redis_ro, password: pw, \
                 databases: [0, 1] }\n";
    let config = parse(redis).unwrap();
    assert_eq!(config.servers[0].databases[1].name, "1");
    let bare = format!("{SERVER}    databases: [app]\n");
    assert!(err(&bare).contains("has no `role`"));
    assert!(
        err(&with_dbs("[{ name: app, rol: x }]", "")).contains("rol"),
        "a mapping keeps its unknown-key error"
    );
}

#[test]
fn constraint_profiles_fold_into_grants_most_restrictive() {
    let yaml = with_dbs(
        "[app]",
        "constraint_profiles:\n  strict: { row_limit: 100, require_reason: true }\n\
         permissions:\n  - group: g\n    grants:\n      - { server: s, database: app, \
         action: query_read, profile: strict, constraints: { row_limit: 500 } }\n",
    );
    let config = parse(&yaml).unwrap();
    let grant = &config.permissions[0].grants[0];
    assert_eq!(grant.profile.as_deref(), Some("strict"));
    assert_eq!(grant.constraints.row_limit, Some(100));
    assert!(grant.constraints.require_reason);
    let unknown = with_dbs(
        "[app]",
        "permissions:\n  - group: g\n    grants:\n      - { server: s, database: app, \
         action: query_read, profile: nope }\n",
    );
    assert!(err(&unknown).contains("unknown constraint profile `nope`"));
}

#[test]
fn except_narrows_a_wildcard_and_is_boot_checked() {
    let grant = |db: &str, except: &str| {
        with_dbs(
            "[app, secrets]",
            &format!(
                "permissions:\n  - group: g\n    grants:\n      - {{ server: s, database: '{db}', \
                 action: query_read, except: [{except}] }}\n"
            ),
        )
    };
    let config = parse(&grant("*", "secrets")).unwrap();
    let id = sso("u", &["g"]);
    let allowed = |db| evaluate(&id, Action::QueryRead, "s", db, &config.permissions);
    assert!(matches!(allowed("app"), Decision::Allow { .. }));
    assert_eq!(allowed("secrets"), Decision::Deny);
    assert!(err(&grant("app", "secrets")).contains("only applies"));
    assert!(err(&grant("*", "typo")).contains("unknown database `typo`"));
}

#[test]
fn user_subjects_parse_trim_and_reject_duplicates_and_blanks() {
    let block = |subjects: &str| with_dbs("[app]", &format!("permissions:\n{subjects}"));
    let grants = "    grants: [{ server: s, database: app, action: query_read }]\n";
    let config = parse(&block(&format!("  - user: ' sub-1 '\n{grants}"))).unwrap();
    assert_eq!(config.permissions[0].subject, Subject::User("sub-1".into()));
    let allowed = evaluate(
        &sso("sub-1", &[]),
        Action::QueryRead,
        "s",
        "app",
        &config.permissions,
    );
    assert!(matches!(allowed, Decision::Allow { .. }));
    let twice = format!("  - user: a\n{grants}  - user: a\n{grants}");
    assert!(err(&block(&twice)).contains("duplicate permission user `a`"));
    assert!(err(&block(&format!("  - user: ' '\n{grants}"))).contains("non-empty"));
    let both = format!("  - group: g\n    user: a\n{grants}");
    assert!(err(&block(&both)).contains("exactly one of `group:` or `user:`"));
    // A service account must name a *group* block; a same-named user block
    // is not one.
    let svc = format!(
        "{}service_accounts:\n  - {{ name: bot, group: a, token: dbmcp_svc_x }}\n",
        block(&format!("  - user: a\n{grants}"))
    );
    assert!(err(&svc).contains("has no `permissions:`"));
}
