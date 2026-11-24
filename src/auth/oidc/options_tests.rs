use super::*;

fn options(vars: &[(&str, &str)]) -> Result<LoginOptions, LoginOptionsError> {
    LoginOptions::from_lookup(|var| {
        vars.iter()
            .find(|(name, _)| *name == var)
            .map(|(_, value)| (*value).to_owned())
    })
}

#[test]
fn nothing_set_keeps_todays_behaviour() {
    let options = options(&[]).expect("defaults are valid");
    assert_eq!(options.scopes.as_str(), "openid email profile groups");
    assert_eq!(options.groups_prefix, None);
    assert_eq!(options.token_auth_method, TokenAuthMethod::ClientSecretPost);
    assert_eq!(options.groups_max_age, None);
    assert_eq!(options.support_contact, None);
    assert_eq!(options, LoginOptions::default());
}

#[test]
fn scopes_are_normalised_and_must_include_openid() {
    let parsed = options(&[("OIDC_SCOPES", "  openid   email profile ")]).expect("valid");
    assert_eq!(parsed.scopes.as_str(), "openid email profile");
    for bad in [
        "",
        "   ",
        "email profile",
        "openid em\"ail",
        "openid a\\b",
        "openid é",
    ] {
        assert_eq!(
            options(&[("OIDC_SCOPES", bad)]),
            Err(LoginOptionsError::Scopes),
            "{bad:?}"
        );
    }
}

#[test]
fn token_auth_method_is_one_of_two() {
    let basic = options(&[("OIDC_TOKEN_AUTH_METHOD", "client_secret_basic")]).expect("valid");
    assert_eq!(basic.token_auth_method, TokenAuthMethod::ClientSecretBasic);
    let post = options(&[("OIDC_TOKEN_AUTH_METHOD", "client_secret_post")]).expect("valid");
    assert_eq!(post.token_auth_method, TokenAuthMethod::ClientSecretPost);
    for bad in [
        "",
        "basic",
        "CLIENT_SECRET_BASIC",
        "private_key_jwt",
        "none",
    ] {
        assert_eq!(
            options(&[("OIDC_TOKEN_AUTH_METHOD", bad)]),
            Err(LoginOptionsError::TokenAuthMethod),
            "{bad:?}"
        );
    }
}

#[test]
fn groups_max_age_takes_a_unit_and_is_bounded() {
    for (raw, secs) in [
        ("60s", 60),
        ("1m", 60),
        ("90m", 5400),
        ("12h", 43_200),
        ("7d", 604_800),
        ("366d", 366 * 86_400),
    ] {
        let parsed = options(&[("GROUPS_MAX_AGE", raw)]).expect(raw);
        assert_eq!(
            parsed.groups_max_age,
            Some(Duration::from_secs(secs)),
            "{raw}"
        );
    }
    for bad in [
        "",
        "12",
        "h",
        "12 h",
        "+12h",
        "-1h",
        "1.5h",
        "12H",
        "59s",
        "0h",
        "367d",
        "99999999999999999999d",
        "12hé",
    ] {
        assert_eq!(
            options(&[("GROUPS_MAX_AGE", bad)]),
            Err(LoginOptionsError::GroupsMaxAge),
            "{bad:?}"
        );
    }
}

#[test]
fn groups_prefix_is_kept_verbatim_or_refused() {
    let parsed = options(&[("OIDC_GROUPS_PREFIX", "dbmcp-")]).expect("valid");
    assert_eq!(
        parsed.groups_prefix.as_ref().map(GroupsPrefix::as_str),
        Some("dbmcp-")
    );
    assert_eq!(
        options(&[("OIDC_GROUPS_PREFIX", "")])
            .expect("empty is unset")
            .groups_prefix,
        None
    );
    for bad in ["db mcp", " dbmcp-", "db\tmcp", &"x".repeat(129)] {
        assert_eq!(
            options(&[("OIDC_GROUPS_PREFIX", bad)]),
            Err(LoginOptionsError::GroupsPrefix),
            "{bad:?}"
        );
    }
}

#[test]
fn support_contact_is_one_trimmed_line() {
    let parsed = options(&[("GATEWAY_SUPPORT_CONTACT", "  #data-platform on Slack ")]);
    assert_eq!(
        parsed
            .expect("valid")
            .support_contact
            .as_ref()
            .map(SupportContact::as_str),
        Some("#data-platform on Slack")
    );
    assert_eq!(
        options(&[("GATEWAY_SUPPORT_CONTACT", "")])
            .expect("empty is unset")
            .support_contact,
        None
    );
    for bad in ["   ", "line one\nline two", &"x".repeat(201)] {
        assert_eq!(
            options(&[("GATEWAY_SUPPORT_CONTACT", bad)]),
            Err(LoginOptionsError::SupportContact),
            "{bad:?}"
        );
    }
}

#[test]
fn errors_name_the_variable() {
    for (error, var) in [
        (LoginOptionsError::Scopes, "OIDC_SCOPES"),
        (LoginOptionsError::GroupsPrefix, "OIDC_GROUPS_PREFIX"),
        (LoginOptionsError::TokenAuthMethod, "OIDC_TOKEN_AUTH_METHOD"),
        (LoginOptionsError::GroupsMaxAge, "GROUPS_MAX_AGE"),
        (LoginOptionsError::SupportContact, "GATEWAY_SUPPORT_CONTACT"),
    ] {
        assert!(error.to_string().contains(var), "{error}");
    }
}

#[test]
fn a_non_unicode_value_is_refused_not_read_as_unset() {
    let unreadable = || Err(std::env::VarError::NotUnicode("\u{FFFD}".into()));
    for var in LOGIN_OPTION_VARS {
        assert_eq!(
            env_value(var, unreadable()),
            Err(LoginOptionsError::NotUnicode(var)),
            "{var}"
        );
        assert_eq!(
            env_value(var, Err(std::env::VarError::NotPresent)),
            Ok(None)
        );
    }
    assert!(LOGIN_OPTION_VARS.contains(&"GROUPS_MAX_AGE"));
    let shown = LoginOptionsError::NotUnicode("GROUPS_MAX_AGE").to_string();
    assert!(shown.contains("GROUPS_MAX_AGE"), "{shown}");
}
