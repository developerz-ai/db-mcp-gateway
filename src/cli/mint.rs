//! `mint-service-token <name>`: a fresh `dbmcp_svc_<64 hex>` token, the YAML
//! stanza to add, and the env var to store it under (spec 14). Run by an
//! operator, never by a serving gateway: there is deliberately no in-band
//! mint API. Rotation and revocation steps are in the printed text and in
//! website/docs/initial-idea/14-service-tokens.md.

use clap::Args;

use super::{CliError, EXIT_OK};

/// `auth::service_token::TOKEN_PREFIX` (crate-private there);
/// `tests/it_offline/cli_mint.rs` feeds a minted token to the real validator.
const TOKEN_PREFIX: &str = "dbmcp_svc_";

#[derive(Debug, Args)]
pub struct MintArgs {
    /// Service name: `^[a-z0-9][a-z0-9-]{0,62}$`. Becomes the audit identity
    /// `service:<name>`.
    pub name: String,
}

pub fn run(args: &MintArgs) -> Result<u8, CliError> {
    if !valid_name(&args.name) {
        return Err(CliError::Usage(
            "usage: db-mcp-gateway mint-service-token <name>\n  <name> must match \
             ^[a-z0-9][a-z0-9-]{0,62}$ — it becomes the audit identity service:<name>"
                .to_string(),
        ));
    }
    let token = mint_token()?;
    print!("{}", instructions(&args.name, &token));
    Ok(EXIT_OK)
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// 32 bytes from the OS CSPRNG, hex-encoded — the exact shape the boot
/// validator requires (`dbmcp_svc_` + 64 lowercase hex).
fn mint_token() -> Result<String, CliError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        CliError::io(
            "read the OS random source",
            std::io::Error::other(err.to_string()),
        )
    })?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{TOKEN_PREFIX}{hex}"))
}

/// `ci-bot` → `SERVICE_TOKEN_CI_BOT`.
fn env_var(name: &str) -> String {
    format!(
        "SERVICE_TOKEN_{}",
        name.to_ascii_uppercase().replace('-', "_")
    )
}

fn instructions(name: &str, token: &str) -> String {
    let env_var = env_var(name);
    format!(
        "token (store this — shown once): {token}

1. Put the value in the org secret store of record, then deliver it
   to the gateway pod as env var {env_var} (SealedSecret) — or as a mounted
   file and use ${{FILE:/run/secrets/...}} below instead.

2. Add to the gateway YAML (the group needs its own permissions: block):

service_accounts:
  - name: {name}
    group: svc-{name}
    token: ${{ENV:{env_var}}}

permissions:
  - group: svc-{name}
    grants: []   # fill in the minimal grants this service needs

3. Reload: kill -HUP every gateway pod, or roll the deployment (a value
   delivered as a new env var needs the roll; a mounted file does not).
   Revocation = remove the complete stanza (name + group + token ref) and
   reload again; emptying or unsetting the secret is NOT revocation
   (unresolved refs fail the reload or boot). Rotation needs an explicit
   overlap: mint fresh against a DISTINCT temporary name (e.g. <name>-next
   — the same <name> is rejected as a duplicate), add a SECOND stanza
   under that distinct name, reload, update clients, remove the OLD
   stanza, reload again.
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rule_matches_the_audit_identity_charset() {
        for ok in ["ci-bot", "a", "0x", &"a".repeat(63)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-ci", "CI", "ci_bot", "ci bot", &"a".repeat(64)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn token_has_the_boot_validated_shape_and_is_fresh() {
        let token = mint_token().unwrap();
        let hex = token.strip_prefix(TOKEN_PREFIX).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_ne!(token, mint_token().unwrap());
    }

    #[test]
    fn stanza_references_the_env_var_never_the_token() {
        let text = instructions("ci-bot", "dbmcp_svc_secret");
        let stanza = &text[text.find("service_accounts:").unwrap()..];
        assert!(stanza.contains("token: ${ENV:SERVICE_TOKEN_CI_BOT}"));
        assert!(!stanza.contains("dbmcp_svc_secret"));
    }
}
