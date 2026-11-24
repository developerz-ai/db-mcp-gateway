//! Operator options for the login path, read from env and validated at boot:
//! what the gateway asks the IdP for, how it reads the groups claim, how old
//! a login's groups may get, and who a refused user is told to contact.

use std::env::VarError;
use std::time::Duration;

const DEFAULT_SCOPES: &str = "openid email profile groups";
/// Bounds on `GROUPS_MAX_AGE`: below a minute every refresh would force a
/// browser login; the ceiling is the longest refresh chain (`REFRESH_TTL_DAYS`).
const GROUPS_MAX_AGE_MIN: Duration = Duration::from_secs(60);
const GROUPS_MAX_AGE_MAX: Duration = Duration::from_secs(366 * 24 * 3600);
const SUPPORT_CONTACT_MAX_CHARS: usize = 200;
const GROUPS_PREFIX_MAX_CHARS: usize = 128;
/// Every variable [`LoginOptions::from_lookup`] reads.
const LOGIN_OPTION_VARS: [&str; 5] = [
    "OIDC_SCOPES",
    "OIDC_GROUPS_PREFIX",
    "OIDC_TOKEN_AUTH_METHOD",
    "GROUPS_MAX_AGE",
    "GATEWAY_SUPPORT_CONTACT",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginOptions {
    /// `OIDC_SCOPES`: the scopes requested at the IdP's authorization endpoint.
    pub scopes: Scopes,
    /// `OIDC_GROUPS_PREFIX`: only groups starting with this count, and they
    /// are matched against `permissions[].group` with it removed.
    pub groups_prefix: Option<GroupsPrefix>,
    /// `OIDC_TOKEN_AUTH_METHOD`: where the client secret goes at the IdP's
    /// token endpoint.
    pub token_auth_method: TokenAuthMethod,
    /// `GROUPS_MAX_AGE`: the longest a session may run on the groups read at
    /// its login. `None` leaves the refresh-chain TTL as the only bound.
    pub groups_max_age: Option<Duration>,
    /// `GATEWAY_SUPPORT_CONTACT`: shown on the login error pages.
    pub support_contact: Option<SupportContact>,
}

/// Space-separated OAuth scope tokens that include `openid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scopes(String);

impl Scopes {
    pub fn parse(raw: &str) -> Result<Self, LoginOptionsError> {
        let tokens: Vec<&str> = raw.split_ascii_whitespace().collect();
        let well_formed = tokens.iter().all(|token| token.bytes().all(is_scope_byte));
        if !well_formed || !tokens.contains(&"openid") {
            return Err(LoginOptionsError::Scopes);
        }
        Ok(Self(tokens.join(" ")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Scopes {
    fn default() -> Self {
        Self(DEFAULT_SCOPES.to_owned())
    }
}

/// RFC 6749 §3.3 `scope-token` characters.
fn is_scope_byte(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}

/// A non-empty group-name prefix without whitespace or control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupsPrefix(String);

impl GroupsPrefix {
    pub fn parse(raw: &str) -> Result<Self, LoginOptionsError> {
        let acceptable = !raw.is_empty()
            && raw.chars().count() <= GROUPS_PREFIX_MAX_CHARS
            && !raw.chars().any(|c| c.is_whitespace() || c.is_control());
        if !acceptable {
            return Err(LoginOptionsError::GroupsPrefix);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenAuthMethod {
    /// Client id and secret in the form body.
    #[default]
    ClientSecretPost,
    /// Client id and secret in an HTTP Basic `Authorization` header.
    ClientSecretBasic,
}

impl TokenAuthMethod {
    fn parse(raw: &str) -> Result<Self, LoginOptionsError> {
        match raw {
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            _ => Err(LoginOptionsError::TokenAuthMethod),
        }
    }
}

/// One line of operator-written text: an address, a channel, a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportContact(String);

impl SupportContact {
    pub fn parse(raw: &str) -> Result<Self, LoginOptionsError> {
        let contact = raw.trim();
        let acceptable = !contact.is_empty()
            && contact.chars().count() <= SUPPORT_CONTACT_MAX_CHARS
            && !contact.chars().any(char::is_control);
        if !acceptable {
            return Err(LoginOptionsError::SupportContact);
        }
        Ok(Self(contact.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A boot-time refusal. Names the variable, never its value: none of these
/// are secrets, but the message lands in the boot log either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoginOptionsError {
    #[error("invalid OIDC_SCOPES: expected space-separated scope tokens that include `openid`")]
    Scopes,
    #[error(
        "invalid OIDC_GROUPS_PREFIX: expected at most 128 characters with no whitespace or \
         control characters"
    )]
    GroupsPrefix,
    #[error(
        "invalid OIDC_TOKEN_AUTH_METHOD: expected `client_secret_post` or `client_secret_basic`"
    )]
    TokenAuthMethod,
    #[error(
        "invalid GROUPS_MAX_AGE: expected a whole number with a unit (`s`, `m`, `h` or `d`, \
         e.g. `12h`) between 1m and 366d"
    )]
    GroupsMaxAge,
    #[error(
        "invalid GATEWAY_SUPPORT_CONTACT: expected one line of at most 200 characters with no \
         control characters"
    )]
    SupportContact,
    /// Read as unset it would drop the operator's setting to its default.
    #[error("invalid {0}: the value is not valid UTF-8")]
    NotUnicode(&'static str),
}

impl LoginOptions {
    pub fn from_env() -> Result<Self, LoginOptionsError> {
        let mut values = Vec::with_capacity(LOGIN_OPTION_VARS.len());
        for var in LOGIN_OPTION_VARS {
            if let Some(value) = env_value(var, std::env::var(var))? {
                values.push((var, value));
            }
        }
        Self::from_lookup(|var| {
            values
                .iter()
                .find(|(name, _)| *name == var)
                .map(|(_, value)| value.clone())
        })
    }

    /// [`Self::from_env`] over any variable source. An unset variable keeps
    /// its default. So does an empty `OIDC_GROUPS_PREFIX` or
    /// `GATEWAY_SUPPORT_CONTACT` (compose expands an unset `${VAR}` to `""`,
    /// and empty means the same as absent for both); an empty value for any
    /// other variable is refused, because defaulting it would loosen what
    /// the operator asked for.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, LoginOptionsError> {
        let non_empty = |var: &str| lookup(var).filter(|value| !value.is_empty());
        Ok(Self {
            scopes: lookup("OIDC_SCOPES")
                .map(|raw| Scopes::parse(&raw))
                .transpose()?
                .unwrap_or_default(),
            groups_prefix: non_empty("OIDC_GROUPS_PREFIX")
                .map(|raw| GroupsPrefix::parse(&raw))
                .transpose()?,
            token_auth_method: lookup("OIDC_TOKEN_AUTH_METHOD")
                .map(|raw| TokenAuthMethod::parse(&raw))
                .transpose()?
                .unwrap_or_default(),
            groups_max_age: lookup("GROUPS_MAX_AGE")
                .map(|raw| parse_groups_max_age(&raw))
                .transpose()?,
            support_contact: non_empty("GATEWAY_SUPPORT_CONTACT")
                .map(|raw| SupportContact::parse(&raw))
                .transpose()?,
        })
    }
}

/// An unset variable is `None`; one set to bytes that are not UTF-8 is an
/// error, never `None` — that would boot without the operator's setting.
fn env_value(
    var: &'static str,
    raw: Result<String, VarError>,
) -> Result<Option<String>, LoginOptionsError> {
    match raw {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(LoginOptionsError::NotUnicode(var)),
    }
}

fn parse_groups_max_age(raw: &str) -> Result<Duration, LoginOptionsError> {
    let unit_secs = match raw.as_bytes().last() {
        Some(b's') => 1,
        Some(b'm') => 60,
        Some(b'h') => 3600,
        Some(b'd') => 24 * 3600,
        _ => return Err(LoginOptionsError::GroupsMaxAge),
    };
    let digits = &raw[..raw.len() - 1];
    // `u64::from_str` accepts a leading `+`; a duration is digits only.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LoginOptionsError::GroupsMaxAge);
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|count| count.checked_mul(unit_secs))
        .map(Duration::from_secs)
        .filter(|age| (GROUPS_MAX_AGE_MIN..=GROUPS_MAX_AGE_MAX).contains(age))
        .ok_or(LoginOptionsError::GroupsMaxAge)
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
