# 04 — Credential Handling & Audit Integrity

Scope: `src/config/{mod,schema,secret,yaml}.rs`, `src/audit/{mod,permissions,pruner}.rs`, `src/transport/errors.rs`, `src/auth/errors.rs`, `src/transport/admin/error.rs`, `src/state/mod.rs`, plus the consumer sites that render these errors. (Note: `src/errors.rs` does not exist — errors are per-layer.)

The top invariant — credentials never in any response/error/log — and synchronous, append-only audit are taken seriously and enforced. No unconditional credential leak or audit bypass found. One conditional boot-path leak needs a runtime check; the rest are defense-in-depth.

---

## C1 — Boot DB-connect error may surface the DSN (with inline password) via the anyhow chain — **Medium (needs runtime verification)**

**File:** `src/state/mod.rs:16-40`, `src/main.rs:31` + `:76` + `:100-109`

```rust
#[derive(Debug, thiserror::Error)]
pub enum StateDbError {
    #[error("failed to connect to state DB")]
    Connect(#[source] sqlx::Error),
```
```rust
// main.rs
let state_db = state::connect(&config.state_db.url, config.state_db.pool_size).await?;
```

`StateDbConfig` deliberately redacts `url` in `Debug` (`config/mod.rs:83-90`) because `state_db.url` is a full DSN that commonly carries an inline password (built-in default `postgres://gateway:gateway-dev-only@localhost:5433/gateway`, `mod.rs:25`). But on connect failure the raw `sqlx::Error` is kept as `#[source]` and `main` returns `anyhow::Result`; the runtime prints the error with `{:?}`, walking the full `source()` chain and rendering the sqlx error's `Display`. Same for `connect_permissions_mysql(&dsn, …)` where `dsn` is `PERMISSIONS_DB_DSN` (`main.rs:100-109`).

Whether it leaks depends on the failure mode: a Postgres *auth* failure yields a server message without the password, but a *URL/config parse* failure (`sqlx::Error::Configuration`) can echo the connection string. The redaction effort on `StateDbConfig::Debug` is defeated on this path.

**Verify:** feed a malformed `STATE_DB_URL` (e.g. password with a stray `%`, or a bad scheme) and inspect the stderr line `main` emits on exit. If the URL/password appears → confirmed Medium.

**Fix:** map `StateDbError::Connect` so it never carries the raw error to a chain-printing boundary — log the error *type name* only (the pattern already used at `admin/middleware.rs:118-122`) and return a generic anyhow message.

---

## C2 — Secret plaintext never zeroized — **Low**

**File:** `src/config/secret.rs:31`, `:149-151`

```rust
#[derive(Clone, PartialEq, Eq)]
pub enum Password { Literal(String), ... }
```
```rust
pub fn resolve(&self) -> Result<String, SecretError> {
    match self {
        Password::Literal(s) => Ok(s.clone()),   // plaintext cloned, dropped normally
```

`Password::Literal` holds plaintext for the process lifetime; `resolve()` returns a plain `String` moved into sqlx and dropped without scrubbing. No `zeroize` dependency exists. Residual plaintext in heap/freed memory (core dumps, swap, post-free reuse) is the remaining exposure given the project's stance.

**Fix:** wrap in `secrecy::SecretString` / `zeroize::Zeroizing<String>`; have `resolve()` return the wrapped type and expose `&str` only at the sqlx boundary.

---

## C3 — `pruner::run_once` has no internal floor on `ttl_days` — **Low**

**File:** `src/audit/pruner.rs:18-31`

```rust
pub async fn run_once(pool: &PgPool, ttl_days: u32) -> Result<u64, AuditError> {
    let result = sqlx::query(
        "DELETE FROM audit_calls WHERE occurred_at < now() - (interval '1 day' * $1::int)",
    )
    .bind(i32::try_from(ttl_days).unwrap_or(i32::MAX))
```

With `ttl_days == 0` the predicate becomes `occurred_at < now()` — deletes *every* audit row, a silent append-only/durability violation. Today this is prevented only upstream (`mod.rs:191-193` rejects `AUDIT_RETENTION_DAYS=0`). The `pub` pruner trusts its caller completely; a future YAML-sourced retention path (issue #16) that forgets the zero-check would wipe the log.

**Fix:** clamp inside `run_once`: `let days = ttl_days.max(1);`. Retention is the floor of correctness, not the ceiling. (The oversized path is already safe — `$1::int` clamps `u32 > i32::MAX` to ~5.8M years, i.e. deletes nothing. Retention is a bound parameter, not string-interpolated, so not injectable.)

---

## C4 — serde_yaml parse error text + location echoed to boot log — **Low**

**File:** `src/config/yaml.rs:79-110`

```rust
#[error("{path}{location}: {message}")]
Parse { path: PathBuf, location: String, message: String, #[source] source: serde_yaml::Error },
...
let message = source.to_string();
```

`message` is the verbatim serde_yaml error, rendered by `Display` and logged at boot. serde_yaml messages can echo an offending scalar (e.g. `invalid type: string "…", expected u16`). The `password` field accepts any `String` so a mismatch there is unlikely, but a literal password mis-pasted into an adjacent typed field (`port`, a numeric constraint) could be echoed; `location` (`:line:column`) points operators straight at the secret line.

**Fix:** drop `message` from the operator-facing `Display` (keep `path` + `location`), or scrub scalar values out of the serde message.

---

## Correct controls confirmed (no action)

- `Password` `Debug` hand-rolled, redacts `Literal` plaintext while keeping references printable; test-covered (`secret.rs:47-60`, `:246-270`).
- `SecretError::Malformed` carries **no payload**, so a typo'd ref can't echo a literal into a boot error (`secret.rs:80-85`); test-covered.
- Secret types are `Deserialize`-only — `grep Serialize src/config/` is empty; `Password`/`Server`/`Database`/`Config`/`StateDbConfig` cannot round-trip back out to a client.
- `StateDbConfig::Debug` redacts `url` (`config/mod.rs:83-90`).
- Client-facing surfaces never carry DB internals: `list_servers` returns `SafeServerView { name, kind, description }` only; `AuthError`/`AdminError` bodies use fixed category/code strings, never the source error; admin internal failures log `error_type` (type name), never `Display`/`Debug` of the sqlx error.
- `AuthError::State(#[from] sqlx::Error)` keeps the source via `#[source]` only; `#[error(...)]` strings are static, so `Display` doesn't surface DB internals.
- `audit::log` is synchronous, returns `Result`, single append-only `INSERT` with bound params; `serde_json::to_value(&groups).unwrap_or(...)` avoids a request-path panic (`audit/mod.rs:71-102`).
- `permissions::log` accepts `impl sqlx::Executor` (pool *or* transaction), enabling the atomic "audit + data change, roll back together" contract; append-only `INSERT` (`audit/permissions.rs:121-142`).
- No `UPDATE`/`DELETE` against `audit_calls` or `permissions_audit` anywhere except the pruner's single retention `DELETE`.
- Read helpers `latest_for_user_tool`/`latest_for_target` are `#[cfg(any(test, debug_assertions))]` and read-only (cosmetically mislabel read errors as `AuditError::Write` — harmless; note they compile into any debug build, not just tests).
- `auth_database`/`admin.group` empty-string boot rejection and role-name validation present (`yaml.rs:208-265`, `:314-332`).
