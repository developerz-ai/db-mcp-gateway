-- OAuth-bridge login state, moved out of process memory so every replica sees
-- every login (spec 02 §HA): `/authorize` on one replica, the IdP callback on
-- another, the consent POST on a third and `/token` on a fourth all work, with
-- no sticky routing.
--
-- Every row is keyed by the SHA-256 of an opaque bearer value — the OIDC
-- `state`, the consent id, the authorization code — never the value itself,
-- so a dump of these tables replays nothing. The consent's CSRF token is
-- stored as a digest too. The gateway's IdP-side PKCE verifier and ID-token
-- nonce are not stored at all: they are re-derived from `state` under a key
-- derived from the session signing key (`auth::oauth::login_secrets`). The
-- client's PKCE `code_challenge` is stored: it is public by design.
--
-- Single-use is `DELETE ... RETURNING`: of two concurrent takes, one gets the
-- row. `expires_at` is set from the DB clock, so replicas with skewed clocks
-- agree on it; lookups filter on it and the auth GC deletes lapsed rows.
-- Additive only: release N-1 keeps its in-memory stores and never reads these.

CREATE TABLE oauth_pending_flows (
    state_hash BYTEA       PRIMARY KEY,
    -- `OAuthBridge` for an MCP `/authorize` login; NULL for `/auth/login`.
    bridge     JSONB,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_pending_flows_expires_at_idx ON oauth_pending_flows (expires_at);

CREATE TABLE oauth_pending_consents (
    consent_hash BYTEA       PRIMARY KEY,
    csrf_hash    BYTEA       NOT NULL,
    user_sub     TEXT        NOT NULL,
    email        TEXT        NOT NULL,
    groups       JSONB       NOT NULL,
    bridge       JSONB       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_pending_consents_expires_at_idx ON oauth_pending_consents (expires_at);

-- The per-subject consent cap evicts a subject's soonest-expiring consent.
CREATE INDEX oauth_pending_consents_user_sub_expires_at_idx
    ON oauth_pending_consents (user_sub, expires_at);

CREATE TABLE oauth_auth_codes (
    code_hash      BYTEA       PRIMARY KEY,
    user_sub       TEXT        NOT NULL,
    email          TEXT        NOT NULL,
    groups         JSONB       NOT NULL,
    code_challenge TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    client_id      TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_auth_codes_expires_at_idx ON oauth_auth_codes (expires_at);
