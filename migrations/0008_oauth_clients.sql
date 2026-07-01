-- Dynamic-Client-Registration store for the MCP OAuth bridge (RFC 7591).
-- `POST /register` records a public client's redirect-URI allowlist here under a
-- generated `client_id`; `/authorize` later matches the requested `redirect_uri`
-- against this set exactly (OAuth 2.1 redirect allowlist / RFC 8252).
--
-- Moved out of process memory (was `ClientRegistry`'s in-memory HashMap) so a
-- pod restart / redeploy no longer drops every registration and wedges clients
-- that cache their `client_id` — they replayed a now-unknown id and got a hard
-- `invalid_client` instead of silently re-registering. Persisting here matches
-- how `sessions` already survive restarts, and is the "move flow state to the
-- shared state DB" step the single-replica note points at.
--
-- `expires_at` carries the TTL the old in-memory store enforced; lookups filter
-- on it and a periodic GC deletes lapsed rows, so an unauthenticated `/register`
-- flood self-heals rather than accumulating forever.

CREATE TABLE oauth_clients (
    client_id     TEXT        PRIMARY KEY,
    redirect_uris JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_clients_expires_after_create CHECK (expires_at > created_at)
);

-- GC deletes by `expires_at <= now()`; lookup filters `expires_at > now()`.
CREATE INDEX oauth_clients_expires_at_idx ON oauth_clients (expires_at);
