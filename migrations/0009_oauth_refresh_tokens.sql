-- Refresh-token chains for the MCP OAuth bridge (OAuth 2.1 §4.3.1 rotation).
--
-- Moved out of process memory (was `RefreshTokens`' in-memory HashMap) for the
-- same reason `oauth_clients` moved in migration 0008: a pod restart / redeploy
-- dropped every live chain, so every MCP client had to walk a full browser SSO
-- login again. That made the configured "stay signed in" window
-- (`REFRESH_TTL_DAYS`) a fiction — the real ceiling was "time until the next
-- rollout". With the chain here, a redeploy is invisible to a signed-in agent.
--
-- Only the SHA-256 digest of the token is stored (`token_hash`), never the raw
-- value: the DB dump of this table cannot be replayed as a live token. Same
-- at-rest posture the in-memory store already had.
--
-- `chain_issued_at` is the birth of the rotation *chain*, carried verbatim
-- across rotations so the absolute TTL is measured from the first mint and
-- rotation never slides the deadline. `expires_at` is that deadline
-- materialized (`chain_issued_at + REFRESH_TTL_DAYS`) so lookups and GC are a
-- plain indexed comparison. The identity columns are the IdP identity frozen at
-- the original browser login — the chain TTL is exactly the group-staleness
-- window they imply (see `DEFAULT_REFRESH_TTL`).

CREATE TABLE oauth_refresh_tokens (
    token_hash      BYTEA       PRIMARY KEY,
    user_sub        TEXT        NOT NULL,
    email           TEXT        NOT NULL,
    groups          JSONB       NOT NULL,
    chain_issued_at TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_refresh_tokens_expires_after_birth
        CHECK (expires_at > chain_issued_at)
);

-- GC deletes by `expires_at <= now()`; redemption rejects a lapsed chain.
CREATE INDEX oauth_refresh_tokens_expires_at_idx ON oauth_refresh_tokens (expires_at);

-- Logout purges every chain for an identity (`purge_for_sub`): a chain carries
-- no stable session id, so `user_sub` is the only handle spanning it.
CREATE INDEX oauth_refresh_tokens_user_sub_idx ON oauth_refresh_tokens (user_sub);
