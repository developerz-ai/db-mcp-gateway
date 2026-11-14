-- Refresh-token reuse detection (OAuth 2.1 §4.3.1, RFC 9700 §4.14.2).
--
-- Rotation deleted the old token's row, so a rotated-out token was
-- indistinguishable from an unknown one: a thief who rotated a stolen token
-- first kept the chain to its TTL while the legitimate client just got
-- `invalid_grant`. Now each chain carries a stable `chain_id`, and rotation
-- leaves a tombstone of the old hash; presenting a tombstoned hash revokes
-- the chain's live token and its paired session.
--
-- `chain_id` keeps its DEFAULT on purpose: release N-1 still inserts without
-- it (expand/contract, see `state::migrate`), and each such row starts its
-- own chain. The default also backfills existing rows, each of which is the
-- live tail of its own chain.

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN chain_id UUID NOT NULL DEFAULT gen_random_uuid();

-- Reuse revokes every live row of a chain by id.
CREATE INDEX oauth_refresh_tokens_chain_id_idx ON oauth_refresh_tokens (chain_id);

-- One row per rotated-out token hash, kept until the chain's absolute expiry
-- (after which the chain is dead anyway). Grows one row per rotation, the same
-- rate as `sessions`. Only the SHA-256 digest is stored, as in 0009.
-- `rotated_at` gives a just-rotated token a short grace: a client's own
-- concurrent refreshes are not treated as theft.
CREATE TABLE oauth_refresh_rotated (
    token_hash BYTEA       PRIMARY KEY,
    chain_id   UUID        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GC deletes by `expires_at <= now()`.
CREATE INDEX oauth_refresh_rotated_expires_at_idx ON oauth_refresh_rotated (expires_at);
