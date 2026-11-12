-- Pair each refresh token with the access session minted alongside it.
--
-- Without this link a refresh rotation minted a new session but left the
-- previous one live until its own expiry, and `/revoke` on a refresh token
-- ended the chain while the paired bearer kept working. With it, rotation and
-- `/revoke` revoke exactly the paired session (spec 04 §Logout and revocation).
--
-- Nullable: rows written before this migration carry no pairing. `ON DELETE SET
-- NULL` because session GC deletes expired session rows while the refresh
-- chain (default 24 h, up to `REFRESH_TTL_DAYS`) outlives the 8 h session.

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN session_id UUID REFERENCES sessions (id) ON DELETE SET NULL;

-- Session GC deletes from `sessions`; the FK action scans this column.
CREATE INDEX oauth_refresh_tokens_session_id_idx ON oauth_refresh_tokens (session_id);
