-- Store parity with `migrations/0023_grant_expires_at.sql`: an optional,
-- nullable expiry on a grant. NULL (every existing row) never expires.
ALTER TABLE permissions_grants
    ADD COLUMN expires_at TIMESTAMP(6) NULL;
