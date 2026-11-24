-- Optional expiry on a DB grant (plan 101 O10). Additive: a nullable column,
-- NULL for every existing row, which keeps them non-expiring. The evaluator
-- ignores a grant once `now() >= expires_at`; the row stays live (not
-- revoked) so the admin API can still list it, flagged `expired`.
ALTER TABLE permissions_grants
    ADD COLUMN expires_at TIMESTAMPTZ;
