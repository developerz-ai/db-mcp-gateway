-- Sessions issued by the gateway after a successful OIDC login.
-- `revoked_at IS NOT NULL` is the denylist (spec: docs/initial-idea/04-auth-sso.md).
-- Every authenticated request checks this row; keep it lean and well indexed.

CREATE TABLE sessions (
    id           UUID        PRIMARY KEY,
    user_sub     TEXT        NOT NULL,
    user_email   TEXT        NOT NULL,
    groups       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    agent_client TEXT,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,

    CONSTRAINT sessions_expires_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX sessions_user_sub_idx    ON sessions (user_sub);
CREATE INDEX sessions_expires_at_idx  ON sessions (expires_at);
