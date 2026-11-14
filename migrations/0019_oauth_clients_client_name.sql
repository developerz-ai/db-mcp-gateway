-- The RFC 7591 `client_name` a client asserts at `POST /register`, kept so the
-- consent page can show it (labelled unverified — the redirect host stays the
-- trusted line). Validated at /register: at most 100 characters, no control or
-- bidi-formatting characters.
--
-- Additive and nullable: release N-1 inserts without it (expand/contract, see
-- `state::migrate`) and its rows, like adopted clients, keep NULL.

ALTER TABLE oauth_clients
    ADD COLUMN client_name TEXT;
