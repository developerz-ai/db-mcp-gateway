# Pooler contract

What the gateway needs from a Postgres-protocol connection pooler or proxy (PgBouncer, pgcat, RDS Proxy, Supavisor, …) placed between it and a target database. It applies to `kind: postgres` targets (YugabyteDB included); Mongo and Redis targets connect directly.

You rarely need one: the gateway already pools per `(server, database)` — at most `pool.max_connections` (default 4) query connections plus 2 cancel connections per replica, doubled when `write_role` is set, opened lazily and closed after 5 idle minutes. A pooler earns its place when the database's own connection limit is shared with many other clients.

## How the gateway talks to Postgres

Every tool call that touches the database is one explicit transaction on one connection:

```sql
BEGIN;
SET TRANSACTION READ ONLY;            -- READ WRITE for a query_write call
SET LOCAL statement_timeout = <ms>;
SET LOCAL application_name = 'dbmcp-<request-id>-<nonce>';
SET LOCAL standard_conforming_strings = on;
SELECT pg_backend_pid();
<the statement>                       -- unnamed (unprepared) statement
COMMIT;                               -- ROLLBACK for dry_run / errors
```

When the connection goes back to the gateway's pool it runs one simple-query batch outside an explicit transaction: `RESET ALL; RESET SESSION AUTHORIZATION; RESET ROLE; DEALLOCATE ALL; DISCARD SEQUENCES; DISCARD TEMP; SET standard_conforming_strings = on; SELECT pg_advisory_unlock_all()`. On an agent disconnect, a result cut off at the row cap, or a `cancel_query`, a **separate** connection (same role) runs `SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE pid = $1 AND application_name = $2`.

## The contract

| # | Requirement | What breaks otherwise |
|---|---|---|
| 1 | **Session pooling, or transaction pooling with a server reset (rule 8).** *Statement* pooling does not work | Statement mode cannot run a multi-statement transaction: every call fails |
| 2 | **Named prepared statements across the transaction.** The driver (sqlx) prepares its own fixed statements by name and reuses them per connection. In transaction mode the pooler must track them: PgBouncer ≥ 1.21 with `max_prepared_statements` > 0, pgcat with prepared-statement support on | `prepared statement "sqlx_s_…" does not exist` errors, intermittently |
| 3 | **The configured role reaches Postgres.** Pass the client's user through (auth passthrough / `auth_query`), not one shared pooler user | Every query runs with the pooler user's privileges: the read-only role, and the read/write split, stop meaning anything |
| 4 | **One Postgres server per endpoint.** The cancel connection must reach the same server as the query connection | `pg_stat_activity` on another node does not see the backend: cancel-on-disconnect, `cancel_query` and `db_activity` silently find nothing. Statements still end at `statement_timeout` |
| 5 | **`SET LOCAL` and `application_name` pass through.** Poolers that rewrite or drop `application_name` defeat the cancel identity check | Same as 4: cancels and `db_activity` miss |
| 6 | **Client connection limits ≥ gateway pools × replicas.** Size the pooler's per-user client limit for `(max_connections + 2) × replicas`, ×2 with a write role | Pool acquire times out after 5 s → `unavailable` |
| 7 | **TLS on any leg that leaves a trusted network.** `tls: verify_full` to the pooler when it presents a certificate | Credentials and results in plaintext; boot warns per `tls: insecure` server |
| 8 | **In transaction mode, the pooler resets every server connection after every transaction**: `server_reset_query = DISCARD ALL` **and** `server_reset_query_always = 1` on PgBouncer, or the equivalent. Not needed in session mode, where the gateway's own reset reaches the backend the caller used | Session state one caller leaves — a session `set_config` (role included), `lastval()`, a temp table, a session advisory lock — stays on a backend the pooler then hands to the next client, the gateway's or anyone else's. The gateway's reset cannot prevent it (see below) |

## Pooling mode and session isolation

The gateway keeps two things apart, and a pooler's mode decides which of them still hold:

| | What it is | Session mode / no pooler | Transaction mode |
|---|---|---|---|
| **Transaction-local pins** | `READ ONLY`, `statement_timeout`, `application_name`, `standard_conforming_strings` — set with `SET TRANSACTION` / `SET LOCAL` inside each call's transaction | Hold | Hold: they travel with the transaction to whichever backend runs it |
| **Session cleanup** | The reset batch above, run when a connection returns to the gateway's pool | Holds: one gateway connection is one backend | **Does not hold** on its own: the backend went back to the pooler at `COMMIT`, so the batch may run on another backend and the one the caller used is handed out uncleaned |

The gateway itself relies on no session state across calls — no session `SET`, temp tables, `LISTEN` or advisory locks — so its own correctness is the same in both modes. What changes is what a *caller* can leave behind for the next one. In session mode the gateway guarantees nothing survives. In transaction mode that guarantee exists only if the pooler provides it (rule 8); without it, run the endpoint in session mode.

Two more things to know in transaction mode:
- **`DEALLOCATE ALL` and `DISCARD` arrive as a simple query.** A pooler that tracks protocol-level prepared statements (rule 2) keeps its own map of what is prepared on each server connection and does not necessarily notice SQL-level deallocation — older PgBouncer transaction mode in particular; newer releases recognise `DEALLOCATE ALL` / `DISCARD ALL`, but not reliably inside a multi-statement batch. Such a pooler can then believe a statement is still prepared on a server that dropped it, and a later call fails with `prepared statement "…" does not exist`. The gateway narrows the window — it closes its own named statements at the protocol level before the batch, so `DEALLOCATE ALL` normally finds nothing — but if you see that error behind a transaction-mode pooler, check the pooler's release notes for SQL-level `DEALLOCATE` support or switch that endpoint to session pooling.

## Sequences declared with `CACHE`

The reset batch's `DISCARD SEQUENCES` (and a pooler's `DISCARD ALL`) forgets `lastval()` / `currval()` so one caller cannot read a key another generated — and with them the values the backend preallocated for a sequence declared `CACHE n`. Each write-tier call that draws from such a sequence burns up to n − 1 values and goes back to the sequence on its next `nextval`. Expect larger gaps and faster consumption on those sequences (matters for `int4` keys with a large cache); `CACHE 1` sequences, reads, and writes that draw no value are unaffected. On YugabyteDB, where the default cache is 100 per session, use server-side sequence caching (`ysql_sequence_cache_method=server`) for sequences the `write_role` draws from.

## Memory

The byte cap (32 MiB of decoded result per call) is enforced by the gateway, row by row — but the driver buffers each **wire row whole** before the gateway sees it, and Postgres allows a single row of up to 1 GiB per field. A row past the cap is dropped without being decoded, yet it was already read into memory once. Rows of 1 MiB and more are decoded at most two at a time per database, and the buffer is released when the connection returns to the pool. Give the gateway container a memory limit sized for the largest row your targets can return (times the pool size, worst case), so one pathological row OOM-kills a replica that restarts rather than the node.

## Read replicas and load balancers

A load balancer over several Postgres nodes (read replicas, YugabyteDB tservers) violates rule 4. Point `host` at one node per configured server — declare several servers if you want to spread load — or accept that cancellation falls back to `statement_timeout`.

## Readiness

`/readyz` checks only the gateway's state DB. A pooler or target outage shows up as `unavailable` on tool calls and in `tool_calls{outcome="unavailable"}`, not as an unready pod.
