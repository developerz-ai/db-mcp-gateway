# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in db-mcp-gateway, please report it **privately** rather than opening a public GitHub issue.

### How to report

Email **security@developerz.ai** with:
- A description of the vulnerability
- Steps to reproduce (if applicable)
- The affected version(s)
- Any proof-of-concept code (if safe to share)

### What to expect

- **Acknowledgment:** We will acknowledge receipt within 48 hours.
- **Assessment:** We will assess severity and begin work on a fix (typically within 2 weeks for critical issues).
- **Coordinated disclosure:** We will discuss a disclosure timeline with you (typically 90 days from fix, or earlier if the vulnerability is already publicly known).
- **Credit:** If you wish, we will credit you in the security advisory and release notes.

### Scope

We consider the following in scope:

- **Authentication/Authorization bypass** — SSO integration, permission evaluation, session handling.
- **Credential leakage** — Database credentials, tokens, or secrets exposed in logs, errors, responses, or memory.
- **SQL injection or execution bypass** — Unsanitized SQL, parse-tree bypasses, or logic flaws in statement guards.
- **Audit log bypass** — Unauthorized queries that evade audit logging.
- **Denial of service** — Resource exhaustion, unbound allocations, or lack of rate limiting that impacts availability.
- **Cryptographic failures** — Weak key derivation, insecure randomness, or improper use of crypto primitives.

Out of scope:

- Configuration errors by deployment teams (e.g., overly permissive OIDC settings).
- Social engineering or phishing.
- Vulnerabilities in dependencies (please report to the maintainers of those projects).
- Performance issues that do not impact security or availability.

---

## Supported Versions

Security fixes ship in a new release on top of the **latest** `2.x` version, as a new image tag
(`ghcr.io/developerz-ai/db-mcp-gateway:<version>`; the moving `2` and `latest` tags follow it).
There is no long-term support line: to pick up a fix, upgrade to the newest `2.x` release. Moving
from `1.x` is covered by
[`website/docs/deployment/upgrading-to-2.md`](website/docs/deployment/upgrading-to-2.md).

| Version | Supported |
|---|---|
| Latest `2.x` release | ✅ |
| Older `2.x` releases | Fixed by upgrading to the latest `2.x` |
| `1.x` and older | ❌ Upgrade to `2.x` |

A fix for an advisory a first-tier source confirms (CISA KEV, NVD, GitHub Security Advisories, or
the affected vendor) is released within a day of merging (a daily check), without waiting for the weekly release
window. A backport to an older line is a maintainer's call per advisory, never a promise.

---

## Security best practices for deployment

Even with the gateway in place, follow these practices:

1. **Deploy in a private network** — restrict access to the gateway to trusted agents/services only.
2. **Use TLS for all connections** — gateway ↔ agent, gateway ↔ database, gateway ↔ OIDC provider.
3. **Rotate OIDC credentials regularly** — even if using SSO, update client secrets periodically.
4. **Monitor audit logs** — unusual patterns (failed authz, high row counts, long durations) may indicate abuse.
5. **Upgrade promptly** — apply security patches within 2 weeks of release.
6. **Review permissions regularly** — audit who has access to what, especially after role changes.

---

## Security development practices

We follow these practices to minimize vulnerabilities:

- **Code review:** Every PR undergoes review; security-sensitive changes (auth, authz, SQL execution, audit) require a designated security reviewer.
- **Testing:** Unit + integration tests cover normal paths and adversarial cases (failed authz, malformed SQL, etc.).
- **Linting:** `clippy -D warnings` is enforced; no `unwrap`/`expect` outside `main.rs` and tests.
- **Logging:** Sensitive data (credentials, tokens, email addresses) are never logged or included in error messages.
- **Dependencies:** Pinned to known-good versions; security advisories are monitored and addressed.

---

## Security advisories

- **[Advisory-2026-001]** — OAuth authorization code injection in ≤0.2.0. Fixed in 1.0.0. [Details](docs/sec/qa/2026-06-29/).
- **[Advisory-2026-002]** — SQL execution bypass via CTE in ≤0.1.1. Fixed in 0.2.0 and later. [Details](docs/sec/qa/2026-06-29/).

See [`docs/sec/qa/2026-06-29/`](docs/sec/qa/2026-06-29/) for a detailed security audit and remediation status.

---

## Questions?

For non-security questions, open a GitHub issue or check the documentation at [`docs/`](docs/).

For security questions or reporting, email **security@developerz.ai**.
