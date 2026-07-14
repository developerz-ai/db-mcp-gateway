import type {ReactNode} from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './index.module.css';

// Landing page — ported from docs/site/index.html. Content and structure track
// the old hand-rolled HTML; layout + navbar + footer come from Docusaurus.

const REPO = 'https://github.com/developerz-ai/db-mcp-gateway';
const RELEASE_TAG = '1.2.1';

function Hero(): ReactNode {
  return (
    <section className={styles.hero}>
      <span className={styles.eyebrow}>
        <span className={styles.dot} /> v{RELEASE_TAG} · public preview
      </span>
      <h1 className={styles.h1}>
        Give AI agents database access{' '}
        <span className={styles.accent}>without giving out the URL.</span>
      </h1>
      <p className={styles.lede}>
        A self-hosted MCP gateway that holds every credential, enforces
        SSO-driven permissions, and writes an append-only audit row on every
        query. One binary, one YAML, one Postgres.
      </p>
      <div className={styles.cta}>
        <Link
          className={`${styles.btn} ${styles.btnPrimary}`}
          to="/docs/deployment/quickstart">
          Quickstart →
        </Link>
        <Link className={`${styles.btn} ${styles.btnGhost}`} to={REPO}>
          View on GitHub
        </Link>
      </div>
      <div className={styles.install}>
        <div className={styles.codeblock}>
          <pre>
            <span className={styles.cmt}>
              # multi-arch (linux/amd64, linux/arm64) · MIT licensed
            </span>
            {'\n'}docker pull ghcr.io/developerz-ai/db-mcp-gateway:
            <span className={styles.add}>{RELEASE_TAG}</span>
          </pre>
        </div>
      </div>
    </section>
  );
}

function Pillars(): ReactNode {
  return (
    <section className={styles.section} id="pillars">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>The three pillars</span>
        <h2 className={styles.h2}>Zero-trust database access, by design.</h2>
        <p className={styles.sectionLede}>
          Three invariants the gateway is built to enforce. Break any one and
          it's the wrong tool.
        </p>
      </div>
      <div className={styles.grid3}>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <path d="M21 2v6h-6" />
              <path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
              <path d="M3 22v-6h6" />
              <path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
            </svg>
          </span>
          <h3>Credentials never leave the gateway</h3>
          <p>
            No DB URL on a laptop, ever. No tool returns one. No log line
            contains one. Not in errors, not in admin endpoints.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <path d="M20 13c0 5-3.5 7.5-8 8.5-4.5-1-8-3.5-8-8.5V6l8-3 8 3z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </span>
          <h3>Identity, end-to-end</h3>
          <p>
            Every query traces SSO user → group → grant → audit row. OIDC drives
            who, YAML drives what, audit records both.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <circle cx="6" cy="6" r="3" />
              <path d="M6 21V9" />
              <circle cx="18" cy="18" r="3" />
              <path d="M18 3v12" />
              <path d="M12 3v18" />
            </svg>
          </span>
          <h3>Config-as-code</h3>
          <p>
            Permissions live in YAML, reviewed by PR. No in-band admin UI —
            every grant change is a diff, an approver, a commit.
          </p>
        </div>
      </div>
    </section>
  );
}

function Features(): ReactNode {
  return (
    <section className={styles.section} id="features">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>What's in the box</span>
        <h2 className={styles.h2}>
          Everything platform teams need. Nothing they don't.
        </h2>
        <p className={styles.sectionLede}>
          Zero-trust credentials, complete user attribution, per-grant safety
          limits, and Git-reviewed permissions. No SaaS, no admin console, no
          extra moving parts.
        </p>
      </div>
      <div className={styles.grid2}>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </span>
          <h3>Zero-trust security</h3>
          <p>
            Database credentials never leave the gateway. No URLs, passwords, or
            connection strings reach AI agents or developer laptops.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <path d="M14 2v6h6" />
              <path d="M16 13H8" />
              <path d="M16 17H8" />
              <path d="M10 9H8" />
            </svg>
          </span>
          <h3>Complete user attribution</h3>
          <p>
            Every query logged with SSO user identity, SQL statement, reason,
            timestamp, and results. Full compliance audit trail.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M8 11h8" />
              <path d="M12 15V7" />
            </svg>
          </span>
          <h3>Built-in safety</h3>
          <p>
            Statement timeouts, row limits, read-only enforcement, and schema
            filtering prevent runaway queries and accidental writes.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <circle cx="18" cy="18" r="3" />
              <circle cx="6" cy="6" r="3" />
              <path d="M13 6h3a2 2 0 0 1 2 2v7" />
              <path d="M6 9v12" />
            </svg>
          </span>
          <h3>Git-based permissions</h3>
          <p>
            Access control lives in YAML files, reviewed via PR, with complete
            change history. No admin UI to maintain.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="10" rx="2" />
              <circle cx="12" cy="5" r="2" />
              <path d="M12 7v4" />
            </svg>
          </span>
          <h3>MCP-native tool surface</h3>
          <p>
            Purpose-built for AI agents: <code>list_databases</code>,{' '}
            <code>describe_schema</code>, <code>sample_table</code>,{' '}
            <code>run_query</code>, <code>explain</code>,{' '}
            <code>get_query_history</code>.
          </p>
        </div>
        <div className={styles.card}>
          <span className={styles.ic}>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round">
              <ellipse cx="12" cy="5" rx="9" ry="3" />
              <path d="M3 5v14a9 3 0 0 0 18 0V5" />
              <path d="M3 12a9 3 0 0 0 18 0" />
            </svg>
          </span>
          <h3>Multi-database</h3>
          <p>
            PostgreSQL and MongoDB with one grant surface. MySQL and MSSQL are
            rejected at boot — no partial-support surprises.
          </p>
        </div>
      </div>
    </section>
  );
}

function MentalModel(): ReactNode {
  return (
    <section className={styles.section} id="mental-model">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>One-minute mental model</span>
        <h2 className={styles.h2}>
          Agent → gateway → target DB. Everything else is state.
        </h2>
        <p className={styles.sectionLede}>
          The agent talks MCP over HTTPS. The gateway resolves the SSO identity,
          evaluates the YAML grant, opens a read-only pool with
          statement-timeout + row-cap applied, streams the result back — and,
          synchronously, before the response goes out, writes an audit row.
        </p>
      </div>
      <div className={styles.diagram}>
        <pre>{`┌─────────┐    MCP/HTTPS    ┌──────────────┐    pg wire    ┌──────────┐
│ agent   │ ──────────────▶ │   gateway    │ ────────────▶ │ target   │
│ (Claude │   bearer: jwt   │              │  ro role per  │  DBs     │
│  Code)  │ ◀────────────── │  authz+audit │ ◀──────────── │          │
└─────────┘   tool result   └──────┬───────┘   result rows └──────────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │ state DB     │
                            │ (sessions +  │
                            │  audit log)  │
                            └──────────────┘`}</pre>
      </div>
    </section>
  );
}

function Stack(): ReactNode {
  const chips: Array<[string, string]> = [
    ['lang', 'Rust · stable'],
    ['runtime', 'tokio'],
    ['http', 'axum'],
    ['db driver', 'sqlx'],
    ['config', 'serde + YAML'],
    ['state store', 'Postgres'],
    ['image', 'ghcr.io/developerz-ai/db-mcp-gateway'],
  ];
  return (
    <section className={styles.section} id="stack">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>Boring, on purpose</span>
        <h2 className={styles.h2}>One binary. One config. One state Postgres.</h2>
        <p className={styles.sectionLede}>
          No SaaS control plane. No credential vault to run alongside. No queue,
          no cache. The whole architecture fits on one page.
        </p>
      </div>
      <div className={styles.stack}>
        {chips.map(([k, v]) => (
          <span key={k} className={styles.chip}>
            <span className={styles.k}>{k}</span> {v}
          </span>
        ))}
      </div>
    </section>
  );
}

function Quickstart(): ReactNode {
  return (
    <section className={styles.section} id="quickstart">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>Client-side setup</span>
        <h2 className={styles.h2}>Add it to Claude Code with one command.</h2>
        <p className={styles.sectionLede}>
          First tool call triggers the OIDC browser flow. From there every query
          goes through the gateway.
        </p>
      </div>
      <div className={styles.install}>
        <div className={styles.codeblock}>
          <pre>{`claude mcp add --transport http db-gateway \\
  --scope project `}
            <span className={styles.add}>https://db.internal.acme.com</span>
          </pre>
        </div>
      </div>
      <p className={styles.subline}>
        Walk through it in the{' '}
        <Link to="/docs/usage/first-query">5-minute first-query guide</Link>, or
        jump to the full reference in the{' '}
        <Link to="/docs/usage/claude-code">Claude Code reference</Link>.
      </p>
    </section>
  );
}

function QuickLinks(): ReactNode {
  return (
    <section className={styles.section} id="quicklinks">
      <div className={styles.sectionHead}>
        <span className={styles.kicker}>Docs</span>
        <h2 className={styles.h2}>Read next.</h2>
      </div>
      <div className={styles.quicklinks}>
        <table>
          <thead>
            <tr>
              <th>If you're…</th>
              <th>Read</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>A platform / SRE deploying it</td>
              <td>
                <Link to="/docs/deployment/quickstart">Quickstart</Link>
              </td>
            </tr>
            <tr>
              <td>A developer whose org already runs it</td>
              <td>
                <Link to="/docs/usage/first-query">Your first query</Link> →{' '}
                <Link to="/docs/usage/claude-code">Claude Code reference</Link>
              </td>
            </tr>
            <tr>
              <td>Adding it to a non-Claude MCP client</td>
              <td>
                <Link to="/docs/usage/other-agents">Other MCP clients</Link>
              </td>
            </tr>
            <tr>
              <td>Weighing it against alternatives</td>
              <td>
                <Link to="/docs/comparison">Comparison vs alternatives</Link>
              </td>
            </tr>
            <tr>
              <td>Looking for performance numbers</td>
              <td>
                <Link to="/docs/benchmarks">Benchmarks</Link>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  useBaseUrl('/'); // ensures baseUrl is resolved at build time
  return (
    <Layout
      title="db-mcp-gateway — SSO-gated, audited DB access for AI agents"
      description="Self-hosted MCP gateway. Give AI agents audited, SSO-gated database access without ever handing out a database URL. Rust, single Docker image, YAML permissions reviewed by PR.">
      <main className={styles.home}>
        <div className={styles.wrap}>
          <Hero />
          <Pillars />
          <Features />
          <MentalModel />
          <Stack />
          <Quickstart />
          <QuickLinks />
        </div>
      </main>
    </Layout>
  );
}
