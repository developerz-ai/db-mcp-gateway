import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import HomepageFeatures from '@site/src/components/HomepageFeatures';
import styles from './index.module.css';

// Landing shape mirrors react-redux.js.org: centered hero + three feature
// cards, nothing else. Everything else lives in the docs; the sidebar and
// the "Get Started" CTA drive discovery. The hero uses Docusaurus's stock
// `.hero` / `.hero__title` classes so light/dark surfaces come free from
// Infima (no extra CSS needed for theme switching). Shape contract lives
// in the "Landing shape" section of `docs/initial-idea/13-docs-site.md`.

function HomepageHeader(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  const ghUrl = siteConfig.customFields?.ghUrl as string;
  return (
    <header className={clsx('hero', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          <span className={styles.brandMark} aria-hidden="true">
            🛡️
          </span>{' '}
          db-mcp-gateway
        </Heading>
        <p className="hero__subtitle">
          Give AI agents database access, without ever handing out a database
          URL.
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/deployment/quickstart">
            Get Started →
          </Link>
          <Link
            className="button button--secondary button--lg"
            to={ghUrl}>
            View on GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="db-mcp-gateway · SSO-gated, audited DB access for AI agents"
      description="Self-hosted MCP gateway. Give AI agents audited, SSO-gated database access without ever handing out a database URL. Rust, single Docker image, YAML permissions reviewed by PR.">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
