import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

// The three pillars from CLAUDE.md, pared down to react-redux's homepage
// shape (three cards, one row). Wording tracks CLAUDE.md's "Non-negotiables
// (MUST)" list so the landing and the internal contract stay in lockstep.
// Icons use emoji so they render consistently across OSes without a custom
// icon-font dependency (same choice as the 🛡️ navbar brand).

type FeatureItem = {
  icon: string;
  title: string;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    icon: '🔒',
    title: 'Credentials never leave the gateway',
    description: (
      <>
        No DB URL on a laptop, ever. No tool returns one. No log line contains
        one. Not in errors, not in admin endpoints.
      </>
    ),
  },
  {
    icon: '👤',
    title: 'Identity, end-to-end',
    description: (
      <>
        Every query traces SSO user → group → grant → audit row. OIDC drives
        who, YAML drives what, audit records both.
      </>
    ),
  },
  {
    icon: '📝',
    title: 'Config-as-code',
    description: (
      <>
        Permissions live in YAML, reviewed by PR. No in-band admin UI. Every
        grant change is a diff, an approver, a commit.
      </>
    ),
  },
];

function Feature({icon, title, description}: FeatureItem): ReactNode {
  return (
    <div className={clsx('col col--4')}>
      <div className={styles.featureCard}>
        <span className={styles.featureIcon} aria-hidden="true">
          {icon}
        </span>
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
