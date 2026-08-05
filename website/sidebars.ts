import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// Docusaurus strips numeric prefixes from doc IDs by default, so a file at
// docs/initial-idea/01-overview.md has id `initial-idea/overview`. Ordering
// here (not the filename number) drives the sidebar order.

const sidebars: SidebarsConfig = {
  docs: [
    {
      type: 'doc',
      id: 'initial-idea/overview',
      label: 'Introduction',
    },
    {
      type: 'category',
      label: 'Getting started',
      collapsed: false,
      items: [
        'deployment/quickstart',
        'usage/first-query',
        'usage/claude-code',
        'usage/other-agents',
      ],
    },
    {
      type: 'category',
      label: 'Deployment',
      items: [
        'deployment/config-reference',
        'deployment/admin-api',
        'deployment/logging',
        'deployment/releasing',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'features',
        'use-cases',
        'usage/multi-db',
        'comparison',
        'benchmarks',
      ],
    },
    {
      type: 'category',
      label: 'Design',
      items: [
        'initial-idea/architecture',
        'initial-idea/mcp-tools',
        'initial-idea/auth-sso',
        'initial-idea/credentials',
        'initial-idea/permissions',
        'initial-idea/logging-retention',
        'initial-idea/config',
        'initial-idea/deployment',
        'initial-idea/dynamic-permissions',
        'initial-idea/service-tokens',
        'initial-idea/docs-site',
      ],
    },
    {
      type: 'category',
      label: 'Project',
      items: [
        'initial-idea/non-goals',
        'initial-idea/roadmap',
        'initial-idea/seed',
      ],
    },
  ],
};

export default sidebars;
