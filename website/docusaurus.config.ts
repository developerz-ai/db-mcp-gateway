import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docusaurus 3 (classic preset) — replaces the mdBook + hand-rolled landing
// setup. Publishes at https://developerz-ai.github.io/db-mcp-gateway/.
// Contract: docs/initial-idea/13-docs-site.md (moved into website/docs/).

const GH_ORG = 'developerz-ai';
const GH_REPO = 'db-mcp-gateway';
const GH_URL = `https://github.com/${GH_ORG}/${GH_REPO}`;

const config: Config = {
  title: 'db-mcp-gateway',
  tagline:
    'Give AI agents database access — without ever handing out a database URL.',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://developerz-ai.github.io',
  baseUrl: '/db-mcp-gateway/',

  organizationName: GH_ORG,
  projectName: GH_REPO,

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: 'docs',
          editUrl: `${GH_URL}/edit/main/website/`,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    metadata: [
      {
        name: 'description',
        content:
          'Self-hosted MCP gateway. Give AI agents audited, SSO-gated database access without ever handing out a database URL. Rust, single Docker image, YAML permissions reviewed by PR.',
      },
    ],
    navbar: {
      title: 'db-mcp-gateway',
      logo: {
        alt: 'db-mcp-gateway shield logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {
          href: `${GH_URL}`,
          position: 'right',
          className: 'header-github-link',
          'aria-label': 'GitHub repository',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Quickstart', to: '/docs/deployment/quickstart'},
            {label: 'Your first query', to: '/docs/usage/first-query'},
            {label: 'Config reference', to: '/docs/deployment/config-reference'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: GH_URL},
            {
              label: 'GHCR image',
              href: `${GH_URL}/pkgs/container/db-mcp-gateway`,
            },
            {label: 'llms.txt', href: 'pathname:///llms.txt'},
          ],
        },
      ],
      copyright:
        'MIT · Model Context Protocol is a specification from Anthropic. db-mcp-gateway is an independent implementation, not affiliated with or endorsed by Anthropic.',
    },
    prism: {
      theme: prismThemes.oneLight,
      darkTheme: prismThemes.oneDark,
      additionalLanguages: ['bash', 'toml', 'yaml', 'rust', 'sql', 'json'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
