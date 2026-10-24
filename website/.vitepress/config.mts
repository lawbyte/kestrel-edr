import { defineConfig } from 'vitepress'

// GitHub Pages project site: https://lawbyte.github.io/kestrel-edr/
const base = '/kestrel-edr/'
const repo = 'https://github.com/lawbyte/kestrel-edr'

export default defineConfig({
  title: 'Kestrel EDR',
  description: 'Self-hosted Windows EDR focused on infostealers: install, build, deploy and operate.',
  lang: 'en-GB',
  base,
  cleanUrls: true,
  lastUpdated: false,
  appearance: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#5b5fe0' }],
  ],
  themeConfig: {
    logo: '/favicon.svg',
    siteTitle: 'Kestrel EDR',
    search: { provider: 'local' },
    editLink: undefined,
    outline: { level: [2, 3], label: 'On this page' },
    socialLinks: [{ icon: 'github', link: repo }],
    nav: [
      { text: 'Guide', link: '/guide/introduction', activeMatch: '^/guide/' },
      { text: 'Build', link: '/build/', activeMatch: '^/build/' },
      { text: 'Deploy', link: '/deploy/server', activeMatch: '^/deploy/' },
      { text: 'Console', link: '/console/', activeMatch: '^/console/' },
      { text: 'Reference', link: '/reference/rules', activeMatch: '^/reference/' },
      {
        text: 'v1.1.7',
        items: [
          { text: 'Releases', link: `${repo}/releases` },
          { text: 'Security policy', link: `${repo}/blob/main/SECURITY.md` },
          { text: 'Contributing', link: `${repo}/blob/main/CONTRIBUTING.md` },
          { text: 'Report a false positive', link: `${repo}/issues/new?template=false_positive.yml` },
        ],
      },
    ],
    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What Kestrel is', link: '/guide/introduction' },
          { text: 'Step-by-step install', link: '/guide/quick-start' },
        ],
      },
      {
        text: 'Build from source',
        items: [{ text: 'Build on Windows', link: '/build/' }],
      },
      {
        text: 'Deploy',
        items: [
          { text: 'Deploy the server', link: '/deploy/server' },
          { text: 'Enroll devices', link: '/deploy/enroll' },
        ],
      },
      {
        text: 'Using the console',
        items: [
          { text: 'Overview, incidents, alerts', link: '/console/' },
          { text: 'Console tour', link: '/console/tour' },
          { text: 'Devices', link: '/console/devices' },
          { text: 'Response actions', link: '/console/response' },
          { text: 'Evidence capture', link: '/console/evidence' },
          { text: 'Hunting', link: '/console/hunt' },
          { text: 'Rules, exclusions and IOCs', link: '/console/rules' },
          { text: 'Policies', link: '/console/policies' },
          { text: 'Agent updates', link: '/console/updates' },
          { text: 'Quarantine and review requests', link: '/console/quarantine-reviews' },
          { text: 'Settings', link: '/console/settings' },
        ],
      },
      {
        text: 'Features',
        items: [
          { text: 'Remote access', link: '/guide/remote-access' },
          { text: 'Employee tray app', link: '/guide/tray' },
        ],
      },
      {
        text: 'Operations',
        items: [
          { text: 'Testing safely', link: '/guide/testing' },
          { text: 'Security model and limits', link: '/guide/security' },
          { text: 'Privacy (PDPA, UU PDP)', link: '/guide/privacy' },
          { text: 'Troubleshooting', link: '/guide/troubleshooting' },
          { text: 'FAQ', link: '/guide/faq' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Detection rules', link: '/reference/rules' },
          { text: 'Agent CLI', link: '/reference/cli' },
          { text: 'Ports, files and API', link: '/reference/ports-files' },
          { text: 'Resource use on endpoints', link: '/reference/performance' },
        ],
      },
    ],
    footer: {
      message: 'Released under the Apache License 2.0. SigmaHQ rules are under the Detection Rule License 1.1.',
      copyright: 'Copyright 2026 Kestrel EDR contributors',
    },
    docFooter: { prev: 'Previous', next: 'Next' },
  },
})
