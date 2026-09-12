import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://rise-deploy.github.io',
  base: '/oauthrelay',
  integrations: [
    starlight({
      title: 'oauthrelay',
      description: 'Stable OAuth callbacks and explicit OIDC relay boundaries.',
      customCss: ['./src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/rise-deploy/oauthrelay/edit/develop/docs/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/rise-deploy/oauthrelay',
        },
      ],
      sidebar: [
        { label: 'Home', slug: 'index' },
        { label: 'Getting started', slug: 'getting-started' },
        {
          label: 'Concepts',
          items: [{ label: 'Relay trust model', slug: 'relay-model' }],
        },
        {
          label: 'Guides',
          items: [{ autogenerate: { directory: 'guides' } }],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Configuration', slug: 'configuration' },
            { label: 'File provider', slug: 'reference/file-provider' },
            { label: 'AWS SSM provider', slug: 'reference/ssm-provider' },
            { label: 'Kubernetes provider', slug: 'reference/kubernetes-provider' },
            { label: 'Runtime and deployment', slug: 'reference/runtime' },
            { label: 'HTTP endpoints', slug: 'reference/http-endpoints' },
          ],
        },
      ],
    }),
  ],
});
