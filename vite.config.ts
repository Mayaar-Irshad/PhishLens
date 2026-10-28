import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

/**
 * Content Security Policy for the production build. GitHub Pages cannot send
 * response headers, so the policy is delivered as a <meta> tag. It is only
 * injected at build time because the Vite dev server relies on inline scripts
 * and a WebSocket for hot reload.
 *
 * `connect-src 'none'` means the page itself cannot make fetch/XHR/WebSocket
 * requests at all, which backs up the "nothing is uploaded" promise.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'none'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

function contentSecurityPolicy(): Plugin {
  const charset = '<meta charset="UTF-8" />';
  return {
    name: 'phishlens-csp',
    apply: 'build',
    transformIndexHtml: {
      order: 'pre',
      handler: (html) => {
        if (!html.includes(charset))
          throw new Error('index.html must declare <meta charset="UTF-8" />');
        // Directly after the charset declaration, before any script or stylesheet.
        return html.replace(
          charset,
          `${charset}\n    <meta http-equiv="Content-Security-Policy" content="${CONTENT_SECURITY_POLICY}" />`,
        );
      },
    },
  };
}

export default defineConfig({
  // Relative base so the build works from any GitHub Pages sub-path
  // (https://<user>.github.io/<repo>/) without extra configuration.
  base: './',
  plugins: [react(), contentSecurityPolicy()],
  build: {
    target: 'es2022',
    sourcemap: false,
  },
  worker: {
    format: 'es',
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.{ts,tsx}'],
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/vite-env.d.ts'],
      reporter: ['text', 'html'],
    },
  },
});
