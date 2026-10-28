import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Security guard rails for application code. PhishLens handles hostile input,
 * so these patterns are banned outright rather than reviewed case by case.
 */
const securityRules = {
  'no-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  '@typescript-eslint/no-implied-eval': 'error',
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'Never render untrusted markup. Render text through React instead.',
    },
    {
      selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML)$/]',
      message: 'innerHTML/outerHTML are banned: they parse markup and can execute content.',
    },
    {
      selector:
        'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment)$/]',
      message: 'HTML-parsing DOM sinks are banned.',
    },
    {
      selector:
        "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]",
      message: 'document.write is banned.',
    },
  ],
  'no-restricted-globals': [
    'error',
    { name: 'fetch', message: 'PhishLens must not make network requests.' },
    { name: 'XMLHttpRequest', message: 'PhishLens must not make network requests.' },
    { name: 'WebSocket', message: 'PhishLens must not make network requests.' },
    { name: 'EventSource', message: 'PhishLens must not make network requests.' },
    { name: 'importScripts', message: 'Workers must not load remote scripts.' },
    { name: 'localStorage', message: 'Email data must not be persisted.' },
    { name: 'sessionStorage', message: 'Email data must not be persisted.' },
    { name: 'indexedDB', message: 'Email data must not be persisted.' },
    { name: 'caches', message: 'Email data must not be persisted.' },
  ],
  'no-restricted-properties': [
    'error',
    { object: 'window', property: 'open', message: 'Never open extracted URLs.' },
    { object: 'window', property: 'localStorage', message: 'Email data must not be persisted.' },
    { object: 'window', property: 'sessionStorage', message: 'Email data must not be persisted.' },
    { object: 'window', property: 'indexedDB', message: 'Email data must not be persisted.' },
    { object: 'window', property: 'fetch', message: 'PhishLens must not make network requests.' },
    {
      object: 'navigator',
      property: 'sendBeacon',
      message: 'PhishLens must not make network requests.',
    },
    { object: 'document', property: 'cookie', message: 'Email data must not be persisted.' },
    { object: 'location', property: 'assign', message: 'Never navigate to extracted URLs.' },
    { object: 'location', property: 'replace', message: 'Never navigate to extracted URLs.' },
  ],
};

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      eqeqeq: ['error', 'always'],
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: securityRules,
  },
  {
    files: ['tests/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
  {
    files: ['**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
  },
  prettier,
);
