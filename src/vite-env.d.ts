/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Maximum accepted message size in megabytes (default 10). */
  readonly VITE_MAX_EMAIL_MB?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
