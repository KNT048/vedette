/// <reference types="vite/client" />
interface ImportMetaEnv { readonly VITE_API_MOCK?: 'on' | 'off'; readonly VITE_API_REAL?: string }
interface ImportMeta { readonly env: ImportMetaEnv }
/** TERMS.md and its version, computed by vite.config.ts the way the box computes it. */
declare module 'virtual:terms' {
  export const TERMS: string
  export const TERMS_VERSION: string
}
/** docs/cookbook: each Markdown file (README.md is the index) and the served URL of each image, keyed "images/<file>". */
declare module 'virtual:cookbook' {
  export const PAGES: { file: string; markdown: string }[]
  export const IMAGES: Record<string, string>
}
