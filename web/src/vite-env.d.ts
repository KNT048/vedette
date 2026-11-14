/// <reference types="vite/client" />
interface ImportMetaEnv { readonly VITE_API_MOCK?: 'on' | 'off'; readonly VITE_API_REAL?: string }
interface ImportMeta { readonly env: ImportMetaEnv }
/** TERMS.md (D-544) and its version, computed by vite.config.ts the way the box computes it. */
declare module 'virtual:terms' {
  export const TERMS: string
  export const TERMS_VERSION: string
}
