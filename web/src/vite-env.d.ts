/// <reference types="vite/client" />
interface ImportMetaEnv { readonly VITE_API_MOCK?: 'on' | 'off'; readonly VITE_API_REAL?: string }
interface ImportMeta { readonly env: ImportMetaEnv }
