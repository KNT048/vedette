/// <reference types="vite/client" />
interface ImportMetaEnv { readonly VITE_API_MOCK?: 'on' | 'off' }
interface ImportMeta { readonly env: ImportMetaEnv }
