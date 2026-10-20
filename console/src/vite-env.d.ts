/// <reference types="vite/client" />
interface ImportMetaEnv {
  readonly VITE_MOCK?: string
  readonly VITE_DEMO?: string
}
interface ImportMeta {
  readonly env: ImportMetaEnv
}
