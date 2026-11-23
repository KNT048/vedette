// A ring buffer of the last 20 browser-side errors for the bug-report diagnostic bundle (S-CORE-5). Kept in memory only, never sent anywhere.
// Emails and IP addresses are removed from the message before it is stored: the diagnostic bundle must not contain them.
export interface ClientError { at: string; kind: 'error' | 'unhandledrejection'; message: string }

const MAX = 20
const buf: ClientError[] = []
let installed = false

export function redact(s: string): string {
  return s
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, '[email]')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '[ip]')
    .replace(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi, '[ip]')
}

function push(kind: ClientError['kind'], raw: unknown) {
  const msg = raw instanceof Error ? `${raw.name}: ${raw.message}` : String(raw)
  buf.push({ at: new Date().toISOString(), kind, message: redact(msg).slice(0, 300) })
  if (buf.length > MAX) buf.shift()
}

/** Called once in main.tsx. */
export function installClientErrors() {
  if (installed) return
  installed = true
  window.addEventListener('error', (e) => push('error', e.error ?? e.message))
  window.addEventListener('unhandledrejection', (e) => push('unhandledrejection', e.reason))
}

/** For page errors (RouteError) that the browser does not report through an event. */
export const recordClientError = (e: unknown) => push('error', e)
export const getClientErrors = (): ClientError[] => [...buf]
