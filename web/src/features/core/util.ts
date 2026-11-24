import { canonicalZone } from '@/lib/zoneNames'

/** Split out so a test can replace it (jsdom does not allow changing location.reload). */
export const nav = { reload: () => window.location.reload(), toSetup: () => window.location.assign('/setup') }

/** A LAN range must be an internal address: exactly the rule of the inventory module (one single copy), 10/8, 172.16/12, 192.168/16 and 100.64/10
 * (RFC 6598). A wider prefix (for example 10.0.0.0/0, 100.0.0.0/8) covers the whole Internet so it is refused. The input is a CIDR already
 * qua CIDR_RE. */
export { isPrivateCidr, LOCAL_RANGE_NAMES } from '@/features/inventory/validate'

export const CIDR_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
export const MIN_PASSWORD = 12
export const MAX_UPLOAD = 5 * 1024 * 1024

/** A short "Browser on OS" for the sessions table, from the User-Agent the box stored; the raw text stays in a tooltip.
 * Order matters: Edge and Opera also say Chrome, Chrome also says Safari, iOS also says Mac OS X. Unknown → the raw text. */
export function deviceLabel(ua: string): string {
  const browser = /Edg(e|A|iOS)?\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Firefox\/|FxiOS\//.test(ua) ? 'Firefox'
    : /HeadlessChrome\//.test(ua) ? 'Headless Chrome' : /Chrome\/|CriOS\/|Chromium\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ''
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /CrOS/.test(ua) ? 'ChromeOS' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : ''
  if (browser && os) return `${browser} on ${os}`
  return browser || os || ua
}

/** One shell word in single quotes, for a command the page asks the reader to paste (an email may hold ' ; $ and backticks). */
export const shellQuote = (s: string) => `'${s.replaceAll("'", "'\\''")}'`

// The mock's copy of core/auth guessable: keep the stems and runs equal to password.go.
const COMMON_STEMS = ['password', 'passwrd', 'passwort', 'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbnm', 'qazwsx', 'iloveyou', 'welcome', 'letmein', 'admin', 'administrator', 'changeme', 'default', 'secret', 'monkey', 'dragon', 'football', 'baseball', 'sunshine', 'princess', 'superman', 'master', 'login', 'abc', 'abcdef', 'trustno', 'vedette']
const KEY_RUNS = ['01234567890123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm']
export const GUESSABLE_PASSWORD = 'This password is too easy to guess: it is built on a common password, a run like 123456 or qwerty, or the name in your email. A sentence of a few unrelated words is stronger.'
/** A password long enough but among the first a guesser tries: a common stem, a run, ≤ 3 distinct characters, or the email's name. */
export function guessablePassword(password: string, email: string): boolean {
  const compact = password.toLowerCase().replaceAll(' ', '')
  const chars = [...compact]
  if (new Set(chars).size <= 3) return true
  const isRun = (s: string) => KEY_RUNS.some((r) => r.includes(s) || [...r].reverse().join('').includes(s))
  if (isRun(compact)) return true
  const stem = chars.map((c) => (c === '@' ? 'a' : c === '$' ? 's' : /\p{L}/u.test(c) ? c : '')).join('')
  const digits = chars.filter((c) => c >= '0' && c <= '9').join('')
  const stemLen = [...stem].length
  // A run with a few other characters around it: "qwertyuiop2024", "1234567890!!".
  if ((stemLen >= 6 && isRun(stem)) || (digits.length >= 6 && stemLen < 4 && isRun(digits))) return true
  if (!stem) return false
  if (COMMON_STEMS.some((w) => stem.length % w.length === 0 && stem === w.repeat(stem.length / w.length))) return true
  const at = email.trim().toLowerCase().indexOf('@')
  const letters = at < 0 ? '' : [...email.trim().toLowerCase().slice(0, at)].filter((c) => /\p{L}/u.test(c)).join('')
  return letters.length >= 4 && stem === letters
}

const IPV4_BARE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export interface NormalisedCidr { value: string; note: 'prefix' | 'network' | null }
/** A bare address without the prefix length: do NOT guess /24 (the range could be /25, /23...). */
export const isBareIp = (raw: string) => IPV4_BARE.test(raw.trim())
/**
 * Normalise a network range the user typed. A prefix is required ("192.168.142.0/24"); without a prefix → null
 * (use isBareIp to report the right error). "192.168.142.5/24" has host bits → "192.168.142.0/24" (note 'network', the prefix is kept).
 */
export function normaliseCidr(raw: string): NormalisedCidr | null {
  const s = raw.trim()
  let note: NormalisedCidr['note'] = null
  if (!CIDR_RE.test(s)) return null
  const [ip = '', p = ''] = s.split('/')
  const bits = Number(p)
  const n = ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0)
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  const net = (n & mask) >>> 0
  if (net !== n) note = 'network'
  return { value: `${[24, 16, 8, 0].map((sh) => (net >>> sh) & 255).join('.')}/${bits}`, note }
}

/** Zones offered for search: every zone the browser lists under its current IANA name (some engines list a zone under an older alias,
 *  which the box's operating system may not ship), plus the box default and UTC (some engines leave UTC out). */
export const TIMEZONES: string[] = [...new Set([...Intl.supportedValuesOf('timeZone').map(canonicalZone), 'Asia/Ho_Chi_Minh', 'UTC'])].sort()
/** Any name the browser itself accepts as a zone; the box checks the name again (time.LoadLocation). */
export const validTimeZone = (z: string): boolean => {
  try { new Intl.DateTimeFormat(undefined, { timeZone: z }); return true } catch { return false }
}
/** This browser's zone under its current IANA name (Chrome's "Asia/Saigon" is "Asia/Ho_Chi_Minh"). */
export const browserTimeZone = (): string | null => { const z = Intl.DateTimeFormat().resolvedOptions().timeZone; return z ? canonicalZone(z) : null }
/** Two names of one zone: an engine reports a zone under its own name for it (Chrome's "Asia/Saigon" is the IANA "Asia/Ho_Chi_Minh"),
 *  so names are compared as the engine resolves them. */
export const sameTimeZone = (a: string, b: string): boolean => {
  if (a === b) return true
  try {
    return new Intl.DateTimeFormat('en', { timeZone: a }).resolvedOptions().timeZone === new Intl.DateTimeFormat('en', { timeZone: b }).resolvedOptions().timeZone
  } catch { return false }
}

export async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let s = ''
  bytes.forEach((b) => { s += String.fromCharCode(b) })
  return btoa(s)
}
export function fromBase64(b64: string): string {
  const s = atob(b64)
  return new TextDecoder().decode(Uint8Array.from(s, (c) => c.charCodeAt(0)))
}

/** Compare versions like 1.2.3 / 20261106.08 / 0.10.0-beta.1 (a beta is lower than the release of the same number). */
export function compareVersion(a: string, b: string): number {
  const [ma = '', pa] = a.split('-')
  const [mb = '', pb] = b.split('-')
  const xa = ma.split('.').map(Number)
  const xb = mb.split('.').map(Number)
  for (let i = 0; i < Math.max(xa.length, xb.length); i++) {
    const d = (xa[i] ?? 0) - (xb[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  if (pa === pb) return 0
  if (pa === undefined) return 1
  if (pb === undefined) return -1
  return pa < pb ? -1 : 1
}

/** The public page of a Vedette release, where its whole notes are (the box shows the first 500 characters). */
export const releaseUrl = (version: string) => `https://github.com/KNT048/vedette/releases/tag/v${encodeURIComponent(version)}`
