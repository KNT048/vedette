// Prepares a real box (make dev-api REAL=core,inventory,feeds,findings,mitigation) for the findings/mitigation checks:
// the real first-run setup, an operator and a viewer, KEV loaded, and three devices so that real findings exist.
// Idempotent: run it again on a box that is already set up and it signs in instead.
//   BOX_URL=http://127.0.0.1:8080 SETUP_CODE=<code from the backend log> QA_PASSWORD=<a long password> node web/e2e/qa/real-box.mjs
// Accounts afterwards: admin@qa.test, op@qa.test, view@qa.test, all with QA_PASSWORD (the same ones the feeds checks use).
// Plain Node, no dependencies. Test-only: it signs in over HTTP with the password it is given.
const BOX = process.env.BOX_URL ?? 'http://127.0.0.1:8080'
const PASSWORD = process.env.QA_PASSWORD
const CODE = process.env.SETUP_CODE
if (!PASSWORD) throw new Error('set QA_PASSWORD')

const ACCOUNTS = [
  { name: 'QA Admin', email: 'admin@qa.test', role: 'admin' },
  { name: 'QA Operator', email: 'op@qa.test', role: 'operator' },
  { name: 'QA Viewer', email: 'view@qa.test', role: 'viewer' },
]
// Real KEV products: QNAP Photo Station (has a project recommendation pack), Fortinet FortiOS (many CVEs), Microsoft Windows (hundreds).
const DEVICES = [
  { name: 'nas02', ip: '192.168.10.21', vendor: 'QNAP', product: 'Photo Station', version: '6.1.2' },
  { name: 'fw01', ip: '192.168.10.1', vendor: 'Fortinet', product: 'FortiOS', version: '7.0.1' },
  { name: 'dc01', ip: '192.168.10.5', vendor: 'Microsoft', product: 'Windows', version: '10.0.17763' },
]

const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms))

async function call(session, method, path, body) {
  const headers = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (session) {
    headers.Cookie = session.cookie
    if (method !== 'GET') headers['X-CSRF-Token'] = session.csrf
  }
  for (let attempt = 0; attempt < 20; attempt++) {
    const r = await fetch(`${BOX}/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    if (r.status === 503 && path.startsWith('/auth/login')) { await sleep(500); continue } // the box checks one password at a time
    const text = await r.text()
    return { status: r.status, body: text ? JSON.parse(text) : null, jar: r.headers.getSetCookie().map((c) => c.split(';')[0]) }
  }
  throw new Error(`${method} ${path}: the box stayed busy`)
}
const sessionOf = (jar) => {
  const csrf = jar.find((c) => c.startsWith('__Host-vedette_csrf='))?.split('=')[1]
  if (!csrf) throw new Error('no CSRF cookie in the answer')
  return { cookie: jar.join('; '), csrf }
}
async function login(email, password) {
  const r = await call(null, 'POST', '/auth/login', { email, password })
  return r.status === 200 ? sessionOf(r.jar) : null
}
const must = (r, what, ...ok) => {
  if (!ok.includes(r.status)) throw new Error(`${what}: ${r.status} ${JSON.stringify(r.body)}`)
  return r
}

let admin = await login(ACCOUNTS[0].email, PASSWORD)
if (!admin) {
  if (!CODE) throw new Error('the box is not set up yet: set SETUP_CODE to the code in the backend log')
  const r = must(await call(null, 'POST', '/core/setup', {
    org: 'QA Company', admin: { name: ACCOUNTS[0].name, email: ACCOUNTS[0].email, password: PASSWORD },
    lan: ['192.168.10.0/24'], commitment: false, bundle: 'custom', modules: (process.env.BOX_MODULES ?? 'inventory,feeds,findings,mitigation').split(','), setup_code: CODE, accept_terms: true,
  }), 'setup', 200, 201)
  admin = sessionOf(r.jar)
  console.log('setup done')
}

const users = must(await call(admin, 'GET', '/core/users'), 'list users', 200).body.items
for (const a of ACCOUNTS.slice(1)) {
  if (users.some((u) => u.email === a.email)) continue
  const made = must(await call(admin, 'POST', '/core/users', { name: a.name, email: a.email, role: a.role }), `create ${a.email}`, 201).body
  const s = await login(a.email, made.temp_password)
  if (!s) throw new Error(`first sign-in of ${a.email} failed`)
  must(await call(s, 'POST', '/core/account/password', { current: made.temp_password, next: PASSWORD }), `password of ${a.email}`, 200)
  console.log('created', a.email)
}
const op = await login(ACCOUNTS[1].email, PASSWORD)
if (!op) throw new Error('operator cannot sign in')

if (process.env.BOX_SKIP_DATA) { console.log('accounts ready, no data (BOX_SKIP_DATA)'); process.exit(0) }
// KEV first (the box pulls CISA, or its GitHub mirror when cisa.gov answers 403), then the devices, then wait for the findings to appear.
const kev = must(await call(admin, 'POST', '/feeds/sources/cisa-kev/fetch'), 'fetch KEV', 200).body
if (kev.status !== 'ok') throw new Error(`KEV fetch: ${JSON.stringify(kev)}`)
console.log('KEV loaded:', kev.records ?? '?', 'records')
const have = must(await call(op, 'GET', '/inventory/devices'), 'list devices', 200).body.items ?? []
for (const d of DEVICES) {
  if (have.some((x) => x.ip === d.ip)) continue
  const r = must(await call(op, 'POST', '/inventory/devices', d), `add ${d.name}`, 201).body
  console.log('added', d.name, `${r.kev_cves} CVEs in KEV`)
  if (d.name === 'fw01') must(await call(op, 'PATCH', `/inventory/devices/${r.id}`, { kind: 'firewall' }), 'kind of fw01', 200)
}
let n = 0
for (let i = 0; i < 40 && n === 0; i++) {
  n = must(await call(op, 'GET', '/findings'), 'list findings', 200).body.items.length
  if (n === 0) await sleep(500)
}
console.log('findings on the box:', n)
