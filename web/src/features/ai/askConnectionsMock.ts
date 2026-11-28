// Mock of the connections outside the network that Ask may use (S-AI-5): each only after an administrator allows it, because the read
// tools of a connection get the arguments the AI writes. A connection inside the network (a private address literal) is always usable.
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { collection } from '@/mocks/db'
import { connectorsStore } from '@/mocks/connectors'
import type { AskConnection, AskConnectionsView } from './types'

export const askConnStore = collection<Record<string, { allowed: boolean; address: string }>>('ai_ask_connections', () => ({}), () => ({}))

const hostOf = (kind: string, target: string) => {
  if (kind === 'ssh') return target.replace(/:\d{1,5}$/, '').replace(/^\[|\]$/g, '')
  try { return new URL(target).hostname.replace(/^\[|\]$/g, '') } catch { return '' }
}
/** A literal private IPv4 or unique-local IPv6 address, as the box judges it; CGNAT, loopback, link-local, public addresses and names are outside. */
export function insideNetwork(kind: string, target: string): boolean {
  const h = hostOf(kind, target)
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
  }
  return /^f[cd][0-9a-f]{0,2}:/i.test(h)
}

function outside(): AskConnection[] {
  const allowed = askConnStore.get()
  return connectorsStore.get()
    .filter((c) => c.enabled && c.tools.some((t) => t.access === 'read' && t.enabled) && !insideNetwork(c.kind, c.target))
    .map((c) => {
      const d = allowed[c.id]?.address === c.target ? allowed[c.id] : undefined // a decision is for the address it was made at
      return { id: c.id, name: c.name, address: c.target, allowed: d?.allowed === true, decided: d !== undefined }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

export const askConnectionHandlers = [
  http.get(`${API}/ai/ask/connections`, () => {
    const denied = guard('admin'); if (denied) return denied
    const items = outside()
    return HttpResponse.json<AskConnectionsView>({ items, notice: items.some((c) => !c.decided) })
  }),
  http.put(`${API}/ai/ask/connections/:id`, async ({ request, params }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    const c = outside().find((x) => x.id === id)
    if (!c) return fail(404, 'not_found', 'No connection outside the network with read tools has this id.')
    const b = await body<{ allowed: boolean }>(request)
    if (typeof b.allowed !== 'boolean') return fail(400, 'invalid', 'Say whether Ask may use the connection: allowed true or false.')
    askConnStore.set({ ...askConnStore.get(), [id]: { allowed: b.allowed, address: c.address } })
    audit('ai.ask.connection', `${id}: ${b.allowed ? 'allowed' : 'not allowed'}`)
    return HttpResponse.json<AskConnection>({ ...c, allowed: b.allowed, decided: true })
  }),
]
