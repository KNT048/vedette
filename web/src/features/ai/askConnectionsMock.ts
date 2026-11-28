// Mock of the connections outside the network that Ask may use (S-AI-5): each only after an administrator allows it, because the read
// tools of a connection get the arguments the AI writes. A connection inside the network (a private address literal) is always usable.
import { http, HttpResponse } from 'msw'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { collection } from '@/mocks/db'
import { connectorsStore } from '@/mocks/connectors'
import type { AskConnection, AskConnectionsView } from './types'

export const askConnStore = collection<Record<string, boolean>>('ai_ask_connections', () => ({}), () => ({}))

const hostOf = (kind: string, target: string) => {
  if (kind === 'ssh') return target.replace(/:\d{1,5}$/, '').replace(/^\[|\]$/g, '')
  try { return new URL(target).hostname.replace(/^\[|\]$/g, '') } catch { return '' }
}
/** A literal private, loopback, unique-local or CGNAT address, as the box judges it; a name is never inside. */
export function insideNetwork(kind: string, target: string): boolean {
  const h = hostOf(kind, target)
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)
  }
  return /^(::1|f[cd][0-9a-f]{0,2}:)/i.test(h)
}

function outside(): AskConnection[] {
  const allowed = askConnStore.get()
  return connectorsStore.get()
    .filter((c) => c.enabled && c.tools.some((t) => t.access === 'read' && t.enabled) && !insideNetwork(c.kind, c.target))
    .map((c) => ({ id: c.id, name: c.name, address: c.target, allowed: allowed[c.id] === true, decided: c.id in allowed }))
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
    askConnStore.set({ ...askConnStore.get(), [id]: b.allowed })
    audit('ai.ask.connection', `${id}: ${b.allowed ? 'allowed' : 'not allowed'}`)
    return HttpResponse.json<AskConnection>({ ...c, allowed: b.allowed, decided: true })
  }),
]
