// A stand-in model for the ai specs on the real backend: an OpenAI-compatible server (Chat Completions) on loopback, so the success path of every
// AI job can run with no provider key and nothing leaving the machine (PRIVACY flow 3). A profile "inside your network" may reach loopback
// (modules/ai/provider IsInternalAddr), so the box dials it like a local Ollama. It answers by what the box asked for, never by chance:
// the JSON of the response_format schema the job names (explain_cve, log_digest, cve_news, finding_brief, probe), one read-only tool call
// when tools are offered and no tool result came back yet, else plain text. The model named FAIL answers 500 (a broken primary, for the
// fallback). Every request is kept in `calls` so a test can count them and read what the box sent.
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export const FAIL = 'm-fail'
/** The fixed text of the answers, so a test can find them in the API and the page. */
export const SAY = {
  why: 'The feed entry names a product that runs on one matching device, so it is worth patching first.',
  ask: ['The box lists the devices the read-only tool returned.', 'Check which of them still need approval.'],
  digest: 'The logs of the last day hold nothing unusual from the one source that sends them.',
}

export interface FakeCall { model: string; auth: string | null; schema: string | null; tools: string[]; text: string; toolResult: boolean }
export interface FakeAI {
  base: string
  calls: FakeCall[]
  /** A fact the answer suggests the box remember (a "Remember:" line of an answer, the "remember" list of a digest), when the box asks for one. */
  remember: string | null
  server: Server
}

interface Msg { role: string; content?: string | null }
interface Req { model: string; messages: Msg[]; tools?: { function: { name: string } }[]; response_format?: { json_schema?: { name?: string; schema?: { properties?: Record<string, unknown> } } } }

function answer(f: FakeAI, req: Req): { content: string | null; tool?: string; finish: string } {
  const msgs = req.messages ?? []
  const tools = (req.tools ?? []).map((t) => t.function.name)
  if (tools.length > 0 && msgs.at(-1)?.role !== 'tool') {
    return { content: null, tool: tools.includes('search_assets') ? 'search_assets' : tools[0]!, finish: 'tool_calls' }
  }
  const schema = req.response_format?.json_schema
  switch (schema?.name) {
    case 'explain_cve':
      return { content: JSON.stringify({ why: SAY.why, patch_steps: ['Update to the fixed version the vendor names.'], temp_mitigations: ['Keep the device off the Internet until it is patched.'], detection_hints: ['Look for sign-ins nobody expected.'] }), finish: 'stop' }
    case 'log_digest': {
      const d: Record<string, unknown> = { summary: SAY.digest, items: [{ severity: 'info', title: 'One source sends logs', evidence: ['A few lines arrived from the test source.'], recommendation: 'Nothing to do now.' }] }
      if (schema.schema?.properties && 'remember' in schema.schema.properties) d.remember = f.remember ? [f.remember] : []
      return { content: JSON.stringify(d), finish: 'stop' }
    }
    case 'cve_news':
      return { content: JSON.stringify({ exploited: 'The exploited list says so.', public_exploit: 'No public code appears in the sources.', workaround: 'The sources do not give one.', other: [] }), finish: 'stop' }
    case 'finding_brief':
      return { content: JSON.stringify({ paragraphs: ['A fake brief.'], steps: ['A fake step.'] }), finish: 'stop' }
    case 'probe':
      return { content: JSON.stringify({ ok: true }), finish: 'stop' }
  }
  const asked = msgs.some((m) => typeof m.content === 'string' && m.content.includes('end the answer with one line "Remember: "'))
  return { content: SAY.ask.join('\n\n') + (asked && f.remember ? `\n\nRemember: ${f.remember}` : ''), finish: 'stop' }
}

/** Starts the fake on a free loopback port; close `server` when done. */
export async function fakeAI(): Promise<FakeAI> {
  const f = { calls: [], remember: null } as unknown as FakeAI
  f.server = createServer((rq, rs) => {
    const chunks: Buffer[] = []
    rq.on('data', (c: Buffer) => chunks.push(c))
    rq.on('end', () => {
      const req = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Req
      const msgs = req.messages ?? []
      f.calls.push({
        model: req.model, auth: rq.headers.authorization ?? null, schema: req.response_format?.json_schema?.name ?? null, tools: (req.tools ?? []).map((t) => t.function.name),
        text: msgs.map((m) => (typeof m.content === 'string' ? m.content : '')).join('\n'), toolResult: msgs.at(-1)?.role === 'tool',
      })
      const send = (status: number, body: unknown) => { const b = JSON.stringify(body); rs.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) }).end(b) }
      if (rq.url !== '/v1/chat/completions') return send(404, { error: { message: 'not found' } })
      if (req.model === FAIL) return send(500, { error: { message: 'the fake model is down' } })
      const a = answer(f, req)
      const message = a.tool
        ? { role: 'assistant', content: null, tool_calls: [{ id: `call-${f.calls.length}`, type: 'function', function: { name: a.tool, arguments: '{}' } }] }
        : { role: 'assistant', content: a.content }
      send(200, { id: `fake-${f.calls.length}`, model: req.model, choices: [{ index: 0, message, finish_reason: a.finish }], usage: { prompt_tokens: 120, completion_tokens: 40 } })
    })
  })
  await new Promise<void>((ok) => f.server.listen(0, '127.0.0.1', ok))
  f.base = `http://127.0.0.1:${(f.server.address() as AddressInfo).port}/v1`
  return f
}
