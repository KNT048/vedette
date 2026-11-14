// Gom features/*/contract.ts thành OpenAPI 3.1 (D-18). Không sửa tay api/openapi.json: chạy `pnpm openapi`.
import { z } from 'zod'
import type { Endpoint } from './contract'

const mods = import.meta.glob<{ endpoints: Endpoint[] }>('../features/*/contract.ts', { eager: true })

export interface ModuleEndpoint extends Endpoint { module: string }
export const allEndpoints: ModuleEndpoint[] = Object.entries(mods)
  .flatMap(([p, m]) => m.endpoints.map((e) => ({ ...e, module: p.match(/features\/([\w-]+)\//)![1]! })))
  .sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))

function js(schema: z.ZodType) {
  const out = z.toJSONSchema(schema, { target: 'draft-2020-12', unrepresentable: 'any', io: 'output' }) as Record<string, unknown>
  delete out.$schema
  return out
}

function parameters(e: Endpoint) {
  const list: Record<string, unknown>[] = []
  for (const [where, obj] of [['path', e.params], ['query', e.query], ['header', e.headers]] as const) {
    if (!obj) continue
    for (const [name, s] of Object.entries(obj.shape)) {
      const schema = s as z.ZodType
      list.push({ name, in: where, required: where === 'path' || !schema.safeParse(undefined).success, schema: js(schema) })
    }
  }
  return list
}

const ERROR = {
  type: 'object',
  required: ['error'],
  properties: { error: { type: 'object', required: ['code', 'message'], properties: { code: { type: 'string' }, message: { type: 'string', description: 'What went wrong and how to fix it' } }, additionalProperties: true } },
}

export function buildOpenApi() {
  const paths: Record<string, Record<string, unknown>> = {}
  for (const e of allEndpoints) {
    const code = String(e.status ?? 200)
    const ok = e.response === null ? { '204': { description: 'Done, no content' } }
      : e.response === 'file' ? { [code]: { description: 'File download', content: { [e.fileType ?? 'application/octet-stream']: { schema: { type: 'string', format: 'binary' } } } } }
      : e.response === 'text' ? { [code]: { description: 'Plain text', content: { 'text/plain; charset=utf-8': { schema: { type: 'string' } } } } }
      : { [code]: { description: code === '201' ? 'Created' : code === '202' ? 'Accepted' : 'OK', content: { 'application/json': { schema: js(e.response) } } } }
    ;(paths[e.path] ??= {})[e.method] = {
      operationId: `${e.module}_${e.method}_${e.path.replace(/[{}]/g, '').replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '')}`,
      summary: e.summary,
      tags: [e.module],
      'x-stories': e.stories,
      'x-min-role': e.role,
      ...(e.role === 'public' ? { security: [] } : {}),
      ...(parameters(e).length ? { parameters: parameters(e) } : {}),
      ...(e.body === 'file' ? { requestBody: { required: true, content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } } }
        : e.body ? { requestBody: { required: !e.bodyOptional, content: { 'application/json': { schema: js(e.body) } } } } : {}),
      responses: { ...ok, default: { description: 'Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } },
    }
  }
  return {
    openapi: '3.1.0',
    info: { title: 'Vedette API', version: '0.1.0-m1', description: 'Generated from the SPA mock contract (D-18). The Go backend must match this file.' },
    servers: [{ url: '/api/v1' }],
    security: [{ session: [] }],
    components: {
      securitySchemes: { session: { type: 'apiKey', in: 'cookie', name: '__Host-vedette_session' } },
      schemas: { Error: ERROR },
    },
    tags: [...new Set(allEndpoints.map((e) => e.module))].map((name) => ({ name })),
    paths,
  }
}
