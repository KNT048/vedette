// Test hợp đồng (D-18), chạy riêng một module: `pnpm exec vitest run src/lib/contract.test.ts -t "<module>"`.
// 1) Mọi handler mock có endpoint trong contract.ts và ngược lại. 2) Mọi GET gọi thử được trả dữ liệu khớp schema.
// 3) api/openapi.json khớp hợp đồng hiện tại (sinh lại bằng `pnpm openapi`).
import { describe, expect, it } from 'vitest'
import type { RequestHandler } from 'msw'
import { handlersByModule } from '@/mocks/handlers'
import { orgStore, sessionStore } from '@/mocks/stores'
import { allEndpoints, buildOpenApi } from './openapi'
import openapiFile from '../../../api/openapi.json'

const key = (method: string, path: string) => `${method.toLowerCase()} ${path}`
function handlerKey(h: RequestHandler) {
  const info = h.info as unknown as { method: string; path: string }
  const path = String(info.path).replace(/^\*\/api\/v1/, '').replace(/:(\w+)/g, '{$1}')
  return key(info.method, path)
}

const modules = Object.keys(handlersByModule).sort()

describe.each(modules)('hợp đồng %s', (mod) => {
  const handlers = handlersByModule[mod]!.map(handlerKey)
  const eps = allEndpoints.filter((e) => e.module === mod)

  it('mọi handler mock có trong contract.ts và ngược lại', () => {
    const declared = new Set(eps.map((e) => key(e.method, e.path)))
    expect(handlers.filter((h) => !declared.has(h)), 'handler chưa khai trong contract.ts').toEqual([])
    expect([...declared].filter((d) => !handlers.includes(d)), 'endpoint khai mà mock không có').toEqual([])
  })

  it('GET trả dữ liệu khớp schema', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    for (const e of eps.filter((x) => x.method === 'get' && x.response && x.response !== 'file')) {
      if (e.path.includes('{') && !e.example?.params) continue
      sessionStore.set({ userId: e.role === 'public' ? null : 'u-admin' })
      const path = e.path.replace(/\{(\w+)\}/g, (_, k: string) => encodeURIComponent(e.example!.params![k]!))
      const qs = e.example?.query ? `?${new URLSearchParams(e.example.query)}` : ''
      const res = await fetch(`${location.origin}/api/v1${path}${qs}`)
      expect(res.status, `GET ${path}${qs}`).toBeLessThan(300)
      const parsed = (e.response as Exclude<typeof e.response, null | 'file'>).safeParse(await res.json())
      expect(parsed.success ? [] : parsed.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`), `GET ${path}${qs} khớp schema`).toEqual([])
    }
  })
})

describe('openapi.json', () => {
  it('khớp hợp đồng hiện tại (chạy `pnpm openapi` nếu lệch)', () => {
    expect(openapiFile).toEqual(JSON.parse(JSON.stringify(buildOpenApi())))
  })
})
