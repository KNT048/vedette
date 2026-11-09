// Drift test: the SPA's moduleOf must give, for every operation of api/openapi.json, the module that Go's
// ModuleOf gives (api/route-modules.json, kept equal to the Go table by core/server/routemodules_test.go).
import { describe, expect, it } from 'vitest'
import openapi from '../../../api/openapi.json'
import goModules from '../../../api/route-modules.json'
import { handlers } from '@/mocks/handlers'
import { handlerApiPath, mockedHandlers } from '@/mocks/realFilter'
import { moduleOf, realModules } from './apiModules'

const methods = ['get', 'post', 'put', 'patch', 'delete']
const ops = Object.entries(openapi.paths as Record<string, Record<string, unknown>>).flatMap(([path, item]) =>
  Object.keys(item).filter((m) => methods.includes(m)).map((m) => `${m.toUpperCase()} ${path}`),
)
const fixture = goModules as Record<string, string>

describe('moduleOf matches core/server/modules.go', () => {
  it('knows the same operations as the Go route table', () => {
    expect(ops.sort()).toEqual(Object.keys(fixture).sort())
  })
  it.each(ops)('%s', (op) => {
    expect(moduleOf(op.slice(op.indexOf(' ') + 1))).toBe(fixture[op])
  })
  it('handles concrete ids and query strings', () => {
    expect(moduleOf('/findings/f-12/applied?x=1')).toBe('mitigation')
    expect(moduleOf('/findings/f-12')).toBe('findings')
    expect(moduleOf('/scans/credentialed/run')).toBe('scan-credentialed')
    expect(moduleOf('/modules')).toBe('core')
  })
})

describe('realModules', () => {
  it('parses the list, all and the legacy VITE_API_MOCK=off', () => {
    expect(realModules(undefined)('core')).toBe(false)
    expect(realModules('core, inventory')('inventory')).toBe(true)
    expect(realModules('core')('ai')).toBe(false)
    expect(realModules('all')('ai')).toBe(true)
    expect(realModules(undefined, 'off')('ai')).toBe(true)
  })
})

describe('mockedHandlers', () => {
  it('drops exactly the handlers of real modules', () => {
    const real = new Set(['core', 'host'])
    const kept = mockedHandlers(handlers, (m) => real.has(m))
    const dropped = handlers.filter((h) => !kept.includes(h))
    expect(dropped.length).toBeGreaterThan(0)
    expect(dropped.every((h) => real.has(moduleOf(handlerApiPath(h))))).toBe(true)
    expect(kept.every((h) => !real.has(moduleOf(handlerApiPath(h))))).toBe(true)
    expect(dropped.map(handlerApiPath)).toContain('/modules')
  })
  it('keeps everything when nothing is real and drops everything for all', () => {
    expect(mockedHandlers(handlers, () => false)).toHaveLength(handlers.length)
    expect(mockedHandlers(handlers, () => true)).toHaveLength(0)
  })
})
