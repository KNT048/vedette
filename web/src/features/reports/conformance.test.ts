// The periodic security report API, run as one script of calls against the GUI mock: roles, validation at the edge,
// the options shaping the document, and a sent document kept exactly as sent. Every 2xx body is checked against the
// zod schema of contract.ts, so the backend that implements these endpoints can replay the same steps.
import { beforeEach, describe, expect, it } from 'vitest'
import type { ZodType } from 'zod'
import { resetMockDb } from '@/mocks/db'
import { modulesStore, sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { ReportDefinition, ReportDocument, SentReport, SentReportItem } from './contract'
import type { ReportDefinitionInput, ReportDocument as Doc } from './types'

const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }

async function call(role: Role | null, method: string, path: string, body?: unknown, schema?: ZodType) {
  sessionStore.set({ userId: role ? USER[role] : null })
  const r = await fetch(`http://localhost/api/v1${path}`, {
    method, headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = await r.json().catch(() => null) as { error?: { code: string; field?: string } } | null
  if (schema && r.ok) {
    const p = schema.safeParse(data)
    expect(p.success ? [] : p.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`), `${method} ${path} fits the schema`).toEqual([])
  }
  return { status: r.status, code: data?.error?.code ?? null, field: data?.error?.field ?? null, body: data as never }
}

const input = (d: ReportDefinitionInput): ReportDefinitionInput => ({ name: d.name, options: structuredClone(d.options), recipients: [...d.recipients] })

describe('reports conformance (mock)', () => {
  beforeEach(() => {
    resetMockDb()
    modulesStore.update((l) => l.map((m) => (m.id === 'reports' ? { ...m, enabled: true } : m)))
  })

  it('reads the definition and its schedule key, and only an admin saves it', async () => {
    expect((await call(null, 'GET', '/reports/definition')).status).toBe(401)
    const got = await call('viewer', 'GET', '/reports/definition', undefined, ReportDefinition)
    expect(got.status).toBe(200)
    const def = got.body as ReportDefinitionInput & { id: string; schedule_key: string }
    expect(def.schedule_key).toBe(`reports.def:${def.id}`)
    expect((await call('operator', 'PUT', '/reports/definition', input(def))).code).toBe('forbidden')
    const saved = await call('admin', 'PUT', '/reports/definition', { ...input(def), recipients: [' Boss@Example.com ', 'boss@example.com'] }, ReportDefinition)
    expect(saved.status).toBe(200)
    expect((saved.body as { recipients: string[] }).recipients).toEqual(['boss@example.com'])
  })

  it('refuses a definition that is not valid and names the field', async () => {
    const def = (await call('admin', 'GET', '/reports/definition')).body as ReportDefinitionInput
    const cases: [ReportDefinitionInput, string, string][] = [
      [{ ...input(def), name: ' ' }, 'invalid_name', 'name'],
      [{ ...input(def), options: { ...def.options, period: 'yearly' as never } }, 'invalid_period', 'options.period'],
      [{ ...input(def), options: { ...def.options, grouping: 'site' as never } }, 'invalid_grouping', 'options.grouping'],
      [{ ...input(def), options: { ...def.options, sections: Object.fromEntries(Object.keys(def.options.sections).map((k) => [k, false])) as never } }, 'no_sections', 'options.sections'],
      [{ ...input(def), recipients: ['ok@example.com', 'not-an-email'] }, 'invalid_email', 'recipients[1]'],
      [{ ...input(def), recipients: Array.from({ length: 21 }, (_, i) => `u${i}@example.com`) }, 'invalid_recipients', 'recipients'],
    ]
    for (const [b, code, field] of cases) {
      const r = await call('admin', 'PUT', '/reports/definition', b)
      expect([r.status, r.code, r.field], code).toEqual([400, code, field])
    }
  })

  it('makes the document with the saved options: sections, devices not added yet, not relevant, grouping', async () => {
    const full = (await call('viewer', 'GET', '/reports/document', undefined, ReportDocument)).body as Doc
    expect(Object.keys(full)).toEqual(expect.arrayContaining(['summary', 'handled', 'open', 'new', 'exposure', 'detections', 'coverage']))
    const patched = full.handled!.devices.flatMap((d) => d.items).find((i) => i.product === 'WinRAR')!
    expect([patched.handled.resolution, patched.handled.via, patched.handled.by, patched.handled.from_version, patched.handled.to_version]).toEqual(['patched', 'version_moved', 'system', '6.24', '7.23'])
    expect(full.handled!.devices.flatMap((d) => d.items).some((i) => i.handled.resolution === 'not_relevant')).toBe(false)
    expect(full.open!.groups.flatMap((g) => g.items).some((f) => !f.device.added)).toBe(true)
    expect(full.summary!.first.length).toBeLessThanOrEqual(3)

    const def = (await call('admin', 'GET', '/reports/definition')).body as ReportDefinitionInput
    const narrow = input(def)
    narrow.options = { ...narrow.options, grouping: 'cve', include_not_added: false, include_not_relevant: true, sections: { ...narrow.options.sections, exposure: false, coverage: false } }
    expect((await call('admin', 'PUT', '/reports/definition', narrow)).status).toBe(200)
    const doc = (await call('viewer', 'GET', '/reports/document', undefined, ReportDocument)).body as Doc
    expect(doc.exposure).toBeUndefined()
    expect(doc.coverage).toBeUndefined()
    expect(doc.open!.grouping).toBe('cve')
    expect(doc.open!.groups.every((g) => g.key.startsWith('CVE-'))).toBe(true)
    expect(doc.open!.groups.flatMap((g) => g.items).every((f) => f.device.added)).toBe(true)
    expect(doc.handled!.devices.flatMap((d) => d.items).some((i) => i.handled.resolution === 'not_relevant')).toBe(true)
  })

  it('sends to the saved recipients and keeps the document exactly as sent', async () => {
    expect((await call('viewer', 'POST', '/reports/send')).code).toBe('forbidden')
    const sentNow = await call('operator', 'POST', '/reports/send', undefined, SentReportItem)
    expect(sentNow.status).toBe(200)
    const item = sentNow.body as { id: string; trigger: string; recipients: string[] }
    expect(item.trigger).toBe('manual')
    const list = (await call('viewer', 'GET', '/reports/history')).body as { items: { id: string }[] }
    expect(list.items[0]!.id).toBe(item.id)
    const kept = await call('viewer', 'GET', `/reports/history/${item.id}`, undefined, SentReport)
    const before = (kept.body as { document: Doc }).document

    const def = (await call('admin', 'GET', '/reports/definition')).body as ReportDefinitionInput
    expect((await call('admin', 'PUT', '/reports/definition', { ...input(def), options: { ...def.options, period: 'last_30_days' } })).status).toBe(200)
    const again = (await call('viewer', 'GET', `/reports/history/${item.id}`)).body as { document: Doc }
    expect(again.document).toEqual(before)
    expect(again.document.period.kind).toBe('last_7_days')
    expect((await call('viewer', 'GET', '/reports/history/nope')).code).toBe('not_found')
  })

  it('refuses to send with no recipient', async () => {
    const def = (await call('admin', 'GET', '/reports/definition')).body as ReportDefinitionInput
    expect((await call('admin', 'PUT', '/reports/definition', { ...input(def), recipients: [] })).status).toBe(200)
    expect((await call('operator', 'POST', '/reports/send')).code).toBe('no_recipients')
  })
})
