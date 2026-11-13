import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { assetsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { engineStore, nextRun, runs, scannerStore, timing, zoneStore } from './mocks'
import { manyAssets } from '@/mocks/seed/assets'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import type { ScanConfig, ScanRun } from './types'

// D-417: v1 does not offer the credentialed scan (no backend yet); its GUI is kept, so this file runs it as offered, and one test runs v1.
const credFlag = vi.hoisted(() => ({ CREDENTIALED_IN_UI: true }))
vi.mock('@/lib/credentialed', () => credFlag)

const base = () => `${location.origin}/api/v1`
const as = (userId: string) => sessionStore.set({ userId })
const json = (method: string, b: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
const getRuns = async () => ((await (await fetch(`${base()}/scans/runs`)).json()) as { items: ScanRun[] }).items
const postRun = (targets: string[]) => fetch(`${base()}/scans/runs`, json('POST', { targets }))

timing.engineMs = 0 // the mock's engine is busy after Stop now only where a test says so (D-261 (4))
afterEach(() => { timing.stepMs = 2000; timing.stopMs = 1000; timing.engineMs = 0; vi.useRealTimers(); localStorage.removeItem('vedette-mock-egress') })

async function onlyTarget(label: RegExp) {
  await userEvent.click(await screen.findByRole('button', { name: 'Clear selection' }))
  await userEvent.click(screen.getByRole('checkbox', { name: label }))
}

describe('scan: trang chính và chọn mục tiêu (S-SCAN-1)', () => {
  it('câu đầu nêu lần quét gần nhất, có phạm vi, không lỗi a11y', async () => {
    renderApp('/scans')
    // the seeded scheduled run checks only devices allowed without a pick (D-126 (2)), so its match count follows the seed
    expect(await screen.findByRole('heading', { level: 1, name: /Last scan .*: \d+ devices checked/ })).toBeInTheDocument()
    expect(await screen.findByText(/Only scans inside the confirmed scope: 192\.168\.10\.0\/24, 192\.168\.20\.0\/24/)).toBeInTheDocument()
    expect(await screen.findByText(/Scan scope commitment ticked on/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('mặc định chọn thiết bị có phát hiện (trừ thiết bị chỉ quét khi tự tick, D-126); thiết bị chưa duyệt, bị loại trừ, tên miền chưa xác thực bị khoá kèm lý do', async () => {
    renderApp('/scans')
    const nas = await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    expect(nas).not.toBeChecked() // fragile: only the person's own tick picks it
    expect(screen.getByRole('checkbox', { name: /WEB01/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /SRV-AD/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /FW-HQ/ })).not.toBeChecked()
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    const unapproved = screen.getByRole('checkbox', { name: /BROTHER-STORE/ })
    expect(unapproved).toBeDisabled()
    expect(screen.getAllByText('Not approved in the inventory, so not scanned').length).toBeGreaterThan(0)
    expect(screen.getByRole('checkbox', { name: /acme-demo\.example/ })).toBeDisabled()
    expect(screen.getByText('Ownership not verified, so not scanned')).toBeInTheDocument()
    // External targets are listed but this version does not scan them yet, even when verified (deferred).
    expect(screen.getByRole('checkbox', { name: /^acme\.example / })).toBeDisabled()
    expect(screen.getAllByText('External targets are not scanned yet').length).toBeGreaterThan(0)
    expect(screen.getByText(/This version does not scan external targets for vulnerabilities yet/)).toBeInTheDocument()
    // IP ngoài hộp không thấy quá 30 ngày thì không quét được
    expect(screen.getByRole('checkbox', { name: /203\.0\.113\.55/ })).toBeDisabled()
    expect(screen.getAllByText('Verification expired, verify again, so not scanned').length).toBeGreaterThan(0)
    expect(screen.getByRole('link', { name: 'Open External exposure' })).toHaveAttribute('href', '/exposure')
  })

  it('D-126: chọn sẵn và nút chọn hàng loạt không bao giờ tick thiết bị mong manh, chưa phân loại, khai tay; người dùng tự tick mới là chọn', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, origin: 'manual' as const } : a.id === 'a-unk01' ? { ...a, approved: true } : a)))
    renderApp('/scans')
    const nas = await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    const items = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; pick_only: boolean; selectable: boolean }[]
    const pick = (id: string) => items.find((x) => x.id === id)!.pick_only
    expect([pick('a-nas02'), pick('a-web01'), pick('a-unk01'), pick('a-srvad')]).toEqual([true, true, true, false])
    expect(nas).toBeEnabled()
    expect(nas).not.toBeChecked() // it has a finding, but a preselection is not a pick
    expect(screen.getByRole('checkbox', { name: /WEB01/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /SRV-AD/ })).toBeChecked()
    expect(screen.getAllByText('Fragile: pick it to scan at a quarter of the speed').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Added by hand: pick it to scan').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Type unknown: pick it to identify its services (no operating system probe) and scan it at a quarter of the speed').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    expect(nas).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /WEB01/ })).not.toBeChecked()
    await userEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
    await userEvent.click(nas) // the person's own tick is the pick
    expect(nas).toBeChecked()
    expect(screen.getByRole('button', { name: 'Scan now (1)' })).toBeEnabled()
  })

  it('rà soát M1: danh sách làm mới thì chọn hàng loạt bỏ thiết bị vừa thành chỉ-quét-khi-tự-tick; tick tay vẫn giữ', async () => {
    timing.stepMs = 60_000
    renderApp('/scans')
    await onlyTarget(/WEB01/)
    await userEvent.click(screen.getByRole('button', { name: 'Scan now (1)' }))
    await screen.findByRole('button', { name: 'Stop now' })
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    expect(screen.getByRole('checkbox', { name: /SRV-AD/ })).toBeChecked()
    await userEvent.click(screen.getByRole('checkbox', { name: /NAS-PHOTOS/ })) // the person's own tick
    assetsStore.update((l) => l.map((a) => (a.id === 'a-srvad' ? { ...a, fragile: true } : a)))
    await userEvent.click(screen.getByRole('button', { name: 'Stop now' })) // a mutation: the lists refresh
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /SRV-AD/ })).not.toBeChecked())
    expect(screen.getByRole('checkbox', { name: /NAS-PHOTOS/ })).toBeChecked()
  })

  it('?target= của một thiết bị mong manh không tick sẵn nó', async () => {
    renderApp('/scans?target=a-nas02')
    expect(await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })).not.toBeChecked()
    expect(screen.getByText('0 selected')).toBeInTheDocument()
  })

  it('loại trừ trong cấu hình khoá thiết bị tương ứng', async () => {
    as('u-admin')
    const res = await fetch(`${base()}/scans/config`, json('PUT', { exclusions: ['192.168.10.21'] }))
    expect(res.status).toBe(200)
    renderApp('/scans')
    expect(await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })).toBeDisabled()
    expect(screen.getAllByText('In the exclusion list').length).toBeGreaterThan(0)
  })

  it('?target= từ trang phát hiện chọn sẵn đúng thiết bị', async () => {
    renderApp('/scans?target=a-web01')
    expect(await screen.findByRole('checkbox', { name: /WEB01/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /NAS-PHOTOS/ })).not.toBeChecked()
    expect(screen.getByText('1 selected')).toBeInTheDocument()
  })

  it('chưa có văn bản đồng ý thì khoá nút và nói rõ', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))
    renderApp('/scans')
    expect(await screen.findByRole('button', { name: /Scan now/ })).toBeDisabled()
    expect(screen.getAllByText(/The scan scope commitment is not ticked yet/).length).toBeGreaterThan(0)
    expect(screen.getByText(/Vedette scans no address until you set the scan scope and tick the commitment/)).toBeInTheDocument()
    as('u-admin')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(400)
    expect((await res.json()).error.code).toBe('commitment_required')
  })

  it('lỗi API hiện thông báo và nút thử lại', async () => {
    server.use(http.get('*/api/v1/scans/targets', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the device list.' } }, { status: 503 })))
    renderApp('/scans')
    expect(await screen.findByText('Could not read the device list.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('module quét tắt thì hiện ModuleOff', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    renderApp('/scans')
    expect(await screen.findByText('Vulnerability scan module is off')).toBeInTheDocument()
  })
})

describe('scan: API không bao giờ quét ngoài phạm vi (LEGAL §3)', () => {
  it('từ chối thiết bị chưa duyệt, tên miền chưa xác thực, mục lạ, danh sách rỗng, và quét chồng', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-op')
    const bad = await postRun(['a-unk01'])
    expect(bad.status).toBe(400)
    expect((await bad.json()).error.message).toMatch(/has not been approved in the inventory, so it cannot be scanned/)
    const ext = await postRun(['ext:xt-3'])
    expect(ext.status).toBe(400)
    expect((await ext.json()).error.message).toMatch(/has no verified ownership/)
    const old = await postRun(['ext:xt-4'])
    expect(old.status).toBe(400)
    expect((await old.json()).error.message).toMatch(/verification expired, verify again/)
    expect((await postRun(['192.168.99.1'])).status).toBe(400)
    expect((await postRun([])).status).toBe(400)
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
    timing.stepMs = 60_000
    expect((await postRun(['a-nas02'])).status).toBe(201)
    const again = await postRun(['a-web01'])
    expect(again.status).toBe(409)
    expect((await again.json()).error.code).toBe('already_running')
  })

  it('mục tiêu ngoài đã xác thực chưa được quét ở bản này: 400 out_of_scope nói rõ, không lượt nào bắt đầu', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-op')
    const targets = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; kind: string; selectable: boolean; reason: string | null }[]
    expect(targets.filter((x) => x.kind === 'external').every((x) => !x.selectable)).toBe(true)
    expect(targets.find((x) => x.id === 'ext:xt-2')!.reason).toBe('not_supported')
    const res = await postRun(['ext:xt-2'])
    expect(res.status).toBe(400)
    const err = (await res.json()).error
    expect(err.code).toBe('out_of_scope')
    expect(err.message).toMatch(/is an external target, and this version does not scan external targets yet, so it cannot be scanned/)
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
  })

  it('D-126, D-470: chọn tay là đồng ý cho thiết bị khai tay, mong manh, chưa phân loại và chính hộp; thiết bị "never" thì không bao giờ', async () => {
    const { ensureBox } = await import('@/features/inventory/mocks')
    ensureBox()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, origin: 'manual' as const } : a.id === 'a-unk01' ? { ...a, approved: true } : a)))
    as('u-admin')
    expect((await fetch(`${base()}/inventory/devices/a-srvad`, json('PATCH', { regular_scan: 'never' }))).status).toBe(200)
    renderApp('/scans')
    expect(await screen.findByRole('checkbox', { name: /WEB01/ })).toBeEnabled()
    const items = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; label: string; fragile: boolean; selectable: boolean; reason: string | null }[]
    const byId = (id: string) => items.find((x) => x.id === id)!
    expect(byId('a-web01')).toMatchObject({ selectable: true, reason: null }) // added by hand, picked by hand
    expect(byId('a-nas02')).toMatchObject({ selectable: true, fragile: true })
    expect(byId('a-unk01')).toMatchObject({ selectable: true, fragile: true }) // unknown kind counts as fragile: a quarter of the speed
    expect(byId('a-box')).toMatchObject({ selectable: true, pick_only: true, box: true, reason: null }) // D-470: a person may scan the box
    expect(byId('a-srvad')).toMatchObject({ selectable: false, reason: 'regular_scan_never' }) // "never" set by a person is absolute
    expect(screen.getByText(/^The Vedette box itself: pick it to scan it from the network/)).toBeInTheDocument()
    expect(screen.getAllByText('Set to never be scanned in the inventory').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    expect(screen.getByRole('checkbox', { name: new RegExp(`^${byId('a-box').label} `) })).not.toBeChecked() // Select all never ticks the box
    expect(screen.getByText(/need your own tick/)).toHaveTextContent(/need your own tick \([^)]*the Vedette box itself[^)]*\)/) // and says why
    as('u-op')
    expect((await (await postRun(['a-srvad'])).json()).error.message).toMatch(/is set to never be scanned in the inventory; change that setting first/)
    expect((await postRun(['a-box'])).status).toBe(201)
  })

  it('máy quét không sẵn sàng: can_scan=false kèm lý do, nút khoá, POST trả 503 scanner_unavailable', async () => {
    scannerStore.set({ available: false })
    renderApp('/scans')
    expect(await screen.findByRole('button', { name: /Scan now/ })).toBeDisabled()
    expect(screen.getAllByText(/The vulnerability scanner is not available: the scan container or its scanner is missing/).length).toBeGreaterThan(0)
    // the commitment is ticked, so the page must not blame it
    expect(screen.queryByText(/Vedette scans no address until you set the scan scope/)).not.toBeInTheDocument()
    const cfg = await (await fetch(`${base()}/scans/config`)).json()
    expect(cfg.can_scan).toBe(false)
    expect(cfg.block_reason).toMatch(/^The vulnerability scanner is not available/)
    as('u-op')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('scanner_unavailable')
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
  })

  it('no run history: the title and the schedule note blame the real reason, not always the commitment', async () => {
    runs.set([])
    scannerStore.set({ available: false })
    const view = renderApp('/scans')
    expect(await screen.findByRole('heading', { level: 1, name: 'Cannot scan: the vulnerability scanner is not available' })).toBeInTheDocument()
    view.unmount()
    renderApp('/scans?tab=safety')
    expect(await screen.findByText(/nothing runs while the vulnerability scanner is not available/)).toBeInTheDocument()
    expect(screen.queryByText(/until the scan scope commitment is ticked/)).not.toBeInTheDocument()
  })

  it('no run history and no commitment: the title and the schedule note ask for the commitment', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))
    runs.set([])
    const view = renderApp('/scans')
    expect(await screen.findByRole('heading', { level: 1, name: 'Cannot scan yet: confirm the scan scope first' })).toBeInTheDocument()
    view.unmount()
    renderApp('/scans?tab=safety')
    expect(await screen.findByText(/nothing runs until the scan scope commitment is ticked/)).toBeInTheDocument()
  })

  it('thiết bị nằm trong loại trừ cũng bị từ chối khi gọi thẳng API', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { exclusions: ['192.168.10.0/24'] }))
    const res = await postRun(['a-web01'])
    expect(res.status).toBe(400)
    expect((await res.json()).error.message).toMatch(/is on the exclusion list/)
  })
})

describe('scan: quét ngay, tiến độ, dừng ngay (S-SCAN-4)', () => {
  it('quét một thiết bị đến khi xong: ghi kết quả vào phát hiện dùng chung, kiểm toán, nhật ký probe', async () => {
    timing.stepMs = 30
    renderApp('/scans')
    await onlyTarget(/NAS-PHOTOS/)
    await userEvent.click(screen.getByRole('button', { name: 'Scan now (1)' }))
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const run = (await getRuns())[0]!
    expect(run.results.map((r) => r.result)).toContain('matched')
    expect(run.started_by).toBe('admin@acme.example')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.history.at(-1)!.action).toBe('rescanned')
    expect(auditStore.get().some((a) => a.action === 'scan.start')).toBe(true)
    const probes = (await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; ip: string }[]
    expect(probes.some((p) => p.run_id === run.id && p.ip === '192.168.10.21')).toBe(true)
    // xem kết quả có bằng chứng và link tới phát hiện
    await waitFor(() => expect(screen.getAllByRole('button', { name: /View results of the scan/ })[0]).toBeEnabled(), { timeout: 4000 })
    await userEvent.click(screen.getAllByRole('button', { name: /View results of the scan/ })[0]!)
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText('Matches, still vulnerable')).toBeInTheDocument()
    expect(within(dlg).getByText('http/cves/2022/CVE-2022-27593.yaml')).toBeInTheDocument()
    expect(within(dlg).getByRole('link', { name: 'Open finding' })).toHaveAttribute('href', '/findings/f-1')
    // D-501: Scan now identifies first and says per device what it found or exactly why not (the NAS is fragile: gentle scan only)
    expect(run.identification).toEqual([expect.objectContaining({ target_id: 'a-nas02', reason: 'gentle_only', found: [] })])
    expect(within(dlg).getByRole('heading', { name: 'What each device was identified as' })).toBeInTheDocument()
    expect(within(dlg).getByText('Gentle scan only')).toBeInTheDocument()
    expect(within(dlg).getByText(/only a gentle port scan ran, without version or operating system detection/)).toBeInTheDocument()
  })

  it('đã giảm thiểu rồi quét lại: không có khớp chỉ là "không báo khớp", không đổi gì ở phát hiện (D-133 (5))', async () => {
    timing.stepMs = 30
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'mitigated' as const } : f)))
    const before = findingsStore.get().find((x) => x.id === 'f-1')!.history.length
    renderApp('/scans?target=a-nas02')
    await userEvent.click(await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })) // fragile: the link does not tick it, the person does
    await userEvent.click(screen.getByRole('button', { name: 'Scan now (1)' }))
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const res = (await getRuns())[0]!.results[0]!
    expect(res.result).toBe('not_matched')
    expect(res.note).toBe('CVE-2022-27593: no match reported by the scan template.')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('mitigated')
    expect(f.history).toHaveLength(before) // nuclei reports matches only: "no match" never marks the finding
    await waitFor(() => expect(screen.getAllByRole('button', { name: /View results of the scan/ })[0]).toBeEnabled(), { timeout: 4000 })
    await userEvent.click(screen.getAllByRole('button', { name: /View results of the scan/ })[0]!)
    expect(within(await screen.findByRole('dialog')).getByText('No match reported')).toBeInTheDocument()
  })

  it('"Dừng ngay": đang chạy hiện tiến độ, bấm dừng thì thấy "Đang dừng" rồi "Đã dừng" trong 5 giây, thiết bị chưa quét không bị chạm', async () => {
    timing.stepMs = 60_000
    timing.stopMs = 300
    renderApp('/scans')
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now (2)' }))
    const bar = await screen.findByRole('progressbar', { name: 'Scan progress' })
    expect(bar).toHaveAttribute('aria-valuenow', '0')
    expect(await screen.findByRole('heading', { level: 1, name: 'Scanning: 0/2 devices done' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    expect(screen.getByText(/Scanning NAS-PHOTOS|Scanning WEB01|Scanning SRV-AD/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Stop now' }))
    expect(await screen.findByRole('button', { name: 'Stopping' })).toBeDisabled()
    const t0 = Date.now()
    await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: /Last scan was stopped .*: 0\/2 devices done/ })).toBeInTheDocument(), { timeout: 5000 })
    expect(Date.now() - t0).toBeLessThan(5000)
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.getAllByText('You pressed Stop now.').length).toBeGreaterThan(0)
    const run = (await getRuns())[0]!
    expect(run.status).toBe('stopped')
    expect(run.results.every((r) => r.result === 'skipped')).toBe(true)
    // the device being scanned when Stop now came: its requests on the way are in the probe log as stopped; the others have none
    const probes = ((await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; result: string }[]).filter((p) => p.run_id === run.id)
    expect(probes.length).toBeGreaterThan(0)
    expect(probes.every((p) => p.result === 'stopped')).toBe(true)
    expect(findingsStore.get().find((x) => x.id === 'f-1')!.history.some((h) => h.action === 'rescanned')).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scan.stop')).toBe(true)
    expect(screen.getByRole('button', { name: /Scan now/ })).toBeEnabled()
  })

  it('dừng lần quét đã kết thúc báo lỗi rõ; dừng hai lần không lỗi', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-op')
    const seeded = (await getRuns())[0]!
    const res = await fetch(`${base()}/scans/runs/${seeded.id}/stop`, json('POST', {}))
    expect(res.status).toBe(409)
    expect((await res.json()).error.code).toBe('not_running')
    expect((await fetch(`${base()}/scans/runs/run-nope/stop`, json('POST', {}))).status).toBe(404)
    timing.stepMs = 60_000
    timing.stopMs = 60_000
    const run = (await (await postRun(['a-nas02'])).json()) as ScanRun
    expect((await fetch(`${base()}/scans/runs/${run.id}/stop`, json('POST', {}))).status).toBe(200)
    expect((await fetch(`${base()}/scans/runs/${run.id}/stop`, json('POST', {}))).status).toBe(200)
    expect((await getRuns())[0]!.status).toBe('stopping')
  })

  it('thiết bị không phản hồi: bật tự dừng thì dừng kèm lý do; tắt thì bỏ qua và quét tiếp', async () => {
    timing.stepMs = 30
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-op')
    await postRun(['a-web01', 'a-cam03', 'a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('auto_stopped'), { timeout: 4000 })
    const stopped = (await getRuns())[0]!
    expect(stopped.stop_reason).toMatch(/CAM-LOBBY \(192\.168\.20\.13\) stopped responding after 3 failed requests/)
    expect(stopped.done).toBe(1)
    expect(stopped.results.find((r) => r.label === 'NAS-PHOTOS')!.result).toBe('skipped')
    expect(stopped.results.find((r) => r.label === 'CAM-LOBBY')!.result).toBe('no_response')
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { stop_on_unresponsive: false }))
    await postRun(['a-web01', 'a-cam03', 'a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const full = (await getRuns())[0]!
    expect(full.results.map((r) => r.result)).toContain('no_response')
    expect(full.results.find((r) => r.label === 'NAS-PHOTOS')!.result).toBe('matched')
  })

  it('vai chỉ xem không quét và không dừng được', async () => {
    renderApp('/scans', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: /Scan now/ })).toBeDisabled()
    expect(screen.getAllByText('Requires Operator role').length).toBeGreaterThan(0)
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(403)
  })

  it('D-126 (2): the seeded scheduled and KEV runs, and the seeded rescan matches, never touch a device that needs a hand pick', async () => {
    renderApp('/scans')
    await screen.findByRole('table', { name: 'History of scans' })
    const targets = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; label: string; pick_only: boolean }[]
    const pick = targets.filter((x) => x.pick_only)
    expect(pick.length).toBeGreaterThan(0)
    const auto = (await getRuns()).filter((r) => r.trigger !== 'manual')
    expect(auto.map((r) => r.trigger).sort()).toEqual(['new_kev', 'schedule'])
    for (const r of auto) expect(r.results.map((x) => x.target_id).filter((id) => pick.some((p) => p.id === id)), r.id).toEqual([])
    const events = ((await (await fetch(`${base()}/scans/events`)).json()) as { items: { result: string; devices: string[] }[] }).items
    for (const e of events.filter((x) => x.result === 'matched')) expect(e.devices.filter((d) => pick.some((p) => p.label === d))).toEqual([])
  })

  it('lịch sử liệt kê lần quét theo lịch, theo KEV mới và lần đã dừng', async () => {
    renderApp('/scans')
    const table = await screen.findByRole('table', { name: 'History of scans' })
    expect(within(table).getByText('On schedule')).toBeInTheDocument()
    expect(within(table).getByText('New KEV with a template')).toBeInTheDocument()
    expect(within(table).getByText('Stopped')).toBeInTheDocument()
    await userEvent.click(within(table).getAllByRole('button', { name: /View results of the scan/ })[2]!)
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText('You pressed Stop now.')).toBeInTheDocument()
    expect(within(dlg).getAllByText('Not scanned').length).toBeGreaterThan(0)
    await expectNoA11yViolations(dlg)
  })
})

describe('scan: lịch và an toàn (S-SCAN-4)', () => {
  it('hiện thiết lập hiện tại, lần quét kế tiếp, và ghi rõ không khai thác, không DoS; không lỗi a11y', async () => {
    renderApp('/scans?tab=safety')
    expect(await screen.findByLabelText('From')).toHaveValue('22:00')
    expect(screen.getByLabelText('Until')).toHaveValue('05:00')
    expect(screen.getByLabelText('Speed')).toHaveValue('5')
    expect(screen.getByLabelText('One IP or network per line')).toHaveValue('192.168.10.240')
    expect(screen.getByText('No exploitation, no denial of service')).toBeInTheDocument()
    expect(screen.getByText(/Never guesses passwords/)).toBeInTheDocument()
    expect(screen.getByText(/Next scan: /)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Stop automatically when a device does not respond' })).toBeChecked()
    await expectNoA11yViolations()
  })

  it('lưu tốc độ và loại trừ: lưu bền, ghi kiểm toán, còn sau khi mở lại', async () => {
    const view = renderApp('/scans?tab=safety')
    await userEvent.selectOptions(await screen.findByLabelText('Speed'), '2')
    const ex = screen.getByLabelText('One IP or network per line')
    await userEvent.clear(ex)
    await userEvent.type(ex, '192.168.10.250{enter}192.168.20.0/24')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Scan settings saved')).toBeInTheDocument()
    const cfg = (await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig
    expect(cfg.rate).toBe(2)
    expect(cfg.exclusions).toEqual(['192.168.10.250', '192.168.20.0/24'])
    expect(auditStore.get().some((a) => a.action === 'scan.config')).toBe(true)
    view.unmount()
    renderApp('/scans?tab=safety')
    expect(await screen.findByLabelText('Speed')).toHaveValue('2')
  })

  it('loại trừ sai nói rõ dòng nào và sửa thế nào', async () => {
    renderApp('/scans?tab=safety')
    const ex = await screen.findByLabelText('One IP or network per line')
    await userEvent.type(ex, '{enter}may-in')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Line 2: "may-in" is not an IP or network range')
    expect(alert).toHaveTextContent('For example 192.168.10.5')
  })

  it('ngày trong tuần là 1 đến 7 (Thứ Hai = 1, Chủ Nhật = 7), ô chọn ngày chỉ mở khi lịch hằng tuần (D-57)', async () => {
    renderApp('/scans?tab=safety')
    const freq = await screen.findByLabelText('Frequency')
    const day = screen.getByLabelText('Day of the week') as HTMLSelectElement
    const opts = [...day.options].map((o) => [o.value, o.textContent])
    expect(opts).toEqual([['1', 'Monday'], ['2', 'Tuesday'], ['3', 'Wednesday'], ['4', 'Thursday'], ['5', 'Friday'], ['6', 'Saturday'], ['7', 'Sunday']])
    await eachOption([
      { option: 'daily', locked: ['Day of the week'] },
      { option: 'weekly', shown: ['Day of the week'] },
      { option: 'daily', locked: ['Day of the week'] },
    ], async (o) => { await userEvent.selectOptions(freq, o) })
    expect(screen.getAllByRole('checkbox', { name: /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/ }).map((c) => c.getAttribute('id'))).toEqual(['day-1', 'day-2', 'day-3', 'day-4', 'day-5', 'day-6', 'day-7'])
    as('u-admin')
    const put = (b: unknown) => fetch(`${base()}/scans/config`, json('PUT', b))
    expect((await put({ window: { days: [0] } })).status).toBe(400) // the old Sunday = 0 is refused
    expect((await put({ window: { days: [8] } })).status).toBe(400)
    expect((await put({ schedule: { weekday: 0 } })).status).toBe(400)
    expect((await put({ schedule: { frequency: 'weekly', weekday: 7 } })).status).toBe(200)
    expect(((await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig).schedule.weekday).toBe(7)
  })

  it('giờ chạy lịch phải nằm trong cửa sổ giờ', async () => {
    renderApp('/scans?tab=safety')
    const at = await screen.findByLabelText('Run at')
    await userEvent.clear(at)
    await userEvent.type(at, '12:00')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The schedule time 12:00 is outside the 22:00 to 05:00 window')
  })

  it('API kiểm tra ở biên và không cho bật phép thử nguy hiểm', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    as('u-admin')
    const put = (b: unknown) => fetch(`${base()}/scans/config`, json('PUT', b))
    const danger = await put({ dangerous_checks: true })
    expect(danger.status).toBe(400)
    expect((await danger.json()).error.message).toMatch(/no exploitation, no denial of service/)
    expect((await put({ window: { days: [] } })).status).toBe(400)
    expect((await put({ window: { from: '22:00', to: '22:00' } })).status).toBe(400)
    expect((await put({ window: { from: '25:00' } })).status).toBe(400)
    expect((await put({ rate: 500 })).status).toBe(400)
    expect((await put({ unresponsive_after: 1 })).status).toBe(400)
    expect((await put({ schedule: { frequency: 'monthly' } })).status).toBe(400)
    expect((await put({ exclusions: ['1.2.3.4/99'] })).status).toBe(400)
    expect((await put({ rate: 10 })).status).toBe(200)
  })

  it('vai vận hành xem được nhưng không đổi được thiết lập', async () => {
    renderApp('/scans?tab=safety', { role: 'operator' })
    expect(await screen.findByText(/Only an administrator can change these settings/)).toBeInTheDocument()
    expect(screen.getByLabelText('Speed')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect((await fetch(`${base()}/scans/config`, json('PUT', { rate: 1 }))).status).toBe(403)
  })

  it('tính lần quét kế tiếp theo lịch hằng ngày, hằng tuần và khi tắt', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'daily', weekday: 7, at: '23:00' } }
    const now = new Date(2026, 10, 6, 12, 0) // thứ Sáu
    expect(new Date(nextRun(c, now)!).getDate()).toBe(6)
    expect(new Date(nextRun(c, now)!).getHours()).toBe(23)
    expect(new Date(nextRun(c, new Date(2026, 10, 6, 23, 30))!).getDate()).toBe(7)
    expect(new Date(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 7 } }, now)!).getDay()).toBe(0) // 7 = Sunday (D-57)
    expect(new Date(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 1 } }, now)!).getDay()).toBe(1) // 1 = Monday
    expect(nextRun({ ...c, schedule: { ...c.schedule, enabled: false } }, now)).toBeNull()
    expect(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 3 }, window: { ...c.window, days: [1] } }, now)).toBeNull()
  })

  it('the first scheduled run is the next window of any window day, not the weekly weekday (W3-6)', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'weekly', weekday: 7, at: '23:00' } }
    const fri = new Date(2026, 10, 13, 14, 40) // the walk: Friday 13 Nov 14:40
    const first = new Date(nextRun(c, fri, true)!)
    expect([first.getDate(), first.getHours()]).toEqual([13, 23])
    expect(new Date(nextRun(c, fri, false)!).getDate()).toBe(15) // once a scheduled run happened: the weekly Sunday
  })

  it('a window that crosses midnight counts by its start day: a 02:00 slot belongs to the day before (#164 review M1)', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'daily', weekday: 1, at: '02:00' } }
    const fri = new Date(nextRun(c, new Date(2026, 10, 20, 12, 0))!) // Friday noon: Saturday 02:00 is Friday's window
    expect([fri.getDate(), fri.getHours()]).toEqual([21, 2])
    const sun = new Date(nextRun(c, new Date(2026, 10, 22, 12, 0))!) // Sunday noon: Monday 02:00 is Sunday's window, so Tuesday
    expect(sun.getDate()).toBe(24)
  })
})

describe('scan: tự quét lại khi có KEV mới (S-SCAN-2)', () => {
  it('nhật ký sự kiện từ KEV thật, CVE nối về trang tra cứu; không lỗi a11y', async () => {
    renderApp('/scans?tab=auto')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(within(table).getAllByRole('link', { name: /^CVE-/ })[0]!.getAttribute('href')).toMatch(/^\/cve\/CVE-/)
    expect(within(table).getAllByText('Matches, alerted').length).toBeGreaterThan(0)
    expect(within(table).getByText('Not scanned: no matching device')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' })).toBeChecked()
    await expectNoA11yViolations()
  })

  it('a rescan with no match says "No match reported" in a neutral tone, never "Not affected" (D-133 (5))', async () => {
    const ev = { id: 'ev-clear', ts: new Date().toISOString(), cve: 'CVE-2026-0002', product: 'Acme NAS', devices: ['nas02'], latency_min: 12, run_id: 'run-1', result: 'clear' }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ items: [ev], auto_rescan: true })))
    renderApp('/scans?tab=auto')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const chip = await within(table).findByText('No match reported')
    expect(chip.className).toContain('text-off')
    expect(within(table).queryByText('Not affected')).toBeNull()
  })

  it('D-145 (7): devices that need a hand pick are named with a link to Scan now; a stopped rescan links to its run', async () => {
    const base = { ts: new Date().toISOString(), product: 'Acme NAS', latency_min: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base, id: 'ev-pick', cve: 'CVE-2026-0003', devices: ['NAS-PHOTOS', 'CAM-03'], run_id: null, result: 'pick_only' },
      { ...base, id: 'ev-stop', cve: 'CVE-2026-0004', devices: ['WEB01'], latency_min: 4, run_id: 'run-seed-3', result: 'stopped' },
    ] })))
    renderApp('/scans?tab=auto')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const pick = await within(table).findByText(/^Not scanned automatically: 2 devices need a hand pick in/)
    expect(pick.className).toContain('text-off')
    expect(within(table).getByText('NAS-PHOTOS, CAM-03')).toBeInTheDocument()
    expect(within(table).getByRole('link', { name: 'Scan now' })).toHaveAttribute('href', '/scans?tab=runs')
    expect(within(table).getByText(/^Stopped before the end:/).className).toContain('text-off')
    await expectNoA11yViolations()
    await userEvent.click(within(table).getByRole('link', { name: 'see the run' }))
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText('You pressed Stop now.')).toBeInTheDocument()
  })

  it('D-261 (2): a rescan dropped after 7 days stays in the log with the reason', async () => {
    const base0 = { ts: new Date().toISOString(), product: 'Acme NAS', devices: [], latency_min: null, run_id: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base0, id: 'ev-a', cve: 'CVE-2026-0006', result: 'expired_no_template' },
      { ...base0, id: 'ev-b', cve: 'CVE-2026-0007', result: 'expired_scanner' },
      { ...base0, id: 'ev-c', cve: 'CVE-2026-0008', result: 'expired_zone' },
    ] })))
    renderApp('/scans?tab=auto')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect((await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).className).toContain('text-off')
    expect(within(table).getByText('Not scanned for 7 days: the scanner was not available')).toBeInTheDocument()
    expect(within(table).getByText('Not scanned for 7 days: the time zone of the organization could not be read')).toBeInTheDocument()
    expect(within(table).queryByText('No matching device')).toBeNull()
    await expectNoA11yViolations()
  })

  it('D-261 (2): the seed has a dropped event with its reason', async () => {
    renderApp('/scans?tab=auto')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).toBeInTheDocument()
  })

  it('D-261 (3): the schedule says why nothing starts while the time zone cannot be read, not "off"', async () => {
    zoneStore.set({ readable: false })
    renderApp('/scans?tab=safety')
    const cfg = await (await fetch(`${base()}/scans/config`)).json()
    expect(cfg.next_run).toBeNull()
    expect(cfg.schedule_blocked_reason).toMatch(/time zone of the organization cannot be read/)
    expect((await screen.findAllByText(/The schedule is on, but the time zone of the organization cannot be read/)).length).toBeGreaterThan(0)
    expect(screen.queryByText('The schedule is off.')).toBeNull()
    expect(screen.getAllByText(/on hold, the time zone cannot be read/).length).toBeGreaterThan(0)
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { schedule: { enabled: false } }))
    expect((await (await fetch(`${base()}/scans/config`)).json()).schedule_blocked_reason).toBeNull()
  })

  it('D-261 (4): after Stop now, while the scanner is still busy, Scan now is locked with the reason and a start is refused', async () => {
    engineStore.set({ busyUntil: Date.now() + 60_000 })
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    expect(await screen.findByRole('button', { name: /Scan now/ })).toBeDisabled()
    expect(screen.getAllByText(/The scanner is still finishing the scan you stopped/).length).toBeGreaterThan(0)
    expect((await (await fetch(`${base()}/scans/runs`)).json()).engine_busy).toBe(true)
    as('u-op')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(409)
    expect((await res.json()).error.code).toBe('already_running')
    engineStore.set({ busyUntil: 0 })
    expect((await (await fetch(`${base()}/scans/runs`)).json()).engine_busy).toBe(false)
    expect((await postRun(['a-nas02'])).status).toBe(201)
  })

  it('quản trị tắt được, có ghi chú giải thích; vận hành thì không', async () => {
    const view = renderApp('/scans?tab=auto')
    await userEvent.click(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' }))
    expect(await screen.findByText(/Off: new vulnerabilities will not be rescanned automatically/)).toBeInTheDocument()
    expect(((await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig).auto_rescan).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scan.config')).toBe(true)
    view.unmount()
    renderApp('/scans?tab=auto', { role: 'operator' })
    expect(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' })).toBeDisabled()
  })
})

describe('scan: nhật ký probe (S-SCAN-4)', () => {
  it('liệt kê đích, thời điểm, mẫu; ghi rõ giữ tối thiểu 90 ngày; lọc được; tải CSV', async () => {
    renderApp('/scans?tab=probes')
    const table = await screen.findByRole('table', { name: 'Probe log' })
    expect(await screen.findByText(/Kept for at least 90 days\. \d+ lines now, oldest from/)).toBeInTheDocument()
    expect(within(table).getAllByText('NAS-PHOTOS').length).toBeGreaterThan(0)
    expect(within(table).getAllByText('http/cves/2022/CVE-2022-27593.yaml').length).toBeGreaterThan(0)
    const rows = within(table).getAllByRole('row').length
    await userEvent.type(screen.getByRole('textbox', { name: 'Filter by target, template, result' }), 'CAM-LOBBY')
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row').length).toBeLessThan(rows))
    const csv = await fetch(`${base()}/scans/probes.csv`)
    expect(csv.headers.get('Content-Disposition')).toContain('attachment; filename=vedette-probe-log.csv')
    expect((await csv.text()).split('\n')[0]).toBe('time,target,name,template,request,result')
    await expectNoA11yViolations()
  })

  it('CSV không để bảng tính đọc tên thiết bị như công thức (tên đến từ mạng)', async () => {
    timing.stepMs = 30
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, hostname: '=HYPERLINK("http://x","y")' } : a)))
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /HYPERLINK/ })
    as('u-op')
    await postRun(['a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const lines = (await (await fetch(`${base()}/scans/probes.csv`)).text()).split('\n')
    expect(lines.some((l) => l.includes(`"'=HYPERLINK(""http://x"",""y"")"`))).toBe(true)
    expect(lines.some((l) => /,"=/.test(l))).toBe(false)
  })

  it('seed giữ bản ghi cũ hơn 80 ngày (không xoá trước 90 ngày)', async () => {
    renderApp('/scans')
    await screen.findByRole('checkbox', { name: /NAS-PHOTOS/ })
    const items = (await (await fetch(`${base()}/scans/probes`)).json()) as { items: { ts: string }[]; retention_days: number }
    expect(items.retention_days).toBe(90)
    expect(Date.now() - Date.parse(items.items.at(-1)!.ts)).toBeGreaterThan(80 * 864e5)
  })
})

const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD1234567890abcdefGHIJKLMNOPQRSTUVWXYZQk2f\n-----END OPENSSH PRIVATE KEY-----'

describe('scan: quét có tài khoản (S-SCAN-5)', () => {
  const enable = () => modulesStore.update((l) => l.map((m) => (m.id === 'scan-credentialed' ? { ...m, enabled: true } : m)))

  it('v1 offers no Credentialed scan tab: the feature has no backend in this build (D-417, walk-1 W1-36)', async () => {
    credFlag.CREDENTIALED_IN_UI = false
    try {
      enable()
      renderApp('/scans')
      expect(await screen.findByRole('tab', { name: 'Schedule and safety' })).toBeInTheDocument()
      expect(screen.queryByRole('tab', { name: 'Credentialed scan' })).toBeNull()
    } finally { credFlag.CREDENTIALED_IN_UI = true }
  })

  it('module tắt mặc định thì nói rõ và chỉ chỗ bật', async () => {
    renderApp('/scans?tab=credentialed')
    expect(await screen.findByText('Credentialed scan module is off')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open module settings' })).toHaveAttribute('href', '/settings/modules')
  })

  it('hiện hướng dẫn chuẩn bị máy đích, mỗi lệnh một khung; không lỗi a11y', async () => {
    enable()
    renderApp('/scans?tab=credentialed')
    expect(await screen.findByText('No server is scanned with an account yet.')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Prepare a Linux target (Debian, Ubuntu)'))
    const codes = [...document.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain('ssh-keygen -t ed25519 -f vedette_scan_key -C "vedette-scan" -N ""')
    expect(codes).toContain('sudo adduser --disabled-password --gecos "" vedette-scan')
    await expectNoA11yViolations()
  })

  it('thêm máy chủ với khoá riêng: chỉ hiện 4 ký tự cuối, khoá không được lưu hay trả lại; kiểm tra kết nối; xoá', async () => {
    enable()
    renderApp('/scans?tab=credentialed')
    await userEvent.selectOptions(await screen.findByLabelText('Target server'), 'a-web01')
    const key = screen.getByLabelText('SSH private key')
    await userEvent.click(key)
    await userEvent.paste(KEY)
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    expect(await screen.findByText('Key saved, ends with ••••Qk2f')).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Servers scanned with an account' })
    expect(within(table).getByText('ends with ••••Qk2f')).toBeInTheDocument()
    expect(within(table).getByText('vedette-scan@192.168.10.12:22')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('b3BlbnNzaC1rZXktdjEAAAAABG5v')
    const list = await (await fetch(`${base()}/scans/credentialed`)).text()
    expect(list).not.toContain('b3BlbnNzaC1rZXktdjE')
    expect(list).not.toContain('PRIVATE KEY')
    const { collection } = await import('@/mocks/db')
    expect(JSON.stringify(collection('scc_target', () => []).get())).not.toContain('b3BlbnNzaC1rZXktdjE')
    expect(auditStore.get().some((a) => a.action === 'scan.credentialed.add')).toBe(true)

    await userEvent.click(within(table).getByRole('button', { name: 'Check connection to WEB01' }))
    expect(await within(table).findByText('Connected')).toBeInTheDocument()
    expect(within(table).getByText(/the target accepted the key ending in Qk2f/)).toBeInTheDocument()

    await userEvent.click(within(table).getByRole('button', { name: 'Remove the scan account of WEB01' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove the scan account of WEB01?' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Remove' }))
    expect(await screen.findByText('No server is scanned with an account yet.')).toBeInTheDocument()
  })

  it('thử kết nối thất bại nói rõ phải kiểm tra gì', async () => {
    enable()
    renderApp('/scans?tab=credentialed')
    await userEvent.selectOptions(await screen.findByLabelText('Target server'), 'a-srvad')
    await userEvent.click(screen.getByLabelText('SSH private key'))
    await userEvent.paste(KEY)
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    const table = await screen.findByRole('table', { name: 'Servers scanned with an account' })
    await userEvent.click(within(table).getByRole('button', { name: 'Check connection to SRV-AD' }))
    expect(await within(table).findByText('Cannot connect')).toBeInTheDocument()
    expect(within(table).getByText(/Check that the SSH service is running and the firewall allows the Vedette box 192\.168\.10\.250/)).toBeInTheDocument()
  })

  it('kiểm tra ở biên: khoá công khai, khoá sai, cổng, tài khoản, trùng, ngoài phạm vi', async () => {
    enable()
    renderApp('/scans?tab=credentialed')
    await screen.findByLabelText('Target server')
    as('u-admin')
    const add = (b: object) => fetch(`${base()}/scans/credentialed`, json('POST', { asset_id: 'a-web01', port: 22, username: 'vedette-scan', private_key: KEY, ...b }))
    const pub = await add({ private_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc vedette' })
    expect(pub.status).toBe(400)
    expect((await pub.json()).error.message).toMatch(/This is a public key/)
    expect((await (await add({ private_key: 'abc' })).json()).error.code).toBe('bad_key')
    expect((await add({ private_key: 'x'.repeat(17_000) })).status).toBe(400)
    expect((await (await add({ port: 70000 })).json()).error.code).toBe('bad_port')
    expect((await (await add({ username: 'Root User' })).json()).error.code).toBe('bad_username')
    expect((await (await add({ asset_id: 'a-unk01' })).json()).error.message).toMatch(/has not been approved/)
    expect((await (await add({ asset_id: 'ext:acme.example' })).json()).error.code).toBe('unknown_host')
    expect((await add({})).status).toBe(201)
    expect((await add({})).status).toBe(409)
  })

  it('vai vận hành thử kết nối được nhưng không thêm hay xoá; chỉ xem thì không làm gì', async () => {
    enable()
    renderApp('/scans?tab=credentialed', { role: 'operator' })
    expect(await screen.findByRole('button', { name: 'Save key' })).toBeDisabled()
    expect(screen.getByLabelText('SSH private key')).toBeDisabled()
    expect(screen.getByText('Requires Admin role')).toBeInTheDocument()
    as('u-view')
    expect((await fetch(`${base()}/scans/credentialed`, json('POST', { asset_id: 'a-web01', port: 22, username: 'x', private_key: KEY }))).status).toBe(403)
  })

  it('tệp khoá được đọc bằng bộ chọn tệp', async () => {
    enable()
    renderApp('/scans?tab=credentialed')
    await screen.findByLabelText('Target server')
    const input = screen.getByLabelText('SSH private key file') as HTMLInputElement
    await userEvent.upload(input, new File([KEY], 'vedette_scan_key', { type: 'text/plain' }))
    expect(await screen.findByText('Read file vedette_scan_key')).toBeInTheDocument()
  })
})

describe('scan: target picker with 500 devices (S-SCAN-4, D-472)', () => {
  type T = { id: string; label: string; ip: string; selectable: boolean; pick_only: boolean }
  const big = () => {
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: ['192.168.0.0/16'] }))
    assetsStore.update((l) => [...l, ...manyAssets(470)])
  }
  const items = async () => ((await (await fetch(`${base()}/scans/targets`)).json()) as { items: T[] }).items
  const devices = () => screen.getByRole('list', { name: 'Devices in the inventory' })
  const start = async () => {
    renderApp('/scans')
    await screen.findByRole('button', { name: 'Select all' })
    await userEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
  }

  it('groups by subnet with 50 rows a page; search finds a device by name, IP, MAC or vendor', async () => {
    big()
    await start()
    const total = (await items()).filter((x) => x.id.startsWith('a-')).length
    expect(total).toBeGreaterThanOrEqual(500)
    expect(screen.getByText(`${total} devices in the inventory`)).toBeInTheDocument()
    expect(within(devices()).getAllByRole('checkbox').filter((c) => c.id.startsWith('tg-')).length).toBeLessThanOrEqual(50)
    expect(screen.getByRole('button', { name: /^192\.168\.10\.0\/24/ })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(/^Page 1 of 1\d$/)).toBeInTheDocument()
    const search = screen.getByRole('searchbox', { name: 'Search devices' })
    for (const q of ['PC-120', '192.168.40.121', '3c:52:82:00:78']) {
      await userEvent.clear(search)
      await userEvent.type(search, q)
      expect(await screen.findByRole('checkbox', { name: /^PC-120 192\.168\.40\.121$/ })).toBeInTheDocument()
      expect(screen.getByText(`1 of ${total} devices match`)).toBeInTheDocument()
    }
    await userEvent.clear(search)
    await userEvent.type(search, 'synology')
    expect(screen.getByText(`48 of ${total} devices match`)).toBeInTheDocument() // 47 generated + the seed's NAS-BACKUP
    // a collapsed group keeps only its header
    await userEvent.clear(search)
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Subnet' }), '192.168.41.0/24')
    const head = screen.getByRole('button', { name: /^192\.168\.41\.0\/24/ })
    await userEvent.click(head)
    expect(head).toHaveAttribute('aria-expanded', 'false')
    expect(within(devices()).queryAllByRole('checkbox').filter((c) => c.id.startsWith('tg-'))).toHaveLength(0)
  })

  it('the selection survives paging, search and filters; Show selected lists exactly it', async () => {
    big()
    await start()
    await userEvent.click(screen.getByRole('checkbox', { name: /^SRV-AD / }))
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    const far = await screen.findAllByRole('checkbox', { name: /^PC-\d+ / })
    const pick = far.find((c) => !(c as HTMLButtonElement).disabled)!
    const name = pick.getAttribute('id')!
    await userEvent.click(pick)
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search devices' }), 'nothing-like-this')
    expect(screen.getByText('No device matches the search and filters.')).toBeInTheDocument()
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: 'Clear filters' })[0]!)
    await userEvent.click(screen.getByRole('button', { name: 'Show selected' }))
    const shown = within(devices()).getAllByRole('checkbox').filter((c) => c.id.startsWith('tg-'))
    expect(shown.map((c) => c.id).sort()).toEqual(['tg-a-srvad', name].sort())
    expect(shown.every((c) => c.getAttribute('data-state') === 'checked')).toBe(true)
    expect(screen.getByRole('button', { name: 'Scan now (2)' })).toBeEnabled()
  })

  it('Select all on a filter ticks only devices that need no own tick and says how many do; Show them lists those, unticked', async () => {
    big()
    await start()
    const list = (await items()).filter((x) => x.ip.startsWith('192.168.40.'))
    const ok = list.filter((x) => x.selectable && !x.pick_only).length
    const tick = list.filter((x) => x.selectable && x.pick_only).length
    const no = list.filter((x) => !x.selectable).length
    expect([ok > 0, tick > 0, no > 0]).toEqual([true, true, true])
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Subnet' }), '192.168.40.0/24')
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    const status = screen.getByText(`Selected ${ok} devices.`, { exact: false })
    expect(status).toHaveTextContent(new RegExp(`${tick} need your own tick \\(\\d+ (type unknown|fragile|added by hand)(, \\d+ (type unknown|fragile|added by hand))*\\): Show them ${no} cannot be scanned \\(\\d+ not approved.*\\); each row says why\\. Approve devices on the Devices page`))
    expect(screen.getByText(`${ok} selected`)).toBeInTheDocument()
    await userEvent.click(within(status).getByRole('button', { name: 'Show them' }))
    expect(screen.getByRole('combobox', { name: 'Show' })).toHaveValue('pick')
    const rows = within(devices()).getAllByRole('checkbox').filter((c) => c.id.startsWith('tg-'))
    expect(rows.length).toBe(Math.min(tick, 49)) // a page is 50 rows, the subnet header included
    expect(rows.every((c) => c.getAttribute('data-state') === 'unchecked' && !(c as HTMLButtonElement).disabled)).toBe(true)
    // D-126 (2): there is no bulk tick for them, the person ticks each one
    await userEvent.click(rows[0]!)
    expect(screen.getByText(`${ok + 1} selected`)).toBeInTheDocument()
  })

  it('W2-5: on a fresh box Select all ticks 0 and says why, by cause, with Show them', async () => {
    // a fresh box: nothing classified yet, two devices not approved
    assetsStore.update((l) => l.map((a, i) => ({ ...a, kind: 'unknown' as const, fragile: false, origin: 'discovered' as const, approved: i > 1 })))
    await start()
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    const status = screen.getByText(/^Selected 0 devices\./)
    const n = (await items()).filter((x) => x.selectable && x.pick_only).length
    expect(status).toHaveTextContent(`Selected 0 devices. ${n} need your own tick (${n} type unknown): Show them 2 cannot be scanned (2 not approved); each row says why. Approve devices on the Devices page`)
    expect(within(status).getByRole('link', { name: 'Approve devices on the Devices page' })).toHaveAttribute('href', '/devices')
    await userEvent.click(within(status).getByRole('button', { name: 'Show them' }))
    expect(screen.getByText(`${n} of ${n + 2} devices match`)).toBeInTheDocument()
  })

  it('the group checkbox ticks its subnet like Select all; ticked again it clears the group', async () => {
    big()
    await start()
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Subnet' }), '192.168.41.0/24')
    const group = screen.getByRole('checkbox', { name: 'Select the devices in 192.168.41.0/24 that need no tick of your own' })
    await userEvent.click(group)
    expect(group).toHaveAttribute('data-state', 'indeterminate') // the fragile and unknown rows still wait for a tick of their own
    expect(screen.getByText(/^Selected \d+ devices\./)).toBeInTheDocument()
    await userEvent.click(group)
    expect(group).toHaveAttribute('data-state', 'unchecked')
    expect(screen.getByText('0 selected')).toBeInTheDocument()
  })

  it('more than 200 selected locks Scan now and names the limit', async () => {
    big()
    await start()
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }))
    const n = (await items()).filter((x) => x.selectable && !x.pick_only).length
    expect(n).toBeGreaterThan(200)
    expect(screen.getByRole('button', { name: `Scan now (${n})` })).toBeDisabled()
    expect(screen.getByText(`A scan can include at most 200 devices; ${n} are selected. Narrow the selection, then scan the rest in a second run.`)).toBeInTheDocument()
  })

  it('beta item 27: "Only devices with findings" shows those devices and says why none was ticked when each needs a hand pick', async () => {
    // kien's box: the devices with findings were added by hand, so the button ticked nothing and said nothing
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' || a.id === 'a-srvad' ? { ...a, origin: 'manual' as const } : a)))
    await start()
    await userEvent.click(screen.getByRole('button', { name: 'Only devices with findings' }))
    expect(screen.getByRole('combobox', { name: 'Show' })).toHaveValue('findings')
    expect(screen.getByRole('checkbox', { name: /^WEB01 / })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /^NAS-PHOTOS / })).toBeInTheDocument()
    expect(screen.getByText(/^Selected 0 devices\./)).toHaveTextContent(/^Selected 0 devices\. \d+ need your own tick/)
    expect(screen.getByText('0 selected')).toBeInTheDocument()
  })

  it('beta item 27, D-484: a product added by hand without an address is named "<product> (no device)" (D-471), says "no IP" and links to its device', async () => {
    assetsStore.update((l) => [{ ...l.find((a) => a.id === 'a-web01')!, id: 'a-office', ip: '—', mac: null, hostname: null, kind: 'unknown' as const, origin: 'manual' as const, model: null,
      vendor: { value: 'Microsoft', source: 'manual' as const, confidence: 1, seen_at: new Date().toISOString() },
      software: [{ id: 's-off', display: 'Microsoft Office', vendor: 'Microsoft', product: 'Office', version: null, kev: [], source: 'manual' as const, confidence: 1 }] }, ...l])
    await start()
    const row = screen.getByRole('checkbox', { name: 'Microsoft Office (no device)' }) // D-471's name; no "—" for the missing IP
    expect(row).toBeDisabled()
    expect(screen.getByText('No IP address, so it cannot be scanned. Add its IP on the device page')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^No IP address/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open device Microsoft Office (no device)' })).toHaveAttribute('href', '/devices/a-office')
    await expectNoA11yViolations()
  })
})
