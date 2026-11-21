import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { toast } from 'sonner'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { engineStore, nextRun, runs, scannerStore, timing, zoneStore } from './mocks'
import { runsPoll, runsPollMs } from './api'
import type { ScanConfig, ScanRun } from './types'

// V1 does not offer the credentialed scan (no backend yet); its GUI is kept, so this file runs it as offered, and one test runs v1.
const credFlag = vi.hoisted(() => ({ CREDENTIALED_IN_UI: true }))
vi.mock('@/lib/credentialed', () => credFlag)

const base = () => `${location.origin}/api/v1`
const as = (userId: string) => sessionStore.set({ userId })
const json = (method: string, b: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
const getRuns = async () => ((await (await fetch(`${base()}/scans/runs`)).json()) as { items: ScanRun[] }).items
const postRun = (targets: string[]) => fetch(`${base()}/scans/runs`, json('POST', { targets }))

timing.engineMs = 0 // the mock's engine is busy after Stop now only where a test says so
const RUNNING_POLL_MS = runsPoll.runningMs
runsPoll.runningMs = 1000 // the page reads every 5 s while a scan runs (#830); the tests' mock scans last 2 s
afterEach(() => { timing.stepMs = 2000; timing.stopMs = 1000; timing.engineMs = 0; vi.useRealTimers(); localStorage.removeItem('vedette-mock-egress') })

describe('scan: API không bao giờ quét ngoài phạm vi (LEGAL §3)', () => {
  it('từ chối thiết bị chưa duyệt, tên miền chưa xác thực, mục lạ, danh sách rỗng, và quét chồng', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' }, { timeout: 4000 }) // the first test loads the page's code
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
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
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

  it('chọn tay là đồng ý cho thiết bị khai tay đã bật quét mạng, mong manh, chưa phân loại và chính hộp; thiết bị "never" thì không bao giờ', async () => {
    const { ensureBox } = await import('@/features/inventory/mocks')
    ensureBox()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, origin: 'manual' as const } : a.id === 'a-unk01' ? { ...a, approved: true } : a)))
    as('u-admin')
    expect((await fetch(`${base()}/inventory/devices/a-srvad`, json('PATCH', { regular_scan: 'never' }))).status).toBe(200)
    const items = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; label: string; fragile: boolean; selectable: boolean; reason: string | null }[]
    const byId = (id: string) => items.find((x) => x.id === id)!
    // Added by hand, its network scan off until a person turns it on: not even a pick; turned on, picked by hand
    expect(byId('a-web01')).toMatchObject({ selectable: false, reason: 'regular_scan_never' })
    expect((await fetch(`${base()}/inventory/devices/a-web01/sources`, json('PUT', { scan: 'on' }))).status).toBe(200)
    const again = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; selectable: boolean; reason: string | null }[]
    expect(again.find((x) => x.id === 'a-web01')).toMatchObject({ selectable: true, reason: null })
    expect(byId('a-nas02')).toMatchObject({ selectable: true, fragile: true })
    expect(byId('a-unk01')).toMatchObject({ selectable: true, fragile: true }) // unknown kind counts as fragile: a quarter of the speed
    expect(byId('a-box')).toMatchObject({ selectable: true, pick_only: true, box: true, reason: null }) // A person may scan the box
    expect(byId('a-srvad')).toMatchObject({ selectable: false, reason: 'regular_scan_never' }) // "never" set by a person is absolute
    as('u-op')
    expect((await (await postRun(['a-srvad'])).json()).error.message).toMatch(/is set to never be scanned in the inventory; change that setting first/)
    expect((await postRun(['a-box'])).status).toBe(201)
  })

  it('máy quét không sẵn sàng: can_scan=false kèm lý do, nút khoá, POST trả 503 scanner_unavailable', async () => {
    scannerStore.set({ available: false })
    as('u-admin')
    const cfg = await (await fetch(`${base()}/scans/config`)).json()
    expect(cfg.can_scan).toBe(false)
    expect(cfg.block_reason).toMatch(/^The vulnerability scanner is not available/)
    as('u-op')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('scanner_unavailable')
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
  })

  it('no run history: the Nuclei schedule note blames the real reason, not always the commitment', async () => {
    runs.set([])
    scannerStore.set({ available: false })
    renderApp('/settings/scanning?tab=engines#nuclei')
    const card = await screen.findByRole('listitem', { name: /Vulnerability checks \(Nuclei\)/ })
    expect(await within(card).findByText(/nothing runs while the vulnerability scanner is not available/)).toBeInTheDocument()
    expect(screen.queryByText(/until the scan scope commitment is ticked/)).not.toBeInTheDocument()
  })

  it('no run history and no commitment: the Nuclei schedule note asks for the commitment', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))
    runs.set([])
    renderApp('/settings/scanning?tab=engines#nuclei')
    const card = await screen.findByRole('listitem', { name: /Vulnerability checks \(Nuclei\)/ })
    expect(await within(card).findByText(/nothing runs until the scan scope commitment is ticked/)).toBeInTheDocument()
  })

  it('thiết bị nằm trong loại trừ cũng bị từ chối khi gọi thẳng API', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { exclusions: ['192.168.10.0/24'] }))
    const res = await postRun(['a-web01'])
    expect(res.status).toBe(400)
    expect((await res.json()).error.message).toMatch(/is on the exclusion list/)
  })
})

describe('scan: quét ngay, tiến độ, dừng ngay (S-SCAN-4)', () => {
  it('#830: one device shows its step, not an empty devices bar; phase-only progress reads right; the page reads every 5 s, every second while stopping', async () => {
    timing.stepMs = 60_000
    const running = { id: 'run-x', trigger: 'manual', trigger_note: null, started_at: new Date().toISOString(), started_by: 'it@acme.example', ended_at: null, status: 'running',
      total: 1, done: 0, current: { label: 'NAS-PHOTOS', ip: '192.168.10.21' }, results: [], matched: 0, stop_reason: null, stop_requested_at: null, identification: [],
      progress: { phase: 'ports', percent: null, done: null, total: null, unit: null, started_at: new Date(Date.now() - 75_000).toISOString(), phase_started_at: new Date().toISOString(),
        updated_at: new Date().toISOString(), eta: null, message: null } } as unknown as ScanRun
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ items: [running], engine_busy: false })))
    renderApp('/settings/scanning?tab=history')
    expect(await screen.findByRole('heading', { level: 2, name: 'Device 1 of 1' })).toBeInTheDocument()
    expect(screen.queryByRole('progressbar', { name: 'Scan progress' })).toBeNull()
    const step = screen.getByRole('progressbar', { name: 'Checking open ports' }) // a real box today: the phase, no percent yet
    expect(step).not.toHaveAttribute('aria-valuenow')
    expect(screen.getByText('Scanning NAS-PHOTOS (192.168.10.21)')).toBeInTheDocument()
    expect(screen.getByText(/^1 min 1\d s elapsed$/)).toBeInTheDocument()
    expect(RUNNING_POLL_MS).toBe(5000)
    expect(runsPollMs({ items: [running], engine_busy: false })).toBe(runsPoll.runningMs)
    expect(runsPollMs({ items: [{ ...running, status: 'stopping' }], engine_busy: false })).toBe(1000)
    expect(runsPollMs({ items: [{ ...running, status: 'done' }], engine_busy: true })).toBe(runsPoll.runningMs)
    expect(runsPollMs({ items: [{ ...running, status: 'done' }], engine_busy: false })).toBe(false)
    await expectNoA11yViolations()
  })

  it('quét một thiết bị đến khi xong: ghi kết quả vào phát hiện dùng chung, kiểm toán, nhật ký probe', async () => {
    timing.stepMs = 30
    as('u-admin')
    await postRun(['a-nas02']) // fragile: a person's own pick
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const run = (await getRuns())[0]!
    expect(run.results.map((r) => r.result)).toContain('matched')
    expect(run.started_by).toBe('admin@acme.example')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.history.at(-1)!.action).toBe('rescanned')
    expect(auditStore.get().some((a) => a.action === 'scan.start')).toBe(true)
    const probes = (await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; ip: string }[]
    expect(probes.some((p) => p.run_id === run.id && p.ip === '192.168.10.21')).toBe(true)
    cleanup()
    // xem kết quả có bằng chứng và link tới phát hiện
    renderApp('/settings/scanning?tab=history')
    await waitFor(() => expect(screen.getAllByRole('button', { name: /View results of the scan/ })[0]).toBeEnabled(), { timeout: 4000 })
    await userEvent.click(screen.getAllByRole('button', { name: /View results of the scan/ })[0]!)
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText('Matches, still vulnerable')).toBeInTheDocument()
    expect(within(dlg).getByText('http/cves/2022/CVE-2022-27593.yaml')).toBeInTheDocument()
    expect(within(dlg).getByRole('link', { name: 'Open finding' })).toHaveAttribute('href', '/findings/f-1')
    // Scan now identifies first and says per device what it found or exactly why not (the NAS is fragile: gentle scan only)
    expect(run.identification).toEqual([expect.objectContaining({ target_id: 'a-nas02', reason: 'gentle_only', found: [] })])
    expect(within(dlg).getByRole('heading', { name: 'What each device was identified as' })).toBeInTheDocument()
    expect(within(dlg).getByText('Gentle scan only')).toBeInTheDocument()
    expect(within(dlg).getByText(/only a gentle port scan ran, without version or operating system detection/)).toBeInTheDocument()
  })

  it('đã giảm thiểu rồi quét lại: không có khớp chỉ là "không báo khớp", không đổi gì ở phát hiện', async () => {
    timing.stepMs = 30
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'mitigated' as const } : f)))
    const before = findingsStore.get().find((x) => x.id === 'f-1')!.history.length
    as('u-admin')
    await postRun(['a-nas02']) // fragile: only a person's own pick (the device page's button) scans it
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const res = (await getRuns())[0]!.results[0]!
    expect(res.result).toBe('not_matched')
    expect(res.note).toBe('CVE-2022-27593: no match reported by the scan template.')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('mitigated')
    expect(f.history).toHaveLength(before) // nuclei reports matches only: "no match" never marks the finding
    renderApp('/settings/scanning?tab=history')
    await waitFor(() => expect(screen.getAllByRole('button', { name: /View results of the scan/ })[0]).toBeEnabled(), { timeout: 4000 })
    await userEvent.click(screen.getAllByRole('button', { name: /View results of the scan/ })[0]!)
    expect(within(await screen.findByRole('dialog')).getByText('No match reported')).toBeInTheDocument()
  })

  it('"Dừng ngay": đang chạy hiện tiến độ, bấm dừng thì thấy "Đang dừng" rồi "Đã dừng" trong 5 giây, thiết bị chưa quét không bị chạm', async () => {
    timing.stepMs = 60_000
    timing.stopMs = 300
    as('u-admin')
    await postRun(['a-web01', 'a-srvad'])
    renderApp('/settings/scanning?tab=history')
    const bar = await screen.findByRole('progressbar', { name: 'Scan progress' })
    expect(bar).toHaveAttribute('aria-valuenow', '0')
    expect(screen.getByRole('heading', { level: 2, name: 'Device 1 of 2' })).toBeInTheDocument()
    // #830: the device's own step under the devices bar (the mock starts each device with host discovery, no percent yet)
    expect(screen.getByRole('progressbar', { name: 'Finding the device' })).not.toHaveAttribute('aria-valuenow')
    expect(screen.getByText(/Scanning WEB01|Scanning SRV-AD/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Stop now' }))
    const stopping = await screen.findByRole('button', { name: 'Stopping…' }) // The shared busy state
    expect(stopping).toBeDisabled()
    expect(stopping).toHaveAttribute('aria-busy', 'true')
    const t0 = Date.now()
    await waitFor(() => expect(screen.getByText(/Last scan was stopped .*: 0\/2 devices done/)).toBeInTheDocument(), { timeout: 5000 })
    expect(Date.now() - t0).toBeLessThan(5000)
    expect(screen.queryByRole('progressbar', { name: 'Scan progress' })).not.toBeInTheDocument()
    expect(screen.getAllByText('You pressed Stop now.').length).toBeGreaterThan(0)
    const run = (await getRuns())[0]!
    expect(run.status).toBe('stopped')
    expect(run.results.every((r) => r.result === 'skipped')).toBe(true)
    // the device being scanned when Stop now came: its requests on the way are in the probe log as stopped; the others have none
    const probes = ((await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; result: string }[]).filter((p) => p.run_id === run.id)
    expect(probes.length).toBeGreaterThan(0)
    expect(probes.every((p) => p.result === 'stopped')).toBe(true)
    expect(findingsStore.get().find((x) => x.id === 'f-1')!.history.some((h) => h.action === 'rescanned')).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scanning.run_stop')).toBe(true)
  })

  it('dừng lần quét đã kết thúc báo lỗi rõ; dừng hai lần không lỗi', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
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
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
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
    as('u-view')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(403)
  })

  it('the seeded scheduled and KEV runs, and the seeded rescan matches, never touch a device that needs a hand pick', async () => {
    renderApp('/settings/scanning?tab=history')
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
    renderApp('/settings/scanning?tab=history')
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
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByLabelText('From')).toHaveValue('22:00')
    expect(screen.getByLabelText('Until')).toHaveValue('05:00')
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toHaveValue('5') // The shared block (inventory stores it)
    expect(screen.getByLabelText('Discovery and SNMP')).toHaveValue('50')
    expect(screen.getByText('No changes, no denial of service')).toBeInTheDocument()
    expect(screen.getByText(/Never guesses passwords/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('#860: the shared block sends the version it read; a save over settings changed elsewhere is refused, says so, and shows the stored values', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    const puts: Array<Record<string, unknown>> = []
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'PUT' && request.url.endsWith('/scanning/safety')) puts.push(await request.clone().json() as Record<string, unknown>)
    })
    renderApp('/settings/scanning?tab=safety')
    await userEvent.selectOptions(await screen.findByLabelText('Vulnerability checks on the LAN'), '2')
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, exclusions: [...st.active.exclusions, '192.168.10.40'] } })) // an inline add elsewhere
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText(/Someone else saved these settings/)).toBeInTheDocument()
    expect(puts[0]?.version).toEqual(expect.any(String))
    await waitFor(() => expect(screen.getByLabelText('One IP or network per line')).toHaveValue('192.168.10.40')) // the form was built again on the stored values
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toHaveValue('2') // and keeps what was typed (#877)
    await userEvent.selectOptions(screen.getByLabelText('Vulnerability checks on the LAN'), '2')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    expect(puts[1]?.version).not.toBe(puts[0]?.version)
    server.events.removeAllListeners()
    toast.dismiss() // the toasts outlive this page: the next test looks for its own
    await waitFor(() => expect(screen.queryByText('Safety settings saved')).toBeNull())
  })

  it('lưu tốc độ và loại trừ: lưu bền, ghi kiểm toán, còn sau khi mở lại', async () => {
    const view = renderApp('/settings/scanning?tab=safety')
    await userEvent.selectOptions(await screen.findByLabelText('Vulnerability checks on the LAN'), '2')
    const ex = screen.getByLabelText('One IP or network per line')
    await userEvent.clear(ex)
    await userEvent.type(ex, '192.168.10.250{enter}192.168.20.0/24')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    as('u-admin')
    const safety = (await (await fetch(`${base()}/scanning`)).json()).safety as { speed: { requests_per_s: number }; exclusions: string[] }
    expect(safety.speed.requests_per_s).toBe(2)
    expect(safety.exclusions).toEqual(['192.168.10.250', '192.168.20.0/24'])
    expect(auditStore.get().some((a) => a.action === 'inventory.settings')).toBe(true)
    view.unmount()
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByLabelText('Vulnerability checks on the LAN')).toHaveValue('2')
  })

  it('loại trừ sai nói rõ dòng nào và sửa thế nào', async () => {
    renderApp('/settings/scanning?tab=safety')
    const ex = await screen.findByLabelText('One IP or network per line')
    await userEvent.type(ex, 'may-in')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Exclusion "may-in" is not valid')
    expect(alert).toHaveTextContent('Enter an IP (192.168.10.10)')
  })

  it('ngày trong tuần là 1 đến 7 (Thứ Hai = 1, Chủ Nhật = 7)', async () => {
    renderApp('/settings/scanning?tab=safety')
    await screen.findByLabelText('From')
    expect(screen.getAllByRole('checkbox', { name: /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/ }).map((c) => c.getAttribute('id'))).toEqual(['day-1', 'day-2', 'day-3', 'day-4', 'day-5', 'day-6', 'day-7'])
    as('u-admin')
    const put = (b: unknown) => fetch(`${base()}/scans/config`, json('PUT', b))
    expect((await put({ window: { days: [0] } })).status).toBe(400) // the old Sunday = 0 is refused
    expect((await put({ window: { days: [8] } })).status).toBe(400)
    expect((await put({ schedule: { weekday: 0 } })).status).toBe(400)
    expect((await put({ schedule: { frequency: 'weekly', weekday: 7 } })).status).toBe(200)
    expect(((await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig).schedule.weekday).toBe(7)
  })

  it('the regular checks use the shared schedule editor on their card', async () => {
    renderApp('/settings/scanning?tab=engines#nuclei')
    expect(await screen.findByText('Weekly on Sun at 23:00, in the scan window', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the schedule of Vulnerability checks' })).toBeEnabled()
    // the card's own Run button starts the checks: the schedule line has no second one
    expect(screen.queryByRole('button', { name: 'Run Vulnerability checks now' })).toBeNull()
    cleanup()
    renderApp('/settings/scanning?tab=engines#nmap-discovery')
    expect(await screen.findByText('Daily at 22:00, in the scan window', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the schedule of LAN sweep' })).toBeEnabled()
  })

  it('API kiểm tra ở biên và không cho bật phép thử nguy hiểm', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
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
    renderApp('/settings/scanning?tab=safety', { role: 'operator' })
    expect(await screen.findByText(/Only an administrator can change these settings/)).toBeInTheDocument()
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect((await fetch(`${base()}/scans/config`, json('PUT', { rate: 1 }))).status).toBe(403)
    expect((await fetch(`${base()}/scanning/safety`, json('PUT', {}))).status).toBe(403)
  })

  it('tính lần quét kế tiếp theo lịch hằng ngày, hằng tuần và khi tắt', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'daily', weekday: 7, at: '23:00' } }
    const now = new Date(2026, 10, 6, 12, 0) // thứ Sáu
    expect(new Date(nextRun(c, now)!).getDate()).toBe(6)
    expect(new Date(nextRun(c, now)!).getHours()).toBe(23)
    expect(new Date(nextRun(c, new Date(2026, 10, 6, 23, 30))!).getDate()).toBe(7)
    expect(new Date(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 7 } }, now)!).getDay()).toBe(0) // 7 = Sunday
    expect(new Date(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 1 } }, now)!).getDay()).toBe(1) // 1 = Monday
    expect(nextRun({ ...c, schedule: { ...c.schedule, enabled: false } }, now)).toBeNull()
    expect(nextRun({ ...c, schedule: { ...c.schedule, frequency: 'weekly', weekday: 3 }, window: { ...c.window, days: [1] } }, now)).toBeNull()
  })

  it('the first scheduled run is the next window of any window day, not the weekly weekday', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'weekly', weekday: 7, at: '23:00' } }
    const fri = new Date(2026, 10, 13, 14, 40) // Friday 13 Nov 14:40
    const first = new Date(nextRun(c, fri, true)!)
    expect([first.getDate(), first.getHours()]).toEqual([13, 23])
    expect(new Date(nextRun(c, fri, false)!).getDate()).toBe(15) // once a scheduled run happened: the weekly Sunday
  })

  it('a window that crosses midnight counts by its start day: a 02:00 slot belongs to the day before (#164)', () => {
    const c: ScanConfig = { window: { days: [1, 2, 3, 4, 5], from: '22:00', to: '05:00' }, rate: 5, exclusions: [], stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, schedule: { enabled: true, frequency: 'daily', weekday: 1, at: '02:00' } }
    const fri = new Date(nextRun(c, new Date(2026, 10, 20, 12, 0))!) // Friday noon: Saturday 02:00 is Friday's window
    expect([fri.getDate(), fri.getHours()]).toEqual([21, 2])
    const sun = new Date(nextRun(c, new Date(2026, 10, 22, 12, 0))!) // Sunday noon: Monday 02:00 is Sunday's window, so Tuesday
    expect(sun.getDate()).toBe(24)
  })
})

describe('scan: tự quét lại khi có KEV mới (S-SCAN-2)', () => {
  it('nhật ký sự kiện từ KEV thật, CVE nối về trang tra cứu; không lỗi a11y', async () => {
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(within(table).getAllByRole('link', { name: /^CVE-/ })[0]!.getAttribute('href')).toMatch(/^\/cve\/CVE-/)
    expect(within(table).getAllByText('Matches, alerted').length).toBeGreaterThan(0)
    expect(within(table).getByText('Not scanned: no matching device')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a rescan with no match says "No match reported" in a neutral tone, never "Not affected"', async () => {
    const ev = { id: 'ev-clear', ts: new Date().toISOString(), cve: 'CVE-2026-0002', product: 'Acme NAS', devices: ['nas02'], latency_min: 12, run_id: 'run-1', result: 'clear' }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ items: [ev], auto_rescan: true })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const chip = await within(table).findByText('No match reported')
    expect(chip.className).toContain('text-off')
    expect(within(table).queryByText('Not affected')).toBeNull()
  })

  it('devices that need a hand pick are named with a link to Scan now; a stopped rescan links to its run', async () => {
    const base = { ts: new Date().toISOString(), product: 'Acme NAS', latency_min: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base, id: 'ev-pick', cve: 'CVE-2026-0003', devices: ['NAS-PHOTOS', 'CAM-03'], run_id: null, result: 'pick_only' },
      { ...base, id: 'ev-stop', cve: 'CVE-2026-0004', devices: ['WEB01'], latency_min: 4, run_id: 'run-seed-3', result: 'stopped' },
    ] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const pick = await within(table).findByText(/^Not scanned automatically: 2 devices need a hand pick on/)
    expect(pick.className).toContain('text-off')
    expect(within(table).getByText('NAS-PHOTOS, CAM-03')).toBeInTheDocument()
    expect(within(table).getByRole('link', { name: 'Devices' })).toHaveAttribute('href', '/devices') // #850: Scan selected is on the Devices list
    expect(within(table).getByText(/^Stopped before the end:/).className).toContain('text-off')
    await expectNoA11yViolations()
    // the run opens on its own page, with why it stopped
    await userEvent.click(within(table).getByRole('link', { name: 'see the run' }))
    expect(await screen.findByRole('heading', { level: 1, name: /Vulnerability checks of/ }, { timeout: 4000 })).toBeInTheDocument()
    expect(await screen.findByText(/^Stopped: You pressed Stop now\./, {}, { timeout: 4000 })).toBeInTheDocument() // the run's own line, from the box
  })

  it('a rescan dropped after 7 days stays in the log with the reason', async () => {
    const base0 = { ts: new Date().toISOString(), product: 'Acme NAS', devices: [], latency_min: null, run_id: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base0, id: 'ev-a', cve: 'CVE-2026-0006', result: 'expired_no_template' },
      { ...base0, id: 'ev-b', cve: 'CVE-2026-0007', result: 'expired_scanner' },
      { ...base0, id: 'ev-c', cve: 'CVE-2026-0008', result: 'expired_zone' },
    ] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect((await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).className).toContain('text-off')
    expect(within(table).getByText('Not scanned for 7 days: the scanner was not available')).toBeInTheDocument()
    expect(within(table).getByText('Not scanned for 7 days: the time zone of the organization could not be read')).toBeInTheDocument()
    expect(within(table).queryByText('No matching device')).toBeNull()
    await expectNoA11yViolations()
  })

  it('the seed has a dropped event with its reason', async () => {
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).toBeInTheDocument()
  })

  it('the schedule says why nothing starts while the time zone cannot be read, not "off"', async () => {
    zoneStore.set({ readable: false })
    renderApp('/settings/scanning?tab=engines#nuclei')
    const cfg = await (await fetch(`${base()}/scans/config`)).json()
    expect(cfg.next_run).toBeNull()
    expect(cfg.schedule_blocked_reason).toMatch(/time zone of the organization cannot be read/)
    expect((await screen.findAllByText(/The schedule is on, but the time zone of the organization cannot be read/)).length).toBeGreaterThan(0)
    expect(screen.queryByText('The schedule is off.')).toBeNull()
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { schedule: { enabled: false } }))
    expect((await (await fetch(`${base()}/scans/config`)).json()).schedule_blocked_reason).toBeNull()
  })

  it('after Stop now, while the scanner is still busy, Scan now is locked with the reason and a start is refused', async () => {
    engineStore.set({ busyUntil: Date.now() + 60_000 })
    as('u-admin')
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
    const view = renderApp('/settings/scanning?tab=engines#nuclei')
    await userEvent.click(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' }))
    expect(await screen.findByText(/Off: new vulnerabilities will not be rescanned automatically/)).toBeInTheDocument()
    expect(((await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig).auto_rescan).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scan.config')).toBe(true)
    view.unmount()
    renderApp('/settings/scanning?tab=engines#nuclei', { role: 'operator' })
    expect(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' })).toBeDisabled()
  })
})

describe('scan: nhật ký probe (S-SCAN-4)', () => {
  it('liệt kê đích, thời điểm, mẫu; ghi rõ giữ tối thiểu 90 ngày; lọc được; tải CSV', async () => {
    renderApp('/settings/scanning?tab=probes')
    const table = await screen.findByRole('table', { name: 'Probe log' })
    expect(await screen.findByText(/Kept for at least 90 days\. \d+ lines now, oldest from/)).toBeInTheDocument()
    expect(within(table).getAllByText('NAS-PHOTOS').length).toBeGreaterThan(0)
    expect(within(table).getAllByText('http/cves/2022/CVE-2022-27593.yaml').length).toBeGreaterThan(0)
    const rows = within(table).getAllByRole('row').length
    await userEvent.type(screen.getByRole('searchbox', { name: 'Filter by target, template, result' }), 'CAM-LOBBY')
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row').length).toBeLessThan(rows))
    const csv = await fetch(`${base()}/scans/probes.csv`)
    expect(csv.headers.get('Content-Disposition')).toContain('attachment; filename=vedette-probe-log.csv')
    expect((await csv.text()).split('\n')[0]).toBe('time,target,name,template,request,result')
    await expectNoA11yViolations()
  })

  it('CSV không để bảng tính đọc tên thiết bị như công thức (tên đến từ mạng)', async () => {
    timing.stepMs = 30
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, hostname: '=HYPERLINK("http://x","y")' } : a)))
    as('u-op')
    await postRun(['a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const lines = (await (await fetch(`${base()}/scans/probes.csv`)).text()).split('\n')
    expect(lines.some((l) => l.includes(`"'=HYPERLINK(""http://x"",""y"")"`))).toBe(true)
    expect(lines.some((l) => /,"=/.test(l))).toBe(false)
  })

  it('seed giữ bản ghi cũ hơn 80 ngày (không xoá trước 90 ngày)', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'History of scans' })
    const items = (await (await fetch(`${base()}/scans/probes`)).json()) as { items: { ts: string }[]; retention_days: number }
    expect(items.retention_days).toBe(90)
    expect(Date.now() - Date.parse(items.items.at(-1)!.ts)).toBeGreaterThan(80 * 864e5)
  })
})

const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD1234567890abcdefGHIJKLMNOPQRSTUVWXYZQk2f\n-----END OPENSSH PRIVATE KEY-----'

describe('scan: quét có tài khoản (S-SCAN-5)', () => {
  const enable = () => modulesStore.update((l) => l.map((m) => (m.id === 'scan-credentialed' ? { ...m, enabled: true } : m)))
  /** Adding a server opens a dialog over the list; this opens it and gives back its server select. */
  const openAddServer = async () => { await userEvent.click(await screen.findByRole('button', { name: 'Add a server' })); return screen.findByLabelText('Target server') }

  it('v1 offers no Credentialed scan tab: the feature has no backend in this build', async () => {
    credFlag.CREDENTIALED_IN_UI = false
    try {
      enable()
      renderApp('/settings/scanning?tab=history')
      expect(await screen.findByRole('tab', { name: 'Safety' })).toBeInTheDocument()
      expect(screen.queryByRole('tab', { name: 'Credentialed scan' })).toBeNull()
    } finally { credFlag.CREDENTIALED_IN_UI = true }
  })

  it('module tắt mặc định thì nói rõ và chỉ chỗ bật', async () => {
    renderApp('/settings/scanning?tab=credentialed')
    expect(await screen.findByText('Credentialed scan module is off')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open module settings' })).toHaveAttribute('href', '/settings/modules#module-scan-credentialed')
  })

  it('hiện hướng dẫn chuẩn bị máy đích, mỗi lệnh một khung; không lỗi a11y', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    expect(await screen.findByText('No server is scanned with an account yet.')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Prepare a Linux target (Debian, Ubuntu)'))
    const codes = [...document.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain('ssh-keygen -t ed25519 -f vedette_scan_key -C "vedette-scan" -N ""')
    expect(codes).toContain('sudo adduser --disabled-password --gecos "" vedette-scan')
    await expectNoA11yViolations()
  })

  it('a device whose type acts as server (a virtual machine) stays an SSH candidate', async () => {
    enable()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, kind: 'virtual_machine' } : a)))
    renderApp('/settings/scanning?tab=credentialed')
    const select = await openAddServer()
    expect(within(select).getByRole('option', { name: /192\.168\.10\.12/ })).toHaveValue('a-web01')
  })

  it('thêm máy chủ với khoá riêng: chỉ hiện 4 ký tự cuối, khoá không được lưu hay trả lại; kiểm tra kết nối; xoá', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await userEvent.selectOptions(await openAddServer(), 'a-web01')
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
    renderApp('/settings/scanning?tab=credentialed')
    await userEvent.selectOptions(await openAddServer(), 'a-srvad')
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
    renderApp('/settings/scanning?tab=credentialed')
    await screen.findByRole('button', { name: 'Add a server' })
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
    renderApp('/settings/scanning?tab=credentialed', { role: 'operator' })
    const open = await screen.findByRole('button', { name: 'Add a server' })
    expect(open).toBeDisabled()
    expect(open).toHaveAttribute('title', 'Requires Admin role')
    as('u-view')
    expect((await fetch(`${base()}/scans/credentialed`, json('POST', { asset_id: 'a-web01', port: 22, username: 'x', private_key: KEY }))).status).toBe(403)
  })

  it('tệp khoá được đọc bằng bộ chọn tệp', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await openAddServer()
    const input = screen.getByLabelText('SSH private key file') as HTMLInputElement
    await userEvent.upload(input, new File([KEY], 'vedette_scan_key', { type: 'text/plain' }))
    expect(await screen.findByText('Read file vedette_scan_key')).toBeInTheDocument()
  })
})
