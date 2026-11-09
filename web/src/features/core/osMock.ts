// Mock API: hệ điều hành của chính hộp (D-53, S-CORE-7). Bản thật chạy qua `vedette-host` (systemd, đặc quyền) với danh sách lệnh apt cố định;
// web không bao giờ chạy shell. Tiến trình cài đặt mô phỏng theo đồng hồ: log hiện dần theo thời gian từ lúc bắt đầu, không cần timer phía máy chủ.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, daysAgo, newId, nowIso } from '@/mocks/db'
import type { MaintenanceWindow, OsPackage, OsRebootBody, OsRun, OsState, UpdateHistory } from './types'

/** Mỗi dòng log hiện sau từng ấy mili giây (test: gần như tức thì). */
const STEP_MS = import.meta.env.MODE === 'test' ? 20 : 450
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/

interface OsStore {
  distro: OsState['os']['distro']; name: string; release: string; kernel: string; support_end: string; extended_end: string | null
  booted_at: string; last_check: string; pending: OsPackage[]; next_kernel: string | null
  reboot_required: boolean; reboot_reasons: string[]; reboot_scheduled_at: string | null
  auto_security: boolean; window: MaintenanceWindow
}
interface RunStore { id: string; scope: 'security' | 'all'; started_at: string; user: string; lines: string[]; pkgs: OsPackage[]; backup: string; settled: boolean }

const pkg = (name: string, current: string, next: string, security: boolean, cves: string[] = []): OsPackage => ({ name, current, new: next, security, cves })
const seed = (): OsStore => ({
  distro: 'ubuntu', name: 'Ubuntu 24.04.3 LTS', release: '24.04', kernel: '6.8.0-71-generic', support_end: '2029-05-31', extended_end: null,
  booted_at: daysAgo(23), last_check: daysAgo(0, 2), next_kernel: null,
  pending: [
    pkg('openssh-server', '1:9.6p1-3ubuntu13.5', '1:9.6p1-3ubuntu13.8', true, ['CVE-2025-26465', 'CVE-2025-26466']),
    pkg('openssl', '3.0.13-0ubuntu3.4', '3.0.13-0ubuntu3.5', true, ['CVE-2024-13176']),
    pkg('linux-image-6.8.0-87-generic', '6.8.0-71.71', '6.8.0-87.88', true, ['CVE-2025-38352']),
    pkg('libc6', '2.39-0ubuntu8.4', '2.39-0ubuntu8.6', true, ['CVE-2025-4802']),
    pkg('curl', '8.5.0-2ubuntu10.5', '8.5.0-2ubuntu10.6', true, ['CVE-2025-0167']),
    pkg('tzdata', '2025b-0ubuntu0.24.04.1', '2025c-0ubuntu0.24.04.1', false),
    pkg('python3-urllib3', '2.0.7-1ubuntu0.1', '2.0.7-1ubuntu0.2', false),
    pkg('vim-tiny', '2:9.1.0016-1ubuntu7.6', '2:9.1.0016-1ubuntu7.8', false),
    pkg('ubuntu-pro-client', '34~24.04', '35.1ubuntu0~24.04', false),
  ],
  reboot_required: false, reboot_reasons: [], reboot_scheduled_at: null,
  auto_security: true, window: { mode: 'window', days: [7], from: '02:00', to: '05:00' },
})
const store = collection<OsStore>('core_os', seed)
const runStore = collection<RunStore | null>('core_os_run', () => null, () => null)

const MIRRORS = { ubuntu: ['archive.ubuntu.com', 'security.ubuntu.com'], debian: ['deb.debian.org', 'security.debian.org'] }
const RELEASE_UPGRADE: Record<string, OsState['release_upgrade']> = {
  '24.04': { to: 'Ubuntu 26.04 LTS', steps: [
    'Take a snapshot of the machine, or at least download the Vedette backup under Settings, Data.',
    'Install every pending update on this page first and reboot.',
    'Open a console or SSH session on the box (not this web page) and run: sudo do-release-upgrade',
    'Answer the prompts, let it restart, then check that this page shows the new release and that the health check is green.',
  ] },
  '12': { to: 'Debian 13 (trixie)', steps: [
    'Take a snapshot of the machine, or at least download the Vedette backup under Settings, Data.',
    'Install every pending update on this page first and reboot.',
    'Open a console or SSH session on the box (not this web page), change "bookworm" to "trixie" in /etc/apt/sources.list and /etc/apt/sources.list.d/, then run: sudo apt update && sudo apt full-upgrade',
    'Reboot, then check that this page shows the new release and that the health check is green.',
  ] },
}

const dayOf = (d: Date) => (d.getDay() === 0 ? 7 : d.getDay())
const minutes = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3))
/** Mốc `d` có nằm trong cửa sổ bảo trì không (cửa sổ qua nửa đêm tính cho ngày bắt đầu). */
export function inWindow(d: Date, w: MaintenanceWindow): boolean {
  if (w.mode === 'always') return true
  const t = d.getHours() * 60 + d.getMinutes()
  const [f, to] = [minutes(w.from), minutes(w.to)]
  if (f < to) return w.days.includes(dayOf(d)) && t >= f && t < to
  const prev = new Date(d.getTime() - 864e5)
  return (t >= f && w.days.includes(dayOf(d))) || (t < to && w.days.includes(dayOf(prev)))
}
function atTime(day: number, hhmm: string): Date {
  const d = new Date(); d.setDate(d.getDate() + day); d.setHours(Number(hhmm.slice(0, 2)), Number(hhmm.slice(3)), 0, 0); return d
}
/** Lần đầu tiên sau bây giờ mà cửa sổ bắt đầu. */
function nextWindowStart(w: MaintenanceWindow): Date | null {
  for (let i = 0; i < 8; i++) { const c = atTime(i, w.from); if (c.getTime() > Date.now() && w.days.includes(dayOf(c))) return c }
  return null
}
function nextAt(hhmm: string, w: MaintenanceWindow): Date | null {
  for (let i = 0; i < 8; i++) { const c = atTime(i, hhmm); if (c.getTime() > Date.now() && inWindow(c, w)) return c }
  return null
}

function doReboot() {
  store.update((s) => ({ ...s, booted_at: nowIso(), reboot_required: false, reboot_reasons: [], reboot_scheduled_at: null, kernel: s.next_kernel ?? s.kernel, next_kernel: null }))
}

export const osHandlers = (deps: { updateCheckOn: () => boolean; addHistory: (e: UpdateHistory) => void }) => {
  const total = (r: RunStore) => r.lines.length * STEP_MS
  const elapsed = (r: RunStore) => Date.now() - new Date(r.started_at).getTime()
  const running = (r: RunStore | null) => !!r && elapsed(r) < total(r)

  /** Khi lần chạy vừa xong: áp hiệu ứng đúng một lần (gói biến mất khỏi danh sách chờ, cần khởi động lại, lịch sử, kiểm toán). */
  function settle() {
    const r = runStore.get()
    if (!r || r.settled || running(r)) return
    const names = new Set(r.pkgs.map((p) => p.name))
    const needReboot = r.pkgs.filter((p) => p.name.startsWith('linux-image-') || p.name === 'libc6')
    runStore.set({ ...r, settled: true })
    const kernel = r.pkgs.find((p) => p.name.startsWith('linux-image-'))
    store.update((s) => ({
      ...s, next_kernel: kernel ? kernel.name.replace('linux-image-', '') : s.next_kernel, pending: s.pending.filter((p) => !names.has(p.name)),
      reboot_required: s.reboot_required || needReboot.length > 0,
      reboot_reasons: [...new Set([...s.reboot_reasons, ...needReboot.map((p) => `${p.name} ${p.new}`)])],
    }))
    deps.addHistory({ id: newId('h'), ts: nowIso(), component: 'os', from: null, to: `${r.pkgs.length} packages (${r.scope === 'security' ? 'security' : 'all'})`, action: 'update', user: r.user })
    audit('os.install_done', r.scope, `${r.pkgs.length} packages`)
  }
  function runView(r: RunStore): OsRun {
    const done = !running(r)
    const shown = done ? r.lines.length : Math.min(r.lines.length, Math.floor(elapsed(r) / STEP_MS) + 1)
    const s = store.get()
    return {
      id: r.id, scope: r.scope, status: done ? 'done' : 'running', started_at: r.started_at,
      finished_at: done ? new Date(new Date(r.started_at).getTime() + total(r)).toISOString() : null, user: r.user,
      lines: r.lines.slice(0, shown),
      result: done ? {
        installed: r.pkgs.length, security: r.pkgs.filter((p) => p.security).length, backup: r.backup,
        health: [{ name: 'vedette-api', ok: true }, { name: 'database', ok: true }, { name: 'sensor', ok: true }, { name: 'web interface', ok: true }],
        reboot_required: s.reboot_required,
      } : null,
    }
  }
  function state(): OsState {
    settle()
    let s = store.get()
    if (s.reboot_scheduled_at && new Date(s.reboot_scheduled_at).getTime() <= Date.now() && !running(runStore.get())) {
      doReboot(); s = store.get()
      audit('os.reboot_done', 'scheduled')
    }
    const { pending, reboot_required, reboot_reasons, reboot_scheduled_at, auto_security, window, ...info } = s // eslint-disable-line @typescript-eslint/no-unused-vars
    return {
      os: { distro: info.distro, name: info.name, release: info.release, kernel: info.kernel, support_end: info.support_end, extended_end: info.extended_end, booted_at: info.booted_at, last_check: info.last_check, mirrors: MIRRORS[info.distro] },
      pending, reboot_required, reboot_reasons, reboot_scheduled_at, auto_security, window,
      release_upgrade: RELEASE_UPGRADE[info.release] ?? null, busy: running(runStore.get()),
    }
  }
  const stamp = () => { const d = new Date(); const p = (n: number) => String(n).padStart(2, '0'); return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}` }
  function linesFor(pkgs: OsPackage[], scope: 'security' | 'all', backup: string): string[] {
    const s = store.get()
    const [main, sec] = MIRRORS[s.distro]
    const codename = s.distro === 'ubuntu' ? 'noble' : 'bookworm'
    return [
      `[vedette-host] run started: apt-get install (${scope === 'security' ? 'security updates only' : 'all updates'})`,
      `[vedette-host] pre-update backup of the Vedette database: ${backup}`,
      `Hit:1 http://${main}/${s.distro} ${codename} InRelease`,
      `Get:2 http://${sec}/${s.distro} ${codename}-security InRelease [126 kB]`,
      'Reading package lists... Done',
      'Building dependency tree... Done',
      `The following packages will be upgraded:\n  ${pkgs.map((p) => p.name).join(' ')}`,
      `${pkgs.length} upgraded, 0 newly installed, 0 to remove.`,
      ...pkgs.flatMap((p) => [`Unpacking ${p.name} (${p.new}) over (${p.current}) ...`, `Setting up ${p.name} (${p.new}) ...`]),
      'Processing triggers for man-db ...',
      'Processing triggers for libc-bin ...',
      '[vedette-host] health check: vedette-api ok, database ok, sensor ok, web interface ok',
      `[vedette-host] run finished: ${pkgs.length} packages installed`,
    ]
  }

  return [
    http.get(`${API}/core/updates/os`, () => { const denied = guard('viewer'); if (denied) return denied; return HttpResponse.json(state()) }),
    http.get(`${API}/core/updates/os/run`, () => {
      const denied = guard('viewer'); if (denied) return denied
      settle()
      const r = runStore.get()
      return HttpResponse.json(r ? runView(r) : null)
    }),
    http.post(`${API}/core/updates/os/check`, () => {
      const denied = guard('operator'); if (denied) return denied
      if (!deps.updateCheckOn()) return fail(409, 'check_off', 'Update checks are off under Privacy. Turn them on to look for operating system updates.')
      if (running(runStore.get())) return fail(409, 'busy', 'An update run is in progress. Wait for it to finish, then check again.')
      store.update((s) => ({ ...s, last_check: nowIso() }))
      audit('os.check', 'operating system')
      return HttpResponse.json(state())
    }),
    http.post(`${API}/core/updates/os/install`, async ({ request }) => {
      const denied = guard('admin'); if (denied) return denied
      const b = await body<{ scope: string }>(request)
      if (b.scope !== 'security' && b.scope !== 'all') return fail(400, 'invalid_scope', 'Choose security updates or all updates.')
      settle()
      if (running(runStore.get())) return fail(409, 'busy', 'Another update run is already in progress. Wait for it to finish; only one run can go at a time.')
      const pkgs = store.get().pending.filter((p) => b.scope === 'all' || p.security)
      if (!pkgs.length) return fail(409, 'nothing_to_install', b.scope === 'security' ? 'There are no security updates waiting. Click "Check now" to look again.' : 'There are no updates waiting. Click "Check now" to look again.')
      const backup = `vedette-pre-update-${stamp()}.db.gz (4.2 MB)`
      const r: RunStore = { id: newId('run'), scope: b.scope, started_at: nowIso(), user: currentUser()!.email, lines: linesFor(pkgs, b.scope, backup), pkgs, backup, settled: false }
      runStore.set(r)
      audit('os.install', b.scope, `${pkgs.length} packages`)
      return HttpResponse.json(runView(r), { status: 202 })
    }),
    http.patch(`${API}/core/updates/os/settings`, async ({ request }) => {
      const denied = guard('admin'); if (denied) return denied
      const b = await body<{ auto_security: boolean; window: MaintenanceWindow }>(request)
      if (b.auto_security !== undefined && typeof b.auto_security !== 'boolean') return fail(400, 'invalid_auto', 'Automatic security updates are on or off.')
      const w = b.window
      if (w !== undefined) {
        if (w.mode !== 'always' && w.mode !== 'window') return fail(400, 'invalid_window', 'The maintenance window is "any time" or "only in a window".')
        if (w.mode === 'window') {
          if (!Array.isArray(w.days) || !w.days.length || w.days.some((d) => !Number.isInteger(d) || d < 1 || d > 7)) return fail(400, 'no_days', 'Pick at least one day for the maintenance window.')
          if (!HHMM.test(String(w.from)) || !HHMM.test(String(w.to))) return fail(400, 'invalid_time', 'Enter the start and end as hours and minutes, for example 02:00.')
          if (w.from === w.to) return fail(400, 'empty_window', 'The start and the end are the same, so the window is empty. Choose different times.')
        }
      }
      store.update((s) => ({
        ...s, auto_security: b.auto_security ?? s.auto_security,
        window: w ? (w.mode === 'always' ? { ...s.window, mode: 'always' } : { mode: 'window', days: [...new Set(w.days)].sort(), from: w.from, to: w.to }) : s.window,
        // Lịch khởi động lại cũ có thể rơi ra ngoài cửa sổ mới: bỏ, người dùng đặt lại.
        reboot_scheduled_at: w && s.reboot_scheduled_at && !inWindow(new Date(s.reboot_scheduled_at), w.mode === 'always' ? { ...s.window, mode: 'always' } : w) ? null : s.reboot_scheduled_at,
      }))
      audit('os.settings', 'operating system', `auto security ${store.get().auto_security ? 'on' : 'off'}, window ${store.get().window.mode}`)
      return HttpResponse.json(state())
    }),
    http.post(`${API}/core/updates/os/reboot`, async ({ request }) => {
      const denied = guard('admin'); if (denied) return denied
      const b = await body<OsRebootBody>(request)
      if (running(runStore.get())) return fail(409, 'busy', 'An update run is in progress. Wait for it to finish before rebooting.')
      const w = store.get().window
      if (b.when === 'now') {
        doReboot()
        audit('os.reboot', 'now')
      } else if (b.when === 'window') {
        if (w.mode !== 'window') return fail(400, 'no_window', 'There is no maintenance window yet. Set the days and hours first, or pick a time yourself.')
        const at = nextWindowStart(w)
        if (!at) return fail(400, 'no_window', 'No maintenance window starts in the next 7 days. Check the days you chose.')
        store.update((s) => ({ ...s, reboot_scheduled_at: at.toISOString() }))
        audit('os.reboot_schedule', 'next window', at.toISOString())
      } else if (b.when === 'custom') {
        if (!HHMM.test(String(b.at))) return fail(400, 'invalid_time', 'Enter the time as hours and minutes, for example 03:30.')
        const at = nextAt(b.at!, w)
        if (!at) return fail(400, 'outside_window', `${b.at} is outside the maintenance window. Pick a time inside it, or change the window first.`)
        store.update((s) => ({ ...s, reboot_scheduled_at: at.toISOString() }))
        audit('os.reboot_schedule', b.at!, at.toISOString())
      } else return fail(400, 'invalid_when', 'Choose: now, next maintenance window, or a time inside the window.')
      return HttpResponse.json(state())
    }),
    http.delete(`${API}/core/updates/os/reboot`, () => {
      const denied = guard('admin'); if (denied) return denied
      if (!store.get().reboot_scheduled_at) return fail(409, 'nothing_scheduled', 'No reboot is scheduled.')
      store.update((s) => ({ ...s, reboot_scheduled_at: null }))
      audit('os.reboot_cancel', 'operating system')
      return HttpResponse.json(state())
    }),
  ]
}
