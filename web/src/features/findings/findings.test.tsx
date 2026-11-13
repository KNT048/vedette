import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { makeQueryClient } from '@/app/App'
import { aiConfigStore, aiRunsStore, assetsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { feature } from './index'
import { FixedInNote } from './Recommendation'
import { dayAfter, untilBounds, untilOk } from './accept'
import type { FindingDetail } from './types'

const FORTI = 'show firewall vip | grep -f 192.168.10.21'
const MIKROTIK_RULE = '/ip firewall filter add chain=forward action=drop in-interface-list=WAN connection-state=new connection-nat-state=dstnat dst-address=192.168.10.21 comment="Vedette: block Internet access to NAS" place-before=0'

describe('findings: danh sách (S-MIT-1)', () => {
  it('câu đầu trả lời, bảng đủ cột, không lỗi a11y', async () => {
    renderApp('/findings')
    expect(await screen.findByRole('heading', { level: 1, name: '3 unresolved findings, 1 confirmed' })).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Findings list' })
    expect(within(table).getAllByRole('row')).toHaveLength(4)
    for (const h of ['Device', 'CVE', 'Product', 'Status', 'Severity', 'Basis', 'Last seen']) expect(within(table).getByRole('columnheader', { name: new RegExp(h) })).toBeInTheDocument()
    expect(within(table).getByText('Confirmed by scan')).toBeInTheDocument()
    expect(within(table).getByText('Product match only')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('lọc theo trạng thái và theo ?cve= từ trang CVE', async () => {
    renderApp('/findings?cve=CVE-2022-27593')
    const table = await screen.findByRole('table', { name: 'Findings list' })
    expect(within(table).getAllByRole('row')).toHaveLength(2)
    expect(within(table).getByText('NAS-PHOTOS')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear CVE-2022-27593 filter' }))
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(4))
    await userEvent.click(screen.getByRole('button', { name: 'Suspected' }))
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(3))
  })

  it('không còn phát hiện chưa xử lý thì nói rõ và chỉ việc làm tiếp', async () => {
    findingsStore.update((l) => l.map((f) => ({ ...f, status: 'patched' as const })))
    renderApp('/findings')
    expect(await screen.findByRole('heading', { level: 1, name: 'No unresolved findings' })).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Open Vulnerability scans' })[0]).toHaveAttribute('href', '/scans')
    expect(screen.getAllByRole('link', { name: 'Open Devices' })[0]).toHaveAttribute('href', '/devices')
  })

  it('D-500: phần mềm không có phiên bản là MỘT dòng "add the version", không phải một finding mỗi CVE; sản phẩm khai tay không thiết bị gọi một lần theo D-471 (W5-1)', async () => {
    server.use(http.get('*/api/v1/findings', () => HttpResponse.json({ items: [], version_needed: [
      { asset: { id: 'a-pc', name: 'PC-KE-TOAN', hostname: 'PC-KE-TOAN', ip: '192.168.10.40', kind: 'pc', display: 'Microsoft Office' }, asset_id: 'a-pc', software_id: 's-1', software: 'Microsoft Office', version: null, cves: 32 },
      { asset: { id: 'a-man', name: 'Microsoft Office (no device)', hostname: null, ip: '—', kind: 'unknown', display: 'Microsoft Office' }, asset_id: 'a-man', software_id: 's-3', software: 'Microsoft Office', version: null, cves: 30 },
      { asset: null, asset_id: 'a-fw', software_id: 's-2', software: 'FortiGate', version: 'latest', cves: 21 },
    ] })))
    renderApp('/findings')
    const box = await screen.findByRole('region', { name: 'Add the version of 3 software to check them' })
    const lines = within(box).getAllByRole('listitem')
    expect(lines[0]).toHaveTextContent(/^PC-KE-TOAN: Microsoft Office has no version: adding it checks 32 exploited CVEs\.$/)
    expect(lines[1]).toHaveTextContent(/^Microsoft Office \(no device\) has no version: adding it checks 30 exploited CVEs\.$/)
    expect(lines[2]).toHaveTextContent(/^A removed device: FortiGate version "latest" cannot be compared/)
    expect(within(box).getByRole('link', { name: 'PC-KE-TOAN' })).toHaveAttribute('href', '/devices/a-pc')
    expect(within(box).getByRole('link', { name: 'Microsoft Office (no device)' })).toHaveAttribute('href', '/devices/a-man')
    expect(box).not.toHaveTextContent('—')
    await expectNoA11yViolations()
  })

  it('lỗi API hiện thông báo và nút thử lại', async () => {
    server.use(http.get('*/api/v1/findings', () => HttpResponse.json({ error: { code: 'x', message: 'The findings store is busy.' } }, { status: 503 })))
    renderApp('/findings')
    expect(await screen.findByText('The findings store is busy.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('module findings tắt thì hiện ModuleOff', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'findings' ? { ...m, enabled: false } : m)))
    renderApp('/findings')
    expect(await screen.findByText('Findings module is off')).toBeInTheDocument()
  })

  it('module mitigation tắt: phát hiện vẫn còn, chỉ phần "What to do" báo module tắt (D-57 (6))', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'mitigation' ? { ...m, enabled: false } : m)))
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { level: 1, name: /NAS-PHOTOS has a confirmed vulnerability/ })).toBeInTheDocument()
    expect(await screen.findByText('Mitigation module is off')).toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
  })

  it('mô đun: findings phụ thuộc inventory và feeds; mitigation phụ thuộc findings; reports phụ thuộc notify', () => {
    const dep = (id: string) => modulesStore.get().find((m) => m.id === id)?.depends
    expect(dep('findings')).toEqual(expect.arrayContaining(['inventory', 'feeds']))
    expect(dep('mitigation')).toEqual(['findings'])
    expect(dep('reports')).toContain('notify')
  })
})

describe('findings: f-1 có khuyến nghị Vedette đã xác nhận (D-21, S-MIT-1, S-SCAN-3)', () => {
  it('hiện Vedette đã xác nhận, người, ngày, soạn với AI, link khuyến cáo QNAP; không lỗi a11y', async () => {
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { level: 1, name: /NAS-PHOTOS has a confirmed vulnerability \(CVE-2022-27593\)/ })).toBeInTheDocument()
    expect(screen.getByText('Confirmed by Vedette maintainers')).toBeInTheDocument()
    expect(screen.getByText(/Confirmed by a Vedette maintainer on/)).toBeInTheDocument()
    expect(screen.getAllByText(/drafted with AI/i).length).toBeGreaterThan(0)
    expect(screen.queryByText('No confirmed recommendation yet')).not.toBeInTheDocument()
    expect(screen.queryByText('Your AI')).not.toBeInTheDocument()
    const advisories = screen.getAllByRole('link', { name: /QSA-22-24|Open the vendor advisory/ })
    expect(advisories.some((a) => a.getAttribute('href') === 'https://www.qnap.com/en/security-advisory/qsa-22-24')).toBe(true)
    await expectNoA11yViolations()
  })

  it('bằng chứng: tóm tắt, mẫu, request/response, cách tự kiểm tra lại và nút quét lại', async () => {
    renderApp('/findings/f-1')
    const ev = (await screen.findByRole('heading', { name: 'Evidence' })).closest('section')!
    expect(within(ev).getByText(/The nuclei-templates safe scan template/)).toBeInTheDocument()
    expect(within(ev).getByText('http/cves/2022/CVE-2022-27593.yaml')).toBeInTheDocument()
    expect(within(ev).getByText(/GET http:\/\/192\.168\.10\.21\/photo/)).toBeInTheDocument()
    expect(within(ev).getByText('curl -sI http://192.168.10.21/photo/')).toBeInTheDocument()
    expect(within(ev).getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', '/scans?target=a-nas02')
  })

  it('FortiGate được chọn sẵn; mỗi bước một khung, dùng IP thật của NAS, có tác dụng phụ và kiểm tra', async () => {
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    expect(within(fw).getByRole('button', { name: 'FortiGate (FortiOS) (declared)' })).toHaveAttribute('aria-pressed', 'true')
    const codes = [...fw.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain(FORTI)
    expect(codes).toContain('show firewall policy | grep -f "<VIP-NAME>"')
    expect(codes).toContain('config firewall policy\nedit <ID>\nset status disable\nnext\nend')
    expect(codes).toContain('config firewall address\nedit "geo-VN"\nset type geography\nset country "VN"\nnext\nend')
    expect(codes.every((c) => !/^\s*#/m.test(c ?? ''))).toBe(true)
    expect(within(fw).getAllByText('Side effects:').length).toBeGreaterThan(0)
    expect(within(fw).getByText(/Access to the NAS from the Internet stops immediately/)).toBeInTheDocument()
    expect(within(fw).getByText('Check after applying')).toBeInTheDocument()
    expect(within(fw).getByText('Undo')).toBeInTheDocument()
  })

  it('chuyển sang MikroTik: lệnh đúng cú pháp, giải thích danh sách WAN', async () => {
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    await userEvent.click(within(fw).getByRole('button', { name: 'MikroTik (RouterOS) (declared)' }))
    const codes = [...fw.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain('/ip firewall nat print where to-addresses=192.168.10.21')
    expect(codes).toContain(MIKROTIK_RULE)
    expect(within(fw).getByText(/default RouterOS WAN interface list/)).toBeInTheDocument()
    await userEvent.click(within(fw).getByRole('button', { name: 'Other device' }))
    expect(within(fw).getByText(/Find the port forwarding section/)).toBeInTheDocument()
  })

  it('"Đã áp dụng" ghi nhật ký (lịch sử + kiểm toán), không tự đổi trạng thái', async () => {
    renderApp('/findings/f-1')
    const patch = (await screen.findByRole('heading', { name: '1. Install the patch' })).closest('section')!
    await userEvent.click(within(patch).getByRole('button', { name: 'Applied' }))
    expect(await within(patch).findByText(/Recorded as applied by admin@acme.example/)).toBeInTheDocument()
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('confirmed')
    expect(f.history.at(-1)!.action).toBe('applied:patch')
    expect(auditStore.get().some((a) => a.action === 'findings.applied' && a.target === 'f-1')).toBe(true)
    expect(await screen.findByText('Applied: patch')).toBeInTheDocument()
  })

  it('"Tôi đã bị chưa?" nêu tệp .deadbolt và trang đăng nhập bị thay', async () => {
    renderApp('/findings/f-1')
    const c = (await screen.findByRole('heading', { name: 'Have I been hit?' })).closest('section')!
    expect(within(c).getAllByText(/Deadbolt/).length).toBeGreaterThan(0)
    expect(within(c).getByText('Files with a .deadbolt extension')).toBeInTheDocument()
    expect(within(c).getByText('QTS login page replaced')).toBeInTheDocument()
    expect(within(c).getByText('curl -s http://192.168.10.21:8080/ | grep -i deadbolt')).toBeInTheDocument()
    expect(within(c).getByText(/find -L \/share/)).toBeInTheDocument()
    expect(within(c).getByText('If you see signs')).toBeInTheDocument()
  })
})

describe('findings: f-2, f-3 chưa có khuyến nghị đã xác nhận (D-21)', () => {
  it('hiện "Chưa có khuyến nghị đã xác nhận", yêu cầu của CISA và link hãng, không có nhãn xác nhận', async () => {
    renderApp('/findings/f-2')
    expect(await screen.findByText('No confirmed recommendation yet')).toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
    expect(screen.getByText(/Apply mitigations in accordance with vendor instructions/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Vendor advisory (wordpress.org)' })).toHaveAttribute('href', 'https://wordpress.org/news/2026/10/wordpress-7-1-4')
    expect(screen.getByText('Steps you can take now')).toBeInTheDocument() // W1-31: what the box knows, without a pack
    expect(screen.getByText(/No confirmed exploitation signs/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('D-488: "What to do" nói phiên bản vá cho đúng thiết bị, đúng nhánh, và không bịa khi NVD không cho', () => {
    const note = (fixed_in: FindingDetail['fixed_in']) => render(<FixedInNote finding={{ asset: { name: 'FortiGate-60F' }, fixed_in } as FindingDetail} />)
    const src = { source: 'NVD affected versions', more: 0, no_fix: 0, distro: '', branches: [] }
    const a = note({ ...src, kind: 'fixed', version: '7.4.1', fixed: '7.4.3' })
    expect(screen.getByText('Fixed in 7.4.3: upgrade FortiGate-60F from 7.4.1 to 7.4.3 or later.')).toBeInTheDocument()
    expect(screen.getByText(/Source: NVD affected versions/)).toBeInTheDocument()
    a.unmount()
    const b = note({ ...src, kind: 'up_to', version: '5.6.8', fixed: '5.6.10' })
    expect(screen.getByText(/Versions up to 5\.6\.10 are affected, and FortiGate-60F runs 5\.6\.8: upgrade to a release after 5\.6\.10\./)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in/)).not.toBeInTheDocument()
    b.unmount()
    const c = note({ ...src, kind: 'branches', version: '', fixed: '', more: 3, branches: [{ branch: '7.4', fixed: '7.4.3' }, { branch: '7.2', fixed: '7.2.7' }, { branch: '', fixed: '22.4R2' }] })
    expect(screen.getByText(/7\.4 \u2192 7\.4\.3, 7\.2 \u2192 7\.2\.7, 22\.4R2, and 3 more/)).toBeInTheDocument()
    c.unmount()
    const d = note({ ...src, kind: 'distro', version: '1.9.4-1ubuntu2', fixed: '', distro: 'Ubuntu' })
    expect(screen.getByText(/It is a Ubuntu package: install its security updates/)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in/)).not.toBeInTheDocument()
    d.unmount()
    const g = note({ ...src, kind: 'fixed', version: '8.2.0', fixed: '8.3.3', distro: 'Ubuntu' })
    expect(screen.getByText('Fixed in 8.3.3: upgrade FortiGate-60F from 8.2.0 to 8.3.3 or later.')).toBeInTheDocument()
    expect(screen.getByText(/If you installed .* from Ubuntu's packages, install its security updates instead/)).toBeInTheDocument()
    g.unmount()
    const e = note({ ...src, kind: 'branches', version: '7.0.x', fixed: '', no_fix: 4, branches: [{ branch: '7.0', fixed: '7.0.9' }] })
    expect(screen.getByText(/cannot read the version "7\.0\.x" of FortiGate-60F.*7\.0 \u2192 7\.0\.9, NVD names no fixed release for 4 more line\(s\)/)).toBeInTheDocument()
    expect(screen.queryByText(/has no version yet/)).not.toBeInTheDocument()
    e.unmount()
    note(null)
    expect(screen.queryByTestId('fixed-in')).not.toBeInTheDocument()
  })

  it('f-3 cũng vậy, với link MSRC', async () => {
    renderApp('/findings/f-3')
    expect(await screen.findByText('No confirmed recommendation yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Vendor advisory (msrc.microsoft.com)' })).toHaveAttribute('href', 'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951')
  })

  it('"Hỏi AI của tôi" trả lời trong AiBlock của khách, ghi lượt chạy, còn sau khi tải lại', async () => {
    const view = renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Ask my AI' }))
    const label = await screen.findByText('Your AI')
    const block = label.closest('[data-ai="true"]') as HTMLElement
    expect(within(block).getByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(within(block).getByText(/Update WordPress to the latest release/)).toBeInTheDocument()
    expect(within(block).queryByText('Drafted by Vedette with AI')).not.toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
    const runs = aiRunsStore.get()
    expect(runs).toHaveLength(1)
    expect(runs[0]!.skill).toBe('mitigation-config')
    view.unmount()
    renderApp('/findings/f-2')
    expect(await screen.findByText('Your AI')).toBeInTheDocument()
  })

  // beta 0.1.0-beta.1: Explain on Haiku 5.5 failed with a cut answer, and the page said "No AI profile is assigned". Each failure of the
  // AI shows the box's own message for it, never the "not set up" one.
  it.each([
    ['ai_cut_off', 502, "The AI's answer was cut off at the output limit (12,000 tokens), so it was not used. Try again; if it keeps happening, use a model for explaining findings that writes shorter answers."],
    ['ai_bad_format', 502, 'The AI answered, but not in the format Vedette needs, so the answer was discarded. Try again, or use a stronger model for this job.'],
    ['provider_error', 502, 'The AI provider returned an error for explaining findings (Claude: provider refused the request (HTTP 400): bad model).'],
    ['blocked_by_hook', 409, 'The AI was not asked: a hook stopped the data sent with it (the device of the finding). The text contains an ID number.'],
    ['budget_reached', 429, "This month's AI budget of 6,000,000 tokens is used up, so AI jobs are stopped until it renews on 1 December 2026. An administrator can raise the budget in Settings, AI assistant."],
    ['ai_timeout', 504, 'The AI provider did not answer explaining findings in time (Claude: provider did not answer in time).'],
  ])('Ask my AI failing with %s shows that failure', async (code, status, message) => {
    server.use(http.post('*/api/v1/findings/:id/ai', () => HttpResponse.json({ error: { code, message } }, { status })))
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Ask my AI' }))
    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByText(/No AI profile is assigned to this job/)).toBeNull()
  })

  it('AI chưa cấu hình: nút tắt, nói rõ phải làm gì, có link tới cài đặt', async () => {
    aiConfigStore.update((c) => ({ ...c, configured: false }))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('button', { name: 'Ask my AI' })).toBeDisabled()
    expect(screen.getAllByText('The AI assistant is off, or no AI profile is assigned to this job.').length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: 'Open AI assistant settings' })[0]).toHaveAttribute('href', '/settings/ai')
    expect(screen.getByRole('button', { name: 'Explain' })).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/findings/f-2/ai`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ skill: 'explain' }) })
    expect(res.status).toBe(409)
  })

  it('"Giải thích" (S-AI-2) hiện trong AiBlock với token và nguồn', async () => {
    renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Explain' }))
    // f-1 là Critical nên trang còn có khối kế hoạch phản ứng (module response); lấy đúng khối "Explain"
    const block = (await screen.findByText(/ransomware groups have used it/)).closest('[data-ai="true"]') as HTMLElement
    expect(within(block).getByText(/tokens in/)).toBeInTheDocument()
    expect(within(block).getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument()
    expect(within(block).getByText('Sources:')).toBeInTheDocument()
    expect(within(block).getByText(/ransomware groups have used it/)).toBeInTheDocument()
    expect(aiRunsStore.get()[0]!.skill).toBe('explain-finding')
    // khuyến nghị của dự án vẫn tách riêng, không bị trộn với khối AI của khách
    expect(screen.getAllByText('Drafted by Vedette with AI')).toHaveLength(1)
  })
})

describe('findings: đổi trạng thái và quyền', () => {
  it('đánh dấu đã vá kèm ghi chú: lưu trạng thái, lịch sử, kiểm toán, còn sau khi tải lại', async () => {
    const view = renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /Patched/ }))
    await userEvent.type(within(dlg).getByLabelText('Note (optional)'), 'Đã lên Photo Station 6.1.2')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status' }))
    expect(await screen.findByRole('heading', { level: 1, name: /CVE-2022-27593 is patched/ })).toBeInTheDocument()
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('patched')
    expect(f.resolution_note).toBe('Đã lên Photo Station 6.1.2')
    expect(f.resolved_by).toBe('admin@acme.example')
    expect(auditStore.get().some((a) => a.action === 'findings.status')).toBe(true)
    expect(screen.getByText('Đã lên Photo Station 6.1.2')).toBeInTheDocument()
    view.unmount()
    renderApp('/findings')
    expect(await screen.findByRole('heading', { level: 1, name: '2 unresolved findings, 0 confirmed' })).toBeInTheDocument()
  })

  it('báo nhầm bắt buộc có ghi chú, lỗi nói rõ phải sửa gì', async () => {
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog')
    await userEvent.click(within(dlg).getByRole('radio', { name: /False positive/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status' }))
    expect(await within(dlg).findByText(/Say why this is a false positive/)).toBeInTheDocument()
    expect(findingsStore.get().find((x) => x.id === 'f-2')!.status).toBe('suspected')
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'WordPress đã là 7.2')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status' }))
    await waitFor(() => expect(findingsStore.get().find((x) => x.id === 'f-2')!.status).toBe('false_positive'))
  })

  it('phát hiện đã xử lý có nút mở lại', async () => {
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'mitigated' as const } : f)))
    renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Reopen finding' }))
    await waitFor(() => expect(findingsStore.get().find((x) => x.id === 'f-1')!.status).toBe('confirmed'))
    expect(findingsStore.get().find((x) => x.id === 'f-1')!.resolved_by).toBeNull()
  })

  it('vai chỉ xem đọc được nhưng không ghi được', async () => {
    renderApp('/findings/f-1', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Mark as handled' })).toBeDisabled()
    for (const b of screen.getAllByRole('button', { name: 'Applied' })) expect(b).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Explain' })).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/findings/f-1/status`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'patched' }) })
    expect(res.status).toBe(403)
  })

  it('API kiểm tra ở biên: hành động lạ, ghi chú quá dài, mở lại phát hiện đang mở', async () => {
    renderApp('/findings')
    await screen.findByRole('table')
    const post = (path: string, b: unknown) => fetch(`${location.origin}/api/v1/findings/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const bad = await post('f-1/status', { action: 'xoa' })
    expect(bad.status).toBe(400)
    expect((await bad.json()).error.message).toMatch(/Choose one of/)
    expect((await post('f-1/status', { action: 'patched', note: 'x'.repeat(501) })).status).toBe(400)
    expect((await post('f-1/status', { action: 'reopen' })).status).toBe(409)
    expect((await post('f-9/status', { action: 'patched' })).status).toBe(404)
    expect((await post('f-2/applied', { item: 'patch' })).status).toBe(400)
    expect((await post('f-1/applied', { item: 'rm -rf' })).status).toBe(400)
  })

  it('trang không có phát hiện này nói rõ', async () => {
    renderApp('/findings/f-404')
    expect(await screen.findByText(/No such finding/)).toBeInTheDocument()
  })
})

describe('findings: slot device.panels', () => {
  function Panel({ assetId }: { assetId: string }) {
    const C = feature.slots!['device.panels']!
    return <QueryClientProvider client={makeQueryClient()}><MemoryRouter><C assetId={assetId} /></MemoryRouter></QueryClientProvider>
  }

  it('liệt kê phát hiện của đúng thiết bị, link tới chi tiết', async () => {
    sessionStore.set({ userId: 'u-admin' })
    render(<Panel assetId="a-nas02" />)
    expect(await screen.findByRole('heading', { name: 'Findings on this device' })).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'CVE-2022-27593' })).toHaveAttribute('href', '/findings/f-1')
    expect(screen.queryByText('CVE-2026-119977')).not.toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('thiết bị không có phát hiện thì nói rõ', async () => {
    sessionStore.set({ userId: 'u-admin' })
    render(<Panel assetId="a-pc01" />)
    expect(await screen.findByText('No findings for this device yet.')).toBeInTheDocument()
  })
})

describe('findings: Mark as handled form matrix (docs/QA.md §2, QA walk 2026-11-12)', () => {
  it('Cancel drops the draft: the next opening starts at Patched with an empty note', async () => {
    renderApp('/findings/f-1')
    const open = async () => { await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' })); return screen.findByRole('dialog', { name: 'Mark as handled' }) }
    let dlg = await open()
    await eachOption([
      { option: 'False positive', shown: ['Note: why (required)'], hidden: ['Note (optional)'] },
      { option: 'Cancel, open again', shown: ['Note (optional)'], hidden: ['Note: why (required)'] },
    ], async (o) => {
      if (o === 'False positive') { await userEvent.click(within(dlg).getByRole('radio', { name: /False positive/ })); fireEvent.change(within(dlg).getByRole('textbox'), { target: { value: 'not ours' } }); return }
      await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
      dlg = await open()
    })
    expect(within(dlg).getByRole('radio', { name: /Patched/ })).toBeChecked()
    expect(within(dlg).getByRole('textbox')).toHaveValue('')
  })
})

describe('findings: customer walk 1 (D-484)', () => {
  it('W1-4: real risk first; a product-only guess shows its severity muted as unverified; certainty filter', async () => {
    renderApp('/findings')
    const table = await screen.findByRole('table', { name: 'Findings list' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getByRole('link', { name: /^CVE-/ }).textContent)).toEqual(['CVE-2022-27593', 'CVE-2026-96951', 'CVE-2026-119977'])
    expect(within(rows[2]!).getByText('High, unverified')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Unverified' }))
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2))
  })

  it('W1-12: select all shown, one action and one note, one history and audit row per finding', async () => {
    renderApp('/findings')
    await screen.findByRole('table', { name: 'Findings list' })
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all 3 findings shown' }))
    const bar = screen.getByRole('region', { name: 'Selected findings' })
    expect(within(bar).getByText('3 findings selected')).toBeInTheDocument()
    await userEvent.click(within(bar).getByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark 3 findings as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /False positive/ }))
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'Lab network, not ours')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status for 3 findings' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'No unresolved findings' })).toBeInTheDocument()
    expect(findingsStore.get().every((f) => f.status === 'false_positive' && f.resolution_note === 'Lab network, not ours' && f.history.at(-1)?.action === 'false_positive')).toBe(true)
    expect(auditStore.get().filter((a) => a.action === 'findings.status')).toHaveLength(3)
  })

  it('W1-12: a closed finding in the selection keeps its status and reason; the toast says so', async () => {
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'patched' as const, resolution_note: 'Updated to 6.1.2' } : f)))
    renderApp('/findings')
    await screen.findByRole('table', { name: 'Findings list' })
    await userEvent.click(screen.getByRole('button', { name: 'All' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all 3 findings shown' }))
    await userEvent.click(within(screen.getByRole('region', { name: 'Selected findings' })).getByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark 3 findings as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /Not relevant/ }))
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'Retired next month')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status for 3 findings' }))
    expect(await screen.findByText('Status saved for 2 findings. 1 was already closed and kept its status.')).toBeInTheDocument()
    const f1 = findingsStore.get().find((f) => f.id === 'f-1')!
    expect([f1.status, f1.resolution_note]).toEqual(['patched', 'Updated to 6.1.2'])
  })

  it('W1-2, W1-32: a device with no IP is named, says "No IP address" and offers no rescan', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, ip: '—', hostname: null } : a)))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { level: 1, name: /^VMware may be affected/ })).toBeInTheDocument()
    expect(screen.getAllByText('No IP address').length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: 'Rescan this device' })).not.toBeInTheDocument()
    expect(screen.queryByText(/a-web01/)).not.toBeInTheDocument()
  })
})

describe('findings: accept risk until a day (D-498, S-MIT-1)', () => {
  it('the day runs from tomorrow to a year ahead, on the local calendar', () => {
    const today = new Date(2026, 10, 13, 23, 30)
    expect(untilBounds(today)).toEqual({ min: '2026-11-14', max: '2027-11-13' })
    expect(dayAfter(new Date(2026, 1, 28), 1)).toBe('2026-03-01')
    for (const [d, ok] of [['2026-11-13', false], ['2026-11-14', true], ['2027-11-13', true], ['2027-11-14', false], ['', false], ['14/11/2026', false]] as const) expect([d, untilOk(d, today)]).toEqual([d, ok])
  })

  it('needs a note and a day; a preset fills the day; the page says until when and by whom', async () => {
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /Accept risk until/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status' }))
    expect(await within(dlg).findByText('Say why you accept the risk (at least 3 characters).')).toBeInTheDocument()
    expect(within(dlg).getByText('Choose a date from tomorrow up to one year from today.')).toBeInTheDocument()
    const date = within(dlg).getByLabelText('Accept until')
    expect(date).toHaveAttribute('min', untilBounds().min)
    expect(date).toHaveAttribute('max', untilBounds().max)
    await userEvent.click(within(dlg).getByRole('button', { name: '90 days' }))
    expect(date).toHaveValue(dayAfter(new Date(), 90))
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'No patch window before March')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save status' }))
    expect(await screen.findByRole('heading', { level: 1, name: /risk accepted until/ })).toBeInTheDocument()
    expect(screen.getByText(/^Risk accepted until .* by admin@acme\.example\. No patch window before March$/)).toBeInTheDocument()
    expect(findingsStore.get().find((x) => x.id === 'f-2')!.history.at(-1)?.action).toBe('risk_accepted')
  })
})
