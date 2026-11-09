import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { makeQueryClient } from '@/app/App'
import { aiConfigStore, aiRunsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { feature } from './index'

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
    expect(screen.getByRole('link', { name: 'https://wordpress.org/news/2026/10/wordpress-7-1-4' })).toBeInTheDocument()
    expect(screen.getByText(/No confirmed exploitation signs/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('f-3 cũng vậy, với link MSRC', async () => {
    renderApp('/findings/f-3')
    expect(await screen.findByText('No confirmed recommendation yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951' })).toBeInTheDocument()
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
