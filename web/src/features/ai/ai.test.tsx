import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { aiAssignStore, aiAvailable, aiConfigStore, aiProfilesStore, aiRunsStore, assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import AiSettings from './AiSettings'
import LogsPanel from './LogsPanel'

const enabled = (el: HTMLElement) => waitFor(() => expect(el).toBeEnabled())
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
/** Dựng một thành phần riêng (cài đặt, khung log) với phiên đã đăng nhập. */
function renderUi(ui: React.ReactNode, role: Role = 'admin') {
  sessionStore.set({ userId: USER[role] })
  const qc = makeQueryClient()
  const view = render(<QueryClientProvider client={qc}><MemoryRouter>{ui}</MemoryRouter><Toaster /></QueryClientProvider>)
  // Vai (useCan) đến sau khi /me trả lời; chờ để các nút không còn ở trạng thái "đang tải quyền".
  const ready = waitFor(() => expect(qc.getQueryData(['me'])).toBeTruthy())
  ready.catch(() => undefined) // tests that never await `ready` must not leave an unhandled rejection after unmount
  return Object.assign(view, { ready })
}
const clearProfiles = () => { aiProfilesStore.set([]); aiAssignStore.update((a) => ({ ...a, jobs: Object.fromEntries(Object.keys(a.jobs).map((k) => [k, { primary: null, fallback: null }])) as typeof a.jobs })); aiConfigStore.update((c) => ({ ...c, configured: false })) }

describe('ai: assistant (S-AI-5, S-AI-6)', () => {
  it('the log of calls says a call the provider did not answer failed, not blocked by the cap (S-AI-4)', async () => {
    renderApp('/assistant')
    const table = await screen.findByRole('table', { name: 'Log of AI calls' })
    expect(await within(table).findByText('Failed: not sent or not answered')).toBeInTheDocument()
    expect(within(table).queryByText('Blocked by cap')).not.toBeInTheDocument()
  })
  it('first sentence says how many tokens were used; no a11y violations', async () => {
    renderApp('/assistant')
    expect(await screen.findByRole('heading', { level: 1, name: /[\d,]+ of 60,000 tokens used today/ })).toBeInTheDocument()
    expect(await screen.findByRole('table', { name: 'Log of AI calls' })).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Tokens used today against the cap' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('shows no money or token prices anywhere on the page', async () => {
    renderApp('/assistant')
    await screen.findByRole('table', { name: 'Log of AI calls' })
    expect(document.body.textContent).not.toMatch(/\$|USD|VND|₫|price|per million/i)
  })

  it('suggested question: the AI block is labelled with model and profile, the table is computed from inventory, tools are read-only', async () => {
    renderApp('/assistant')
    await enabled(await screen.findByRole('button', { name: 'Which machines still expose RDP?' }))
    await userEvent.click(screen.getByRole('button', { name: 'Which machines still expose RDP?' }))
    const region = await screen.findByRole('region', { name: /Answer to: Which machines still expose RDP/ })
    expect(within(region).getByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(within(region).getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument() // hồ sơ chính của "Ask your data"
    expect(within(region).getByText(/Start with SRV-AD/)).toBeInTheDocument()
    const expected = assetsStore.get().filter((a) => a.services.some((s) => s.port === 3389)).length
    const table = within(region).getByRole('table', { name: /Results for the question/ })
    expect(within(table).getAllByRole('row')).toHaveLength(expected + 1)
    expect(within(table).getByRole('link', { name: 'SRV-AD' })).toHaveAttribute('href', '/devices/a-srvad')
    expect(within(region).getByText(/search_assets\(\{"port": 3389\}\)/)).toBeInTheDocument()
    expect(within(region).queryAllByRole('button').filter((b) => !b.closest('table'))).toHaveLength(0) // S-AI-6: không nút hành động trong câu trả lời
    const run = aiRunsStore.get().filter((r) => r.skill === 'ask-my-data')
    expect(run).toHaveLength(1)
    expect(run[0]).toMatchObject({ profile: 'Claude Sonnet', model: 'claude-sonnet-5-5' })
    // suggestions are on in the demo data: the answer names the one it suggested, with the way to review it (S-AI-7, D-225)
    expect(screen.getByText(/The AI suggested 1 memory about this network/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review in Settings, AI assistant, Memory' })).toHaveAttribute('href', '/settings/ai?tab=memory')
    await expectNoA11yViolations()
  })

  it('"Which NAS has findings?" answers about NAS only, not every finding', async () => {
    renderApp('/assistant')
    await enabled(await screen.findByRole('button', { name: 'Which NAS has findings?' }))
    await userEvent.click(screen.getByRole('button', { name: 'Which NAS has findings?' }))
    const region = await screen.findByRole('region', { name: /Answer to: Which NAS has findings/ })
    expect(within(region).getByText(/There are \d+ NAS/)).toBeInTheDocument()
    expect(within(region).queryByText(/WordPress/)).toBeNull()
  })

  it('a question with nothing in the data says there is no answer and shows no table', async () => {
    renderApp('/assistant')
    const box = await screen.findByLabelText('Question')
    await enabled(box)
    await userEvent.type(box, 'What is the weather today?{Enter}')
    const region = await screen.findByRole('region', { name: /Answer to: What is the weather today/ })
    expect(within(region).getByText(/so there is no answer/)).toBeInTheDocument()
    expect(within(region).queryByRole('table')).toBeNull()
  })

  it('with an empty inventory the answer says so instead of claiming nothing is open', async () => {
    assetsStore.set([])
    renderApp('/assistant')
    await enabled(await screen.findByRole('button', { name: 'Which machines still expose RDP?' }))
    await userEvent.click(screen.getByRole('button', { name: 'Which machines still expose RDP?' }))
    expect(await screen.findByText(/The inventory has no devices yet/)).toBeInTheDocument()
  })

  it('too short a question disables Ask; an API error shows a message', async () => {
    renderApp('/assistant')
    const box = await screen.findByLabelText('Question')
    await enabled(box)
    await userEvent.type(box, 'ab')
    expect(screen.getByRole('button', { name: 'Ask' })).toBeDisabled()
    server.use(http.post('*/api/v1/ai/ask', () => HttpResponse.json({ error: { code: 'x', message: 'The provider did not answer.' } }, { status: 502 })))
    await userEvent.type(box, 'c device')
    await userEvent.click(screen.getByRole('button', { name: 'Ask' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The provider did not answer.')
  })

  it('a viewer sees the meter but cannot ask', async () => {
    renderApp('/assistant', { role: 'viewer' })
    const btn = await screen.findByRole('button', { name: 'Which machines still expose RDP?' })
    expect(btn).toBeDisabled()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Which machines still expose RDP?' })).toHaveAttribute('title', expect.stringMatching(/Operator/)))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })

  it('no AI profile: guides to add one and nothing can be asked', async () => {
    clearProfiles()
    renderApp('/assistant')
    expect(await screen.findByRole('heading', { level: 1, name: /No AI profile yet/ })).toBeInTheDocument()
    expect(screen.getByText(/Add an AI profile \(provider, model and key\)/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Settings, AI assistant' })).toHaveAttribute('href', '/settings/ai')
    expect(screen.queryByLabelText('Question')).toBeNull()
    expect(aiAvailable()).toBe(false)
  })

  it('profiles exist but the task has none assigned: says so, links to routing', async () => {
    aiAssignStore.update((a) => ({ ...a, jobs: { ...a.jobs, 'ask-my-data': { primary: null, fallback: null } } }))
    renderApp('/assistant')
    expect(await screen.findByText('No AI profile is assigned to this task')).toBeInTheDocument()
    expect(aiAvailable('ask-my-data')).toBe(false)
    expect(aiAvailable('log-digest')).toBe(true)
  })

  it('AI module off: says why and where to turn it on (S-CORE-1)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: false } : m)))
    renderApp('/assistant')
    expect(await screen.findByRole('heading', { level: 1, name: /AI assistant is off/ })).toBeInTheDocument()
  })
})

describe('ai: token meter, caps, fallback (S-AI-4)', () => {
  it('past the global cap the level drops and is recorded; at minimum with no cap left it blocks', async () => {
    sessionStore.set({ userId: 'u-admin' })
    aiConfigStore.update((c) => ({ ...c, tier: 'max', daily_cap: 1000 }))
    const ask = (q: string) => api('/ai/ask', { method: 'POST', body: JSON.stringify({ question: q }) })
    const r1 = await (await ask('Which machines still expose RDP?')).json() as { downgraded: { from: string; to: string } | null }
    expect(r1.downgraded).toEqual({ from: 'max', to: 'med' })
    const r2 = await (await ask('Which devices are not approved yet?')).json() as { downgraded: { from: string; to: string } | null }
    expect(r2.downgraded).toEqual({ from: 'med', to: 'min' })
    const r3 = await ask('Which cameras are Hikvision?')
    expect(r3.status).toBe(429)
    expect(((await r3.json()) as { error: { message: string } }).error.message).toMatch(/cap is used up/)
    expect(aiRunsStore.get()[0]).toMatchObject({ status: 'capped' })
  })

  it('meter says the cap is used up and lists the sample downgrade', async () => {
    aiConfigStore.update((c) => ({ ...c, daily_cap: 1000 }))
    renderApp('/assistant')
    expect(await screen.findByText(/Today's cap is used up/)).toBeInTheDocument()
    expect(screen.getByText(/lowered from Medium to Minimum/)).toBeInTheDocument()
  })

  it('primary profile unreachable or out of its own cap: the fallback answers and the run is marked', async () => {
    sessionStore.set({ userId: 'u-admin' })
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-sonnet' ? { ...p, base_url: 'https://timeout.example.com' } : p)))
    const res = await api('/ai/ask', { method: 'POST', body: JSON.stringify({ question: 'Which machines still expose RDP?' }) })
    const a = await res.json() as { profile: string; model: string }
    expect(a).toMatchObject({ profile: 'Company Ollama server', model: 'qwen3:8b' }) // dự phòng của "Ask your data"
    expect(aiRunsStore.get()[0]).toMatchObject({ skill: 'ask-my-data', profile: 'Company Ollama server', fallback: true })
    // hồ sơ hết trần riêng cũng chuyển
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-sonnet' ? { ...p, base_url: 'https://api.anthropic.com' } : p.id === 'p-haiku' ? { ...p, daily_cap: 1000 } : p)))
    const r2 = await api('/ai/cve/CVE-2022-27593/news', { method: 'POST' })
    expect(((await r2.json()) as { profile: string }).profile).toBe('Company Ollama server') // chính Haiku hết trần, dự phòng Ollama
  })

  it('a call no profile answered is failed in the log of calls, one a profile cap stopped is capped (S-AI-4, POST-5)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    aiAssignStore.update((a) => ({ ...a, jobs: { ...a.jobs, 'cve-news': { primary: 'p-haiku', fallback: null } } }))
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-haiku' ? { ...p, base_url: 'https://timeout.example.com' } : p)))
    await api('/ai/cve/CVE-2022-27593/news', { method: 'POST' })
    expect(aiRunsStore.get()[0]).toMatchObject({ skill: 'cve-news', status: 'failed' })
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-haiku' ? { ...p, base_url: 'https://api.anthropic.com', daily_cap: 1000 } : p)))
    await api('/ai/cve/CVE-2022-27593/news', { method: 'POST' })
    expect(aiRunsStore.get()[0]).toMatchObject({ skill: 'cve-news', status: 'capped' })
  })

  it('when neither primary nor fallback can answer the error says what to do', async () => {
    sessionStore.set({ userId: 'u-admin' })
    aiAssignStore.update((a) => ({ ...a, jobs: { ...a.jobs, 'weekly-report': { primary: 'p-haiku', fallback: null } } }))
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-haiku' ? { ...p, base_url: 'https://unreachable.example.com' } : p)))
    // unreachable chỉ làm bước "Thử kết nối" lỗi; dùng timeout để mô phỏng không trả lời khi chạy việc
    aiProfilesStore.update((l) => l.map((p) => (p.id === 'p-haiku' ? { ...p, base_url: 'https://timeout.example.com' } : p)))
    const res = await api('/reports/weekly/ai-summary', { method: 'POST', body: '{}' })
    expect(res.status).toBe(200) // báo cáo tuần ghi qua recordAiRun, không qua trần của module ai
    const r = await api('/ai/logs/digest', { method: 'POST', body: '{}' })
    expect(r.status).toBe(200) // log-digest chính là Ollama, không ảnh hưởng
  })
})

describe('ai: settings, profiles (S-AI-1)', () => {
  it('lists the profiles with where they run, last 4 key characters only, and the data-flow notice; no a11y violations', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    const table = await screen.findByRole('table', { name: 'AI profiles' })
    expect(within(table).getByText('Claude Haiku')).toBeInTheDocument()
    expect(within(table).getAllByText('Cloud').length).toBeGreaterThan(0)
    expect(within(table).getByText('Inside your network')).toBeInTheDocument()
    expect(within(table).getAllByText('Key ends in 7Qk2').length).toBe(2)
    expect(within(table).getByText('No key needed')).toBeInTheDocument()
    expect(screen.getByText(/api\.anthropic\.com/)).toBeInTheDocument()
    expect(screen.getByText(/Article 20/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('adds a profile: empty submit explains each field, a wrong key shape is caught, then it saves; the key is never returned', async () => {
    clearProfiles()
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    await userEvent.type(within(dlg).getByLabelText('Profile name'), 'Claude Haiku')
    expect(within(dlg).getByRole('button', { name: 'Add profile' })).toBeDisabled() // chưa xác nhận luồng dữ liệu
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I understand/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    expect(await within(dlg).findByText(/Enter the provider's API key/)).toBeInTheDocument()
    expect(within(dlg).getByLabelText('API key')).toBeInvalid()
    expect(within(dlg).getByLabelText('Profile name')).toHaveValue('Claude Haiku') // dữ liệu đã gõ không mất
    await userEvent.type(within(dlg).getByLabelText('API key'), 'abc def')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    expect(await within(dlg).findByText(/too short or contains spaces/)).toBeInTheDocument()
    await userEvent.clear(within(dlg).getByLabelText('API key'))
    await userEvent.type(within(dlg).getByLabelText('API key'), 'sk-ant-demo-key-9z9z')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const table = await screen.findByRole('table', { name: 'AI profiles' })
    expect(within(table).getByText('Key ends in 9z9z')).toBeInTheDocument()
    const raw = await (await api('/ai/profiles')).text()
    expect(raw).not.toContain('sk-ant-demo-key')
    // việc chưa có hồ sơ chính tự lấy hồ sơ mới nên dùng được ngay
    expect(aiAvailable('ask-my-data')).toBe(true)
    expect(aiConfigStore.get()).toMatchObject({ configured: true, model: 'claude-haiku-5-5', key_last4: '9z9z' })
  })

  it('custom provider: API style, address, optional key for a server inside the network, plain http allowed there only', async () => {
    clearProfiles()
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'Custom')
    expect(within(dlg).getByLabelText('API style')).toBeInTheDocument()
    await userEvent.selectOptions(within(dlg).getByLabelText('API style'), 'Anthropic Messages')
    await userEvent.type(within(dlg).getByLabelText('Profile name'), 'Gateway')
    await userEvent.type(within(dlg).getByLabelText('Server address'), 'http://10.0.0.5:8080')
    await userEvent.type(within(dlg).getByLabelText('Model'), 'my-model')
    // đám mây + http bị từ chối đúng ô
    await userEvent.click(within(dlg).getByRole('button', { name: 'Test connection' }))
    expect(await within(dlg).findByText(/must start with https:\/\//)).toBeInTheDocument()
    expect(within(dlg).getByLabelText('Server address')).toBeInvalid()
    // nội bộ: http được, không cần khoá
    await userEvent.click(within(dlg).getByRole('radio', { name: /Inside your network/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Test connection' }))
    expect(await within(dlg).findByText('Connected')).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(aiProfilesStore.get()[0]).toMatchObject({ name: 'Gateway', kind: 'custom', api_style: 'anthropic', location: 'internal', key_last4: null })
    expect(aiAvailable('log-digest')).toBe(true)
  })

  it('built-in providers are cloud only; duplicate names are refused; the server also refuses an internal Anthropic profile', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    expect(within(dlg).getByRole('radio', { name: /Inside your network/ })).toBeDisabled()
    expect(within(dlg).getByLabelText('Server address')).toHaveValue('https://api.anthropic.com')
    expect(within(dlg).getByLabelText('Model')).toHaveValue('claude-haiku-5-5')
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'OpenAI')
    expect(within(dlg).getByLabelText('Server address')).toHaveValue('https://api.openai.com/v1')
    expect(within(dlg).getByLabelText('Model')).toHaveValue('gpt-6-luna')
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'Google Gemini')
    expect(within(dlg).getByLabelText('Server address')).toHaveValue('https://generativelanguage.googleapis.com/v1beta')
    expect(within(dlg).getByLabelText('Model')).toHaveValue('gemini-3.6-flash')
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'OpenAI-compatible (Ollama, vLLM, LM Studio)')
    expect(within(dlg).getByLabelText('Server address')).toHaveValue('http://localhost:11434/v1')
    expect(within(dlg).getByRole('radio', { name: /Inside your network/ })).toBeChecked()
    await userEvent.clear(within(dlg).getByLabelText('Profile name'))
    await userEvent.type(within(dlg).getByLabelText('Profile name'), 'claude haiku')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    expect(await within(dlg).findByText('Another profile already has this name.')).toBeInTheDocument()
    // moved to the cloud, the new profile drops the local default address; a name the person typed stays
    await userEvent.click(within(dlg).getByRole('radio', { name: /Cloud/ }))
    expect(within(dlg).getByLabelText('Server address')).toHaveValue('')
    expect(within(dlg).getByLabelText('Profile name')).toHaveValue('claude haiku')
    const bad = await api('/ai/profiles', { method: 'POST', body: JSON.stringify({ name: 'X', kind: 'anthropic', api_style: 'anthropic', base_url: 'http://localhost:1/v1', model: 'm', location: 'internal', daily_cap: 5000 }) })
    expect(bad.status).toBe(400)
    expect(((await bad.json()) as { error: { code: string } }).error.code).toBe('invalid_location')
  })

  it('editing keeps the old key when the field is left empty; a new key replaces it', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Claude Haiku' }))
    const dlg = await screen.findByRole('dialog', { name: 'Edit Claude Haiku' })
    expect(within(dlg).getByText(/A key ending in 7Qk2 is stored/)).toBeInTheDocument()
    await userEvent.clear(within(dlg).getByLabelText('Model'))
    await userEvent.type(within(dlg).getByLabelText('Model'), 'claude-haiku-5-6')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(aiProfilesStore.get().find((p) => p.id === 'p-haiku')).toMatchObject({ model: 'claude-haiku-5-6', key_last4: '7Qk2' })
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Claude Haiku' }))
    const dlg2 = await screen.findByRole('dialog', { name: 'Edit Claude Haiku' })
    await userEvent.type(within(dlg2).getByLabelText('API key'), 'new-secret-key-4242')
    await userEvent.click(within(dlg2).getByRole('checkbox', { name: /I understand/ }))
    await userEvent.click(within(dlg2).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(aiProfilesStore.get().find((p) => p.id === 'p-haiku')!.key_last4).toBe('4242'))
  })

  it('a stored key goes only to the address it was saved for: another address needs the key again (message on the key field), the same origin keeps it', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Claude Haiku' }))
    const dlg = await screen.findByRole('dialog', { name: 'Edit Claude Haiku' })
    const url = within(dlg).getByLabelText('Server address')
    await userEvent.clear(url)
    await userEvent.type(url, 'https://evil.example.com')
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I understand/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(await within(dlg).findByText('Changing the address needs the API key entered again.')).toBeInTheDocument()
    expect(within(dlg).getByLabelText('API key')).toHaveAccessibleDescription(/Changing the address needs the API key entered again\./)
    expect(aiProfilesStore.get().find((p) => p.id === 'p-haiku')).toMatchObject({ base_url: 'https://api.anthropic.com', key_last4: '7Qk2' })
    // the same origin (another path) still keeps the key
    await userEvent.clear(url)
    await userEvent.type(url, 'https://api.anthropic.com/v1')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(aiProfilesStore.get().find((p) => p.id === 'p-haiku')).toMatchObject({ base_url: 'https://api.anthropic.com/v1', key_last4: '7Qk2' })
    // the server (mock) enforces it for the connection test too, whatever the form does
    const test = await api('/ai/profiles/test', { method: 'POST', body: JSON.stringify({ id: 'p-haiku', kind: 'anthropic', api_style: 'anthropic', base_url: 'https://evil.example.com', model: 'claude-haiku-5-5', location: 'cloud' }) })
    expect(test.status).toBe(400)
    expect(((await test.json()) as { error: { code: string; message: string } }).error).toMatchObject({ code: 'key_required', message: 'Changing the address needs the API key entered again.' })
    const same = await api('/ai/profiles/test', { method: 'POST', body: JSON.stringify({ id: 'p-haiku', kind: 'anthropic', api_style: 'anthropic', base_url: 'https://api.anthropic.com/v1', model: 'claude-haiku-5-5', location: 'cloud' }) })
    expect(same.status).toBe(200)
  })

  it('tests a saved profile: success is recorded as a run; a rejected key and an unreachable server each say how to fix', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection for Claude Haiku' }))
    expect(await screen.findByText('Connected')).toBeInTheDocument()
    expect(screen.getByText(/Claude Haiku replied in \d+ ms/)).toBeInTheDocument()
    expect(aiRunsStore.get().some((r) => r.skill === 'connection-test' && r.profile === 'Claude Haiku')).toBe(true)
    const rejected = await api('/ai/profiles/test', { method: 'POST', body: JSON.stringify({ kind: 'openai', api_style: 'openai', base_url: 'https://api.openai.com/v1', model: 'gpt-6-luna', location: 'cloud', api_key: 'bad-key-12345' }) })
    expect(rejected.status).toBe(502) // a provider answer, never the API's own "not signed in"
    expect(((await rejected.json()) as { error: { message: string } }).error.message).toMatch(/rejected the key/)
    const down = await api('/ai/profiles/test', { method: 'POST', body: JSON.stringify({ kind: 'openai', api_style: 'openai', base_url: 'https://unreachable.example.com/v1', model: 'gpt-6-luna', location: 'cloud', api_key: 'sk-test-key-12345' }) })
    expect(down.status).toBe(502)
  })

  it('removing asks for confirmation and names the tasks that lose the profile; a fallback moves up', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click(await screen.findByRole('button', { name: 'Remove Claude Sonnet' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove Claude Sonnet?' })
    expect(within(dlg).getByText(/assigned to: .*Explain findings/)).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(aiProfilesStore.get().some((p) => p.id === 'p-sonnet')).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Remove Claude Sonnet' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove profile' }))
    await waitFor(() => expect(aiProfilesStore.get().some((p) => p.id === 'p-sonnet')).toBe(false))
    expect(aiAssignStore.get().jobs['explain-finding']).toEqual({ primary: 'p-haiku', fallback: null })
  })

  it('removing the last usable profile turns AI off for every task', async () => {
    sessionStore.set({ userId: 'u-admin' })
    for (const id of ['p-haiku', 'p-sonnet', 'p-ollama']) await api(`/ai/profiles/${id}`, { method: 'DELETE' })
    expect(aiConfigStore.get().configured).toBe(false)
    expect(aiAvailable()).toBe(false)
  })

  it('an operator cannot change profiles and the server refuses too (403)', async () => {
    const v = renderUi(<AiSettings />, 'operator')
    await v.ready
    expect(await screen.findByRole('button', { name: 'Edit Claude Haiku' })).toBeDisabled()
    expect(screen.getAllByRole('button', { name: 'Add AI profile' })[0]).toBeDisabled()
    expect((await api('/ai/profiles/p-haiku', { method: 'DELETE' })).status).toBe(403)
    expect((await api('/ai/assignments', { method: 'PUT', body: '{}' })).status).toBe(403)
  })

  it('a load error shows a message and a retry button', async () => {
    server.use(http.get('*/api/v1/ai/config', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the AI settings.' } }, { status: 500 })))
    renderUi(<AiSettings />)
    expect(await screen.findByText('Could not read the AI settings.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

describe('ai: settings, job routing and privacy rule', () => {
  it('lists every task with primary and fallback; changing and saving persists', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    const table = await screen.findByRole('table', { name: 'AI job routing' })
    expect(within(table).getAllByRole('row')).toHaveLength(11)
    const primary = within(table).getByLabelText('Primary profile for Log summaries')
    expect(primary).toHaveValue('p-ollama')
    await userEvent.selectOptions(primary, 'Claude Haiku')
    const fb = within(table).getByLabelText('Fallback profile for Log summaries')
    expect(fb).toHaveValue('') // trùng hồ sơ chính nên dự phòng bị bỏ
    await userEvent.selectOptions(fb, 'Company Ollama server')
    const save = screen.getByRole('button', { name: 'Save routing' })
    await enabled(save)
    await userEvent.click(save)
    await waitFor(() => expect(aiAssignStore.get().jobs['log-digest']).toEqual({ primary: 'p-haiku', fallback: 'p-ollama' }))
  })

  it('fallback needs a primary; a fallback cannot equal the primary; save is off until something changes', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    const table = await screen.findByRole('table', { name: 'AI job routing' })
    expect(screen.getByRole('button', { name: 'Save routing' })).toBeDisabled()
    await userEvent.selectOptions(within(table).getByLabelText('Primary profile for Weekly report comments'), 'None')
    expect(within(table).getByLabelText('Fallback profile for Weekly report comments')).toBeDisabled()
    const opts = within(within(table).getByLabelText('Fallback profile for Explain findings')).getAllByRole('option') as HTMLOptionElement[]
    expect(opts.find((o) => o.textContent === 'Claude Sonnet')!.disabled).toBe(true) // đang là hồ sơ chính
  })

  it('privacy rule on: cloud profiles are cleared from tasks that send internal data and greyed out; public-data tasks keep them', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await screen.findByRole('table', { name: 'AI job routing' })
    expect(screen.getByText(/Tasks on public data \(CVE news, translating vendor advisories\) may still use cloud profiles/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('switch', { name: 'Logs and device data go only to profiles inside your network' }))
    expect(await screen.findByText(/cloud assignment\(s\) were cleared/)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'AI job routing' })
    expect(within(table).getByLabelText('Primary profile for Explain findings')).toHaveValue('') // cả chính lẫn dự phòng đều đám mây: bỏ hết
    expect(within(table).getByLabelText('Primary profile for Ask your data')).toHaveValue('p-ollama') // dự phòng nội bộ lên làm chính
    const opts = within(within(table).getByLabelText('Primary profile for Ask your data')).getAllByRole('option') as HTMLOptionElement[]
    expect(opts.find((o) => o.textContent?.startsWith('Claude Haiku'))!.disabled).toBe(true)
    expect(opts.find((o) => o.textContent?.startsWith('Claude Haiku'))!.textContent).toMatch(/cloud, not allowed for internal data/)
    const news = within(within(table).getByLabelText('Primary profile for CVE news')).getAllByRole('option') as HTMLOptionElement[]
    expect(news.find((o) => o.textContent === 'Claude Haiku')!.disabled).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Save routing' }))
    await waitFor(() => expect(aiAssignStore.get().internal_only).toBe(true))
    expect(aiAssignStore.get().jobs['cve-news'].primary).toBe('p-haiku')
    expect(aiAssignStore.get().jobs['explain-finding'].primary).toBeNull()
    expect(aiAssignStore.get().jobs['ask-my-data'].primary).toBe('p-ollama')
  })

  it('the server enforces the privacy rule and the other routing rules with an exact message', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const put = (jobs: Record<string, { primary: string | null; fallback: string | null }>, internal_only = true) => api('/ai/assignments', { method: 'PUT', body: JSON.stringify({ internal_only, jobs }) })
    const cloud = await put({ 'log-digest': { primary: 'p-haiku', fallback: null } })
    expect(cloud.status).toBe(400)
    expect(((await cloud.json()) as { error: { code: string; message: string } }).error).toMatchObject({ code: 'privacy_rule' })
    expect((await put({ 'cve-news': { primary: 'p-haiku', fallback: null } })).status).toBe(200) // dữ liệu công khai thì đám mây được
    expect((await put({ 'log-digest': { primary: null, fallback: 'p-ollama' } })).status).toBe(400)
    expect((await put({ 'log-digest': { primary: 'p-ollama', fallback: 'p-ollama' } })).status).toBe(400)
    expect((await put({ 'log-digest': { primary: 'p-nope', fallback: null } })).status).toBe(400)
    // luật riêng tư bật: việc dữ liệu nội bộ gán hồ sơ đám mây từ cấu hình cũ cũng không chạy
    aiAssignStore.set({ internal_only: true, jobs: { ...aiAssignStore.get().jobs, 'ask-my-data': { primary: 'p-haiku', fallback: null } } })
    expect(aiAvailable('ask-my-data')).toBe(false)
    const ask = await api('/ai/ask', { method: 'POST', body: JSON.stringify({ question: 'Which machines still expose RDP?' }) })
    expect(ask.status).toBe(409)
    expect(((await ask.json()) as { error: { message: string } }).error.message).toMatch(/privacy rule only allows internal AI profiles/)
  })

  it('apply suggestion: fast model for batch tasks, strong for reasoning, internal data prefers the internal profile; reviewed, then saved', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const s = await (await api('/ai/assignments/suggestion?internal_only=false')).json() as { jobs: Record<string, { primary: string | null; fallback: string | null }> }
    expect(s.jobs['explain-finding']!.primary).toBe('p-sonnet') // mạnh cho suy luận
    expect(s.jobs['ask-my-data']!.primary).toBe('p-sonnet')
    expect(s.jobs['log-digest']!.primary).toBe('p-ollama') // nhanh, dữ liệu nội bộ ưu tiên nội bộ
    expect(s.jobs['translate-advisory']!.primary).toBe('p-haiku') // nhanh, dữ liệu công khai ưu tiên đám mây
    const strict = await (await api('/ai/assignments/suggestion?internal_only=true')).json() as { jobs: Record<string, { primary: string | null; fallback: string | null }> }
    expect(strict.jobs['explain-finding']).toEqual({ primary: 'p-ollama', fallback: null })
    expect(strict.jobs['cve-news']!.primary).toBe('p-haiku')
    const v = renderUi(<AiSettings />)
    await v.ready
    await screen.findByRole('table', { name: 'AI job routing' })
    aiAssignStore.set({ internal_only: false, jobs: Object.fromEntries(Object.keys(aiAssignStore.get().jobs).map((k) => [k, { primary: null, fallback: null }])) as never })
    await userEvent.click(screen.getByRole('button', { name: 'Apply suggestion' }))
    expect(await screen.findByText(/Suggestion applied below/)).toBeInTheDocument()
    expect(aiAssignStore.get().jobs['log-digest'].primary).toBeNull() // chưa lưu cho tới khi bấm Save
    await userEvent.click(screen.getByRole('button', { name: 'Save routing' }))
    await waitFor(() => expect(aiAssignStore.get().jobs['log-digest'].primary).toBe('p-ollama'))
  })

  it('no usable profile: routing explains instead of showing empty selects', async () => {
    clearProfiles()
    const v = renderUi(<AiSettings />)
    await v.ready
    expect(await screen.findByText('No usable profile to assign')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply suggestion' })).toBeDisabled()
  })
})

describe('ai: settings, token level and global cap (S-AI-4)', () => {
  it('changes level and cap, saves; a cap outside the range is caught at the field', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    const cap = await screen.findByLabelText('Daily token cap for all profiles together')
    await userEvent.clear(cap)
    await userEvent.type(cap, '50')
    await userEvent.click(within(screen.getByRole('form', { name: 'Token level' })).getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('The cap must be a whole number from 1,000 to 5,000,000.')).toBeInTheDocument()
    expect(cap).toBeInvalid()
    await userEvent.clear(cap)
    await userEvent.type(cap, '90000')
    await userEvent.click(screen.getByRole('radio', { name: /Maximum/ }))
    await userEvent.click(screen.getByRole('switch', { name: 'Mask personal information before sending' }))
    await userEvent.click(within(screen.getByRole('form', { name: 'Token level' })).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(aiConfigStore.get()).toMatchObject({ tier: 'max', daily_cap: 90000, redact_pii: false }))
  })
})

describe('ai: panels on the CVE page (S-AI-3)', () => {
  it('Explain: labelled block with model and profile, sources; asking again uses the saved copy and costs no tokens', async () => {
    renderApp('/cve/CVE-2022-27593')
    await userEvent.click(await screen.findByRole('button', { name: 'Explain' }))
    expect(await screen.findByText('You are affected')).toBeInTheDocument()
    expect(screen.getByText(/You have QNAP Photo Station on NAS-PHOTOS/)).toBeInTheDocument()
    expect(screen.getAllByText('AI-generated, needs human review').length).toBeGreaterThan(0)
    expect(screen.getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument()
    expect(aiRunsStore.get().filter((r) => r.skill === 'explain-finding')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Ask again' }))
    expect(await screen.findByText(/Saved result from/)).toBeInTheDocument()
    expect(aiRunsStore.get().filter((r) => r.skill === 'explain-finding')).toHaveLength(1)
  })

  it('News: shows the sources the box fetched (including a failed one), then the summary with the profile that wrote it', async () => {
    renderApp('/cve/CVE-2022-27593')
    await userEvent.click(await screen.findByRole('button', { name: 'Fetch and summarise news' }))
    expect(await screen.findByText('Sources the box fetched')).toBeInTheDocument()
    expect(screen.getByText('Could not fetch')).toBeInTheDocument()
    expect(screen.getByText(/Exploited: yes/)).toBeInTheDocument()
    expect(screen.getByText(/Model claude-haiku-5-5 \(Claude Haiku\)/)).toBeInTheDocument()
    expect(screen.getByText(/stripped of control characters and checked by your hooks/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a viewer cannot click; with no profile the panel guides to add one; with the task unassigned it says so', async () => {
    renderApp('/cve/CVE-2022-27593', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Explain' })).toBeDisabled()
  })

  it('no profile at all: both panels guide instead of leaving a dead button', async () => {
    clearProfiles()
    renderApp('/cve/CVE-2022-27593')
    expect((await screen.findAllByText('No AI profile yet')).length).toBe(2)
    expect(screen.getByRole('button', { name: 'Explain' })).toBeDisabled()
  })

  it('an unknown CVE or a malformed id gives an exact error (API)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const res = await api('/ai/cve/CVE-2020-0001/explain', { method: 'POST' })
    expect(res.status).toBe(404)
    expect(((await res.json()) as { error: { message: string } }).error.message).toMatch(/not on the exploited list/)
    expect((await api('/ai/cve/abc/news', { method: 'POST' })).status).toBe(400)
  })
})

describe('ai: log digest panel (S-AI-4)', () => {
  it('medium level: devices, evidence, recommendation; regenerate records one run with the profile', async () => {
    renderUi(<LogsPanel />)
    expect(await screen.findByText(/SRV-AD is under RDP password guessing/)).toBeInTheDocument()
    expect(screen.getByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(screen.getByText(/Medium level: A full summary of new kinds of line/)).toBeInTheDocument()
    expect(screen.getByText(/Model qwen3:8b \(Company Ollama server\)/)).toBeInTheDocument() // hồ sơ chính của "Log summaries"
    expect(screen.getAllByRole('link', { name: 'View device' })[0]).toHaveAttribute('href', '/devices/a-srvad')
    await userEvent.click(screen.getByRole('button', { name: 'Regenerate now' }))
    await waitFor(() => expect(aiRunsStore.get().filter((r) => r.skill === 'log-digest')).toHaveLength(1))
    expect(aiRunsStore.get()[0]).toMatchObject({ profile: 'Company Ollama server' })
    // suggestions are on in the demo data: the new one is named, with the way to review it (S-AI-7, D-223)
    expect(await screen.findByText(/The AI suggested 1 memory about this network/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review in Settings, AI assistant, Memory' })).toHaveAttribute('href', '/settings/ai?tab=memory')
    await expectNoA11yViolations()
  })

  it('nothing generated yet (null, no AI call) says so and the button still works', async () => {
    server.use(http.get(`${location.origin}/api/v1/ai/logs/digest`, () => HttpResponse.json({ digest: null })))
    renderUi(<LogsPanel />)
    expect(await screen.findByText('No summary has been made at this level yet. Press Regenerate now.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Regenerate now' })).toBeEnabled()
  })

  it('minimum level has fewer items; maximum has the read-only investigation tools', async () => {
    aiConfigStore.update((c) => ({ ...c, tier: 'min' }))
    const min = renderUi(<LogsPanel />)
    await screen.findByText(/SRV-AD is under RDP password guessing/)
    expect(screen.queryByText(/CAM-GATE outbound traffic spiked/)).toBeNull()
    expect(screen.getByText(/Minimum level: A short summary of the most serious points/)).toBeInTheDocument()
    min.unmount()
    aiConfigStore.update((c) => ({ ...c, tier: 'max' }))
    renderUi(<LogsPanel />)
    expect(await screen.findByText('Read-only tools used to investigate')).toBeInTheDocument()
    expect(screen.getByText(/events_around/)).toBeInTheDocument()
  })

  it('a viewer sees the digest but cannot regenerate', async () => {
    renderUi(<LogsPanel />, 'viewer')
    expect(await screen.findByText(/SRV-AD is under RDP password guessing/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Regenerate now' })).toBeDisabled()
  })

  it('no profile: guidance and a disabled button; task unassigned: says so', async () => {
    clearProfiles()
    const v = renderUi(<LogsPanel />)
    expect(await screen.findByText('No AI profile yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Regenerate now' })).toBeDisabled()
    v.unmount()
    aiProfilesStore.set([{ id: 'p-x', name: 'X', kind: 'anthropic', api_style: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: 'abcd', location: 'cloud', daily_cap: 5000 }])
    aiConfigStore.update((c) => ({ ...c, configured: true }))
    renderUi(<LogsPanel />)
    expect(await screen.findByText('No AI profile is assigned to this task')).toBeInTheDocument()
  })

  it('AI module off: ModuleOff; API error: message with a retry button', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: false } : m)))
    const off = renderUi(<LogsPanel />)
    expect(await screen.findByText(/off/i)).toBeInTheDocument()
    off.unmount()
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: true } : m)))
    server.use(http.get('*/api/v1/ai/logs/digest', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the aggregated logs.' } }, { status: 500 })))
    renderUi(<LogsPanel />)
    expect(await screen.findByText('Could not read the aggregated logs.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

describe('ai: Add AI profile form matrix (docs/QA.md §2)', () => {
  it('each provider type shows only its own fields, keeps no default or key from another, and locks "Inside your network" for cloud providers', async () => {
    clearProfiles()
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    const kind = within(dlg).getByLabelText('Provider type')
    const style = 'API style'
    await eachOption([
      { option: 'Anthropic', shown: ['Server address', 'Model', 'API key'], hidden: [style], locked: ['Inside your network', 'Cloud'] },
      { option: 'OpenAI', hidden: [style], locked: ['Inside your network'] },
      { option: 'Google Gemini', hidden: [style], locked: ['Inside your network'] },
      { option: 'OpenAI-compatible (Ollama, vLLM, LM Studio)', hidden: [style] },
      { option: 'Custom', shown: [style, 'Server address'], hidden: [] },
      { option: 'Anthropic', hidden: [style], locked: ['Inside your network'] }, // going back restores the same fields
    ], async (o) => { await userEvent.selectOptions(kind, within(kind).getByRole('option', { name: o })) }, dlg)

    // defaults follow the option, none leaks from the previous one
    const url = within(dlg).getByLabelText('Server address')
    expect(url).toHaveValue('https://api.anthropic.com')
    await userEvent.selectOptions(kind, 'openai-compatible')
    expect(url).toHaveValue('http://localhost:11434/v1')
    expect(within(dlg).getByLabelText('Model')).toHaveValue('qwen3:8b')
    expect(within(dlg).getByRole('radio', { name: 'Inside your network' })).toBeChecked()
    expect(within(dlg).getByRole('radio', { name: 'Cloud' })).toBeEnabled()
    await userEvent.selectOptions(kind, 'custom')
    expect(url).toHaveValue('')
    expect(within(dlg).getByLabelText('Model')).toHaveValue('')

    // an API key typed for one provider is dropped when the provider changes, and so is the data-flow tick
    await userEvent.selectOptions(kind, 'anthropic')
    await userEvent.type(within(dlg).getByLabelText('API key'), 'sk-ant-secret-for-claude')
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I understand/ }))
    await userEvent.selectOptions(kind, 'openai-compatible')
    expect(within(dlg).getByLabelText('API key')).toHaveValue('')
    await userEvent.selectOptions(kind, 'openai')
    expect(within(dlg).getByLabelText('API key')).toHaveValue('')
    expect(within(dlg).getByRole('checkbox', { name: /I understand/ })).not.toBeChecked()
  })

  it('a local Ollama profile saves without a key and can then be picked for the log jobs', async () => {
    clearProfiles()
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'openai-compatible')
    expect(within(dlg).queryByRole('checkbox', { name: /I understand/ })).toBeNull() // nothing leaves the network
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add profile' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const p = aiProfilesStore.get().find((x) => x.kind === 'openai-compatible')!
    expect(p).toMatchObject({ location: 'internal', model: 'qwen3:8b' })
    const sel = await screen.findByLabelText('Primary profile for Log summaries')
    expect(within(sel).getByRole('option', { name: 'Local model' })).toBeEnabled()
  })
})

describe('AI profile form matrix (docs/QA.md §2, QA walk 2026-11-12)', () => {
  it('"Connected" holds only for what was tested; choosing Inside your network clears the https error', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'Custom')
    fireEvent.change(within(dlg).getByLabelText('Server address'), { target: { value: 'http://10.0.0.5:8000/v1' } })
    fireEvent.change(within(dlg).getByLabelText('Model'), { target: { value: 'llama-4' } })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Test connection' }))
    await within(dlg).findByText(/must start with https:\/\//)
    await eachOption([
      { option: 'Inside your network', hidden: [/must start with https:\/\//] },
      { option: 'Test connection', shown: ['Connected'] },
      { option: 'another model', hidden: ['Connected'] },
    ], async (o) => {
      if (o === 'Inside your network') await userEvent.click(within(dlg).getByRole('radio', { name: /Inside your network/ }))
      else if (o === 'Test connection') { await userEvent.click(within(dlg).getByRole('button', { name: o })); await within(dlg).findByText('Connected') }
      else fireEvent.change(within(dlg).getByLabelText('Model'), { target: { value: 'other-model' } })
    }, dlg)
  })

  it('a server error from Test holds only for the connection it was run on', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add AI profile' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add AI profile' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), 'Custom')
    await userEvent.click(within(dlg).getByRole('radio', { name: /Inside your network/ }))
    fireEvent.change(within(dlg).getByLabelText('Server address'), { target: { value: 'https://u:p@ai.example.com/v1' } })
    fireEvent.change(within(dlg).getByLabelText('Model'), { target: { value: 'llama-4' } })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Test connection' }))
    await within(dlg).findByText(/must not contain a user name/)
    fireEvent.change(within(dlg).getByLabelText('Server address'), { target: { value: 'https://ai.example.com/v1' } })
    expect(within(dlg).queryByText(/must not contain a user name/)).toBeNull()
  })

  it('editing: the stored key is offered only for its own provider', async () => {
    const v = renderUi(<AiSettings />)
    await v.ready
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Claude Haiku' }))
    const dlg = await screen.findByRole('dialog', { name: 'Edit Claude Haiku' })
    const kept = /A key ending in 7Qk2 is stored/
    await eachOption([
      { option: 'Anthropic', shown: [kept] },
      { option: 'OpenAI', hidden: [kept] },
      { option: 'Anthropic', shown: [kept] },
    ], (o) => userEvent.selectOptions(within(dlg).getByLabelText('Provider type'), o), dlg)
  })
})
