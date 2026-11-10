import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean, sampleStart } from './clean'

// QA như người dùng thật cho module ai (S-AI-1..6): nhiều hồ sơ AI, phân việc, dự phòng, luật riêng tư. UI chỉ có tiếng Anh (D-28).
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/ai.spec.ts
// Máy dùng chung với nhiều agent nên chậm: nới thời gian mỗi test.
test.describe.configure({ timeout: 150_000 })

/** Đổi phiên sang tài khoản khác: ép core_session trước mỗi lần tải trang (một lần ghi muộn của trang cũ không đè được). */
async function asUser(page: Page, userId: string) {
  await page.addInitScript((u) => {
    try {
      const k = 'vedette-mock-db-v4'
      const raw = localStorage.getItem(k)
      if (raw) { const db = JSON.parse(raw); db.core_session = { userId: u }; localStorage.setItem(k, JSON.stringify(db)) }
    } catch { /* bỏ qua */ }
  }, userId)
  await page.reload()
}
const noHorizontalScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
const device = (page: Page) => (page.viewportSize()?.width ?? 1366) < 700 ? 'mobile' : 'desktop'
const noVietnamese = async (page: Page) => expect(await page.locator('body').innerText()).not.toMatch(DIACRITICS)
const addProfile = (page: Page) => page.getByRole('button', { name: 'Add AI profile' }).first().click()

test.describe('ai: clean install', () => {
  test('no profile yet: every page guides to add one; no sample data; no console errors', async ({ page }) => {
    const errors = collectErrors(page)
    await finishClean(page)
    await page.goto('/assistant')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('No AI profile yet')
    await expect(page.getByText('Add an AI profile (provider, model and key) to use this.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Settings, AI assistant' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Token meter' })).toHaveCount(0) // chưa nối và chưa chạy: không phô số 0
    await expect(page.getByText('claude-haiku')).toHaveCount(0)
    await shot(page, 'ai', `assistant-clean-${device(page)}`)
    await expectAccessible(page, 'assistant, clean')
    await noHorizontalScroll(page)
    await noVietnamese(page)
    await page.goto('/cve/CVE-2022-27593')
    await expect(page.getByText('No AI profile yet').first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
    expect(errors).toEqual([])
  })

  test('add the first profile from scratch: empty, wrong key shape, rejected key, unreachable server, success; assigned to every task at once; ask with no devices', async ({ page }) => {
    const errors = collectErrors(page)
    await finishClean(page)
    await page.goto('/settings/ai')
    await expect(page.getByText('No AI profile yet').first()).toBeVisible()
    await expect(page.getByText('No usable profile to assign')).toBeVisible()
    await shot(page, 'ai', `settings-clean-${device(page)}`)
    await expectAccessible(page, 'settings, clean')
    await addProfile(page)
    const dlg = page.getByRole('dialog', { name: 'Add AI profile' })
    await expect(dlg.getByLabel('Model')).toHaveValue('claude-haiku-5-5') // không để trống model
    await expect(dlg.getByRole('radio', { name: /Inside your network/ })).toBeDisabled() // Anthropic chỉ chạy đám mây
    await dlg.getByLabel('Profile name').fill('Claude Haiku')
    await dlg.getByRole('checkbox', { name: /I understand/ }).check()
    await dlg.getByRole('button', { name: 'Add profile' }).click()
    await expect(dlg.getByText(/Enter the provider's API key/)).toBeVisible()
    await expect(dlg.getByLabel('Profile name')).toHaveValue('Claude Haiku') // dữ liệu đã gõ không mất
    await dlg.getByLabel('API key').fill('abc def')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByText(/too short or contains spaces/)).toBeVisible()
    await dlg.getByLabel('API key').fill('bad-key-1234567')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('The provider rejected the key')
    await dlg.getByLabel('API key').fill('sk-ant-demo-key-9z9z')
    await dlg.getByLabel('Server address').fill('https://unreachable.example.com')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('Could not connect to unreachable.example.com')
    await dlg.getByLabel('Server address').fill('https://api.anthropic.com')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByText('Connected')).toBeVisible()
    await dlg.getByLabel('Daily token cap for this profile').fill('50')
    await dlg.getByRole('button', { name: 'Add profile' }).click()
    await expect(dlg.getByText(/The cap must be a whole number/)).toBeVisible()
    await dlg.getByLabel('Daily token cap for this profile').fill('20000')
    await dlg.getByLabel('API key').press('Enter') // Enter gửi form
    await expect(page.getByText('AI profile added').first()).toBeVisible()
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText('Key ends in 9z9z')).toBeVisible()
    await page.reload()
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText('Key ends in 9z9z')).toBeVisible()
    await expect(page.getByText('sk-ant-demo-key')).toHaveCount(0) // khoá không bao giờ hiện lại
    // việc chưa có hồ sơ chính tự lấy hồ sơ mới: dùng được ngay
    await expect(page.getByLabel('Primary profile for Ask your data')).toHaveValue(/.+/)
    await page.goto('/assistant')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('tokens used today')
    await page.getByRole('button', { name: 'Which machines still expose RDP?' }).click()
    await expect(page.getByText(/The inventory has no devices yet/)).toBeVisible()
    await expect(page.getByText('AI-generated, needs human review').first()).toBeVisible()
    await shot(page, 'ai', `assistant-clean-asked-${device(page)}`)
    // trang Log chưa có nguồn log: không dựng khung AI (không có gì để tóm tắt)
    await page.goto('/logs')
    await expect(page.getByText('No log sources yet')).toBeVisible()
    await noVietnamese(page)
    expect(errors.filter((e) => !/status of (401|502)/.test(e))).toEqual([]) // 401/502: lỗi thử kết nối cố ý
  })

  test('provider types fill the right address and model; Custom has an API style; a server inside the network may use http and needs no key', async ({ page }) => {
    await finishClean(page)
    await page.goto('/settings/ai')
    await addProfile(page)
    const dlg = page.getByRole('dialog', { name: 'Add AI profile' })
    const kind = dlg.getByLabel('Provider type')
    await kind.selectOption({ label: 'OpenAI' })
    await expect(dlg.getByLabel('Server address')).toHaveValue('https://api.openai.com/v1')
    await expect(dlg.getByLabel('Model')).toHaveValue('gpt-6-luna')
    await kind.selectOption({ label: 'Google Gemini' })
    await expect(dlg.getByLabel('Server address')).toHaveValue('https://generativelanguage.googleapis.com/v1beta')
    await expect(dlg.getByLabel('Model')).toHaveValue('gemini-3.6-flash')
    await kind.selectOption({ label: 'OpenAI-compatible (Ollama, vLLM, LM Studio)' })
    await expect(dlg.getByLabel('Server address')).toHaveValue('http://localhost:11434/v1')
    await expect(dlg.getByRole('radio', { name: /Inside your network/ })).toBeChecked()
    await expect(dlg.getByText(/does not leave your network/)).toBeVisible()
    await expect(dlg.getByRole('checkbox', { name: /I understand/ })).toHaveCount(0) // nội bộ: không cần xác nhận gửi ra ngoài
    await dlg.getByRole('button', { name: 'Test connection' }).click() // không cần khoá
    await expect(dlg.getByText('Connected')).toBeVisible()
    await kind.selectOption({ label: 'Custom' })
    await expect(dlg.getByLabel('API style')).toBeVisible()
    await dlg.getByLabel('API style').selectOption({ label: 'Anthropic Messages' })
    await dlg.getByLabel('Profile name').fill('Gateway')
    await dlg.getByLabel('Server address').fill('http://10.0.0.5:8080')
    await dlg.getByLabel('Model').fill('my-model')
    await dlg.getByRole('button', { name: 'Test connection' }).click() // đám mây + http: bị từ chối đúng ô
    await expect(dlg.getByText(/must start with https:\/\//)).toBeVisible()
    await expect(dlg.getByLabel('Server address')).toHaveAttribute('aria-invalid', 'true')
    await dlg.getByRole('radio', { name: /Inside your network/ }).click()
    await dlg.getByRole('button', { name: 'Add profile' }).click()
    await expect(page.getByText('AI profile added').first()).toBeVisible()
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText('Gateway')).toBeVisible()
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText('No key needed')).toBeVisible()
  })
})

test.describe('ai: sample data', () => {
  test('profiles: list, test, edit keeps the key, remove with confirmation naming the tasks it affects', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/settings/ai')
    const table = page.getByRole('region', { name: 'AI profiles' })
    await expect(table.getByText('Claude Haiku')).toBeVisible()
    await expect(table.getByText('Inside your network')).toBeVisible()
    await expect(table.getByText('Key ends in 7Qk2').first()).toBeVisible()
    await shot(page, 'ai', `settings-${device(page)}`)
    await expectAccessible(page, 'settings')
    await noHorizontalScroll(page)
    await page.getByRole('button', { name: 'Test connection for Claude Haiku' }).click()
    await expect(page.getByText(/Claude Haiku replied in \d+ ms/)).toBeVisible()
    await page.getByRole('button', { name: 'Edit Claude Haiku' }).click()
    const dlg = page.getByRole('dialog', { name: 'Edit Claude Haiku' })
    await expect(dlg.getByText(/A key ending in 7Qk2 is stored/)).toBeVisible()
    await dlg.getByLabel('Model').fill('claude-haiku-5-6')
    await dlg.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('AI profile saved').first()).toBeVisible()
    await expect(table.getByText('claude-haiku-5-6')).toBeVisible()
    await expect(table.getByText('Key ends in 7Qk2').first()).toBeVisible()
    await page.getByRole('button', { name: 'Remove Claude Sonnet' }).click()
    await expect(page.getByRole('dialog')).toContainText('Explain findings')
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await expect(table.getByText('Claude Sonnet')).toBeVisible()
    await page.getByRole('button', { name: 'Remove Claude Sonnet' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Remove profile' }).click()
    await expect(page.getByText('Claude Sonnet removed').first()).toBeVisible()
    await expect(table.getByText('Claude Sonnet')).toHaveCount(0)
    await expect(page.getByLabel('Primary profile for Explain findings')).toHaveValue(/.+/) // dự phòng lên làm chính
    await noVietnamese(page)
    expect(errors).toEqual([])
  })

  test('job routing: privacy rule clears cloud profiles for internal data and greys them out; suggestion; save; persists', async ({ page }) => {
    await sampleStart(page)
    await page.goto('/settings/ai')
    const rule = page.getByRole('switch', { name: 'Logs and device data go only to profiles inside your network' })
    await expect(page.getByText(/Tasks on public data \(CVE news, translating vendor advisories\) may still use cloud profiles/)).toBeVisible()
    await rule.click()
    await expect(page.getByText(/cloud assignment\(s\) were cleared/)).toBeVisible()
    await expect(page.getByLabel('Primary profile for Explain findings')).toHaveValue('') // cả chính lẫn dự phòng đều đám mây
    const optionsOf = (label: string) => page.getByLabel(label).locator('option')
    await expect(optionsOf('Primary profile for Ask your data').filter({ hasText: 'Claude Haiku' })).toBeDisabled()
    await expect(optionsOf('Primary profile for Ask your data').filter({ hasText: 'Claude Haiku' })).toContainText('cloud, not allowed for internal data')
    await expect(optionsOf('Primary profile for CVE news').filter({ hasText: 'Claude Haiku' })).toBeEnabled()
    await page.getByRole('button', { name: 'Apply suggestion' }).click()
    await expect(page.getByText(/Suggestion applied below/)).toBeVisible()
    await expect(page.getByLabel('Primary profile for Explain findings')).toHaveValue(/.+/)
    await shot(page, 'ai', `routing-${device(page)}`)
    await expectAccessible(page, 'routing')
    await page.getByRole('button', { name: 'Save routing' }).click()
    await expect(page.getByText('Job routing saved').first()).toBeVisible()
    await page.reload()
    await expect(rule).toBeChecked()
    await expect(page.getByLabel('Primary profile for Explain findings')).toHaveValue(/.+/)
    // luật riêng tư chặn việc gửi dữ liệu nội bộ tới đám mây: câu hỏi vẫn chạy nhờ hồ sơ nội bộ
    await page.goto('/assistant')
    await page.getByRole('button', { name: 'Which machines still expose RDP?' }).click()
    await expect(page.getByText(/Model qwen3:8b \(Company Ollama server\)/)).toBeVisible()
    // bỏ hồ sơ chính: dự phòng cần hồ sơ chính
    await page.goto('/settings/ai')
    await page.getByLabel('Primary profile for Weekly report comments').selectOption({ label: 'None' })
    await expect(page.getByLabel('Fallback profile for Weekly report comments')).toBeDisabled()
  })

  test('fallback: when the primary stops answering the fallback takes over and the run log and the answer say so', async ({ page }) => {
    await sampleStart(page)
    await page.goto('/settings/ai')
    await page.getByRole('button', { name: 'Edit Claude Sonnet' }).click() // hồ sơ chính của "Ask your data"
    const dlg = page.getByRole('dialog', { name: 'Edit Claude Sonnet' })
    await dlg.getByLabel('Server address').fill('https://timeout.example.com')
    await dlg.getByLabel('API key').fill('sk-ant-demo-key-9z9z') // another address needs the key again (the stored key never follows it)
    await dlg.getByRole('checkbox', { name: /I understand/ }).check()
    await dlg.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('AI profile saved').first()).toBeVisible()
    await page.goto('/assistant')
    await page.getByRole('button', { name: 'Which machines still expose RDP?' }).click()
    await expect(page.getByText(/Model qwen3:8b \(Company Ollama server\)/)).toBeVisible() // dự phòng của "Ask your data"
    const log = page.getByRole('table', { name: 'Log of AI calls' })
    await expect(log.getByText('Fallback used').first()).toBeVisible()
    await shot(page, 'ai', `fallback-${device(page)}`)
  })

  test('ask your data: suggested questions, free text, a question with nothing in the data; table links to the device; history survives reload', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/assistant')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('tokens used today')
    for (const [q, re] of [['Which machines still expose RDP?', /devices? (has|have) RDP/], ['Which devices are not approved yet?', /devices? (is|are) not approved yet/], ['Which findings are confirmed?', /findings? (is|are) confirmed/], ['Which NAS has findings?', /There (is|are) \d+ NAS/], ['Which cameras are Hikvision?', /cameras? and recorders?/], ['Which machines run an operating system near end of support?', /out of support or about to be/]] as const) {
      await page.getByRole('button', { name: q }).click()
      await expect(page.getByText(re).first()).toBeVisible()
      await expect(page.getByRole('region').filter({ hasText: 'You asked:' }).getByText('Read-only tools called')).toBeVisible()
    }
    await shot(page, 'ai', `assistant-answer-${device(page)}`)
    await expectAccessible(page, 'assistant with an answer')
    const box = page.getByLabel('Question', { exact: true })
    await box.fill('Is there any QNAP?')
    await box.press('Enter')
    await expect(page.getByText(/Found \d+ devices? matching|There (is|are) \d+ NAS/).first()).toBeVisible()
    await box.fill('What is the weather today?')
    await box.press('Enter')
    await expect(page.getByText(/so there is no answer/)).toBeVisible()
    await expect(page.getByText(/Result table/)).toHaveCount(0)
    await box.fill('ab')
    await expect(page.getByRole('button', { name: 'Ask', exact: true })).toBeDisabled()
    await page.reload()
    await expect(page.getByText('Recent questions')).toBeVisible()
    await page.getByRole('button', { name: 'Which devices are not approved yet?' }).first().click()
    await page.getByRole('table', { name: /Results for the question/ }).getByRole('link').first().click()
    await expect(page).toHaveURL(/\/devices\//)
    await noVietnamese(page)
    expect(errors).toEqual([])
  })

  test('global cap: past it the level drops and is recorded; at minimum with no cap left the question is blocked with the fix', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/settings/ai')
    await page.getByLabel('Daily token cap for all profiles together').fill('1000')
    await page.getByRole('radio', { name: /Maximum/ }).check()
    await page.getByRole('form', { name: 'Token level' }).getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Token level saved').first()).toBeVisible()
    await page.goto('/assistant')
    await page.getByRole('button', { name: 'Which machines still expose RDP?' }).click()
    await expect(page.getByText(/level lowered from Maximum to Medium/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Which devices are not approved yet?' }).click()
    await expect(page.getByText(/level lowered from Medium to Minimum/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Which cameras are Hikvision?' }).click()
    await expect(page.getByRole('alert')).toContainText('cap is used up')
    await expect(page.getByText(/Today's cap is used up/)).toBeVisible()
    await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '1000')
    await shot(page, 'ai', `assistant-capped-${device(page)}`)
    await page.goto('/settings/ai')
    await expect(page.getByRole('radio', { name: /Minimum/ })).toBeChecked() // không lưu đè mức đã hạ
    expect(errors).toEqual([])
  })

  test('panels on the CVE page and the Logs page; the answering profile is shown; explain is saved', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/cve/CVE-2022-27593')
    await page.getByRole('button', { name: 'Explain', exact: true }).click()
    await expect(page.getByText('You are affected').or(page.getByText(/You may be affected/)).first()).toBeVisible()
    await expect(page.getByText('AI-generated, needs human review').first()).toBeVisible()
    await expect(page.getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeVisible()
    await page.reload()
    await expect(page.getByText(/Saved result from/)).toBeVisible()
    await page.getByRole('button', { name: 'Fetch and summarise news' }).click()
    await expect(page.getByText('Sources the box fetched')).toBeVisible()
    await expect(page.getByText('Could not fetch').first()).toBeVisible()
    await shot(page, 'ai', `cve-panels-${device(page)}`)
    await expectAccessible(page, 'cve + ai')
    await page.goto('/logs')
    await expect(page.getByText('AI log digest')).toBeVisible()
    await expect(page.getByText(/is under RDP password guessing/)).toBeVisible()
    await expect(page.getByText(/Model qwen3:8b \(Company Ollama server\)/)).toBeVisible()
    await page.getByRole('button', { name: 'Regenerate now' }).click()
    await expect(page.getByText(/Summarised /)).toBeVisible()
    await shot(page, 'ai', `logs-digest-${device(page)}`)
    await noVietnamese(page)
    expect(errors.filter((e) => !/404/.test(e))).toEqual([])
  })

  test('removing every profile: panels guide to add one, buttons are disabled with a reason, the meter keeps its history', async ({ page }) => {
    await sampleStart(page)
    await page.goto('/settings/ai')
    for (const name of ['Claude Haiku', 'Claude Sonnet', 'Company Ollama server']) {
      await page.getByRole('button', { name: `Remove ${name}` }).click()
      await page.getByRole('dialog').getByRole('button', { name: 'Remove profile' }).click()
      await expect(page.getByText(`${name} removed`).first()).toBeVisible()
    }
    await expect(page.getByText('No AI profile yet').first()).toBeVisible()
    await page.goto('/logs')
    await expect(page.getByText('AI log digest')).toBeVisible()
    await expect(page.getByText('No AI profile yet').first()).toBeVisible()
    const btn = page.getByRole('button', { name: 'Regenerate now' })
    await expect(btn).toBeDisabled()
    await expect(btn).toHaveAttribute('title', /No AI profile yet/)
    await expectAccessible(page, 'logs, no AI profile')
    await page.goto('/assistant')
    await expect(page.getByRole('heading', { name: 'Token meter' })).toBeVisible()
  })

  test('viewer (director): sees the meter, cannot ask, cannot change profiles, and is told which role is needed', async ({ page }) => {
    await sampleStart(page)
    const s = page.getByRole('button', { name: 'Which machines still expose RDP?' })
    // đổi phiên bằng cách sửa kho rồi tải lại; thử lại nếu một lần ghi muộn của trang cũ đè lên
    await expect(async () => {
      await asUser(page, 'u-view')
      await page.goto('/assistant')
      await expect(s).toHaveAttribute('title', /Operator/, { timeout: 4000 })
    }).toPass({ timeout: 60_000 })
    await expect(s).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Ask', exact: true })).toBeDisabled()
    await expect(page.getByRole('progressbar')).toBeVisible()
    await page.goto('/settings/ai')
    await expect(page.getByText(/Admin/).first()).toBeVisible() // trang cài đặt AI chỉ dành cho quản trị: nói cần vai gì
    await expect(page.getByRole('button', { name: 'Add AI profile' })).toHaveCount(0)
  })

  test('AI module off: the page says so; saved data is kept', async ({ page }) => {
    await sampleStart(page)
    // tắt module bằng cách ép core_modules trước mỗi lần tải trang (chờ kho mock có bảng module)
    await page.waitForFunction(() => !!JSON.parse(localStorage.getItem('vedette-mock-db-v4') ?? '{}').core_modules)
    await page.addInitScript(() => {
      try {
        const k = 'vedette-mock-db-v4'
        const raw = localStorage.getItem(k)
        if (!raw) return
        const db = JSON.parse(raw)
        if (db.core_modules) { db.core_modules = db.core_modules.map((m: { id: string }) => (m.id === 'ai' ? { ...m, enabled: false } : m)); localStorage.setItem(k, JSON.stringify(db)) }
      } catch { /* bỏ qua */ }
    })
    await page.reload()
    await page.goto('/assistant')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('AI assistant is off')
    await page.goto('/cve/CVE-2022-27593')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('CVE-2022-27593')
    await expect(page.getByRole('heading', { level: 2, name: 'Explain in plain English' })).toHaveCount(0) // khung AI không dựng khi module tắt
    await expect(page.getByText(/off/i).first()).toBeVisible({ timeout: 15_000 })
  })
})

test.describe('ai: appearance', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`main screens, ${scheme}: English only, accessible, no horizontal scroll`, async ({ page }) => {
      const errors = collectErrors(page)
      await page.emulateMedia({ colorScheme: scheme })
      await sampleStart(page)
      for (const [path, name] of [['/assistant', 'assistant'], ['/settings/ai', 'settings'], ['/cve/CVE-2022-27593', 'cve'], ['/logs', 'logs']] as const) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        if (name === 'assistant') {
          await page.getByRole('button', { name: 'Which machines still expose RDP?' }).click()
          await expect(page.getByRole('region').filter({ hasText: 'You asked:' })).toBeVisible()
        }
        await page.waitForLoadState('networkidle')
        await shot(page, 'ai', `${name}-${scheme}-${device(page)}`)
        await expectAccessible(page, `${name} ${scheme}`)
        await noHorizontalScroll(page)
        await noVietnamese(page)
      }
      expect(errors).toEqual([])
    })
  }
})
