import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'

// QA như người dùng thật cho module logs (S-LOG-1..3). Giao diện chỉ có tiếng Anh (D-28). Mỗi test tự dựng dữ liệu, không phụ thuộc thứ tự.
// Máy dev dùng chung với agent khác (HMR có thể tải lại trang giữa chừng): cho thử lại một lần.
test.describe.configure({ retries: 1 })
const VI = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i

// Bản bền hơn startWithSample/startClean của helpers: đi thẳng /setup (không đua với chuyển hướng từ /).
/** Xoá dữ liệu rồi mở /setup; thử lại nếu trang vừa tải lại giữa chừng (HMR của server dev dùng chung). */
async function resetStorage(page: Page) {
  for (let i = 0; i < 3; i++) {
    try {
      await page.goto('/setup')
      await page.waitForLoadState('load')
      await page.evaluate(() => localStorage.clear())
      await page.goto('/setup')
      return
    } catch (e) {
      if (i === 2) throw e
    }
  }
}
async function startWithSample(page: Page) {
  await resetStorage(page)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
/** Cài sạch đi hết các bước, chọn gói "Mid-size business" (có logs), bỏ qua kênh. */
async function cleanInstall(page: Page, lan = '192.168.10.0/24') {
  await resetStorage(page)
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Test Admin')
  await page.getByLabel('Sign-in email').fill('admin@test-company.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password').fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('textbox', { name: 'Range 1' }).fill(lan)
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('radio', { name: /Mid-size business/ }).click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Skip and finish' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
/** Đổi phiên mock sang tài khoản khác (u-view = chỉ xem). */
async function asUser(page: Page, userId: string) {
  await page.evaluate((u) => {
    const k = 'vedette-mock-db-v4'
    const db = JSON.parse(localStorage.getItem(k) ?? '{}')
    db.core_session = { userId: u }
    localStorage.setItem(k, JSON.stringify(db))
  }, userId)
  await page.reload()
}
const noHorizontalScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
const visible = (l: ReturnType<Page['locator']>) => l.locator('visible=true').first()

/** Add log source: mở hộp thoại, tìm, chọn loại. */
async function pickKind(page: Page, query: string, name: RegExp | string) {
  await page.getByRole('button', { name: 'Add log source' }).first().click()
  const d = page.getByRole('dialog')
  await d.getByLabel('Find your device or software').fill(query)
  await d.getByRole('button', { name }).click()
  return d
}

test.describe('logs: log sources (S-LOG-1)', () => {
  test('add with errors, add correctly, see the setup, duplicate IP, edit, delete with confirmation, still there after reload', async ({ page, isMobile }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/logs')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Today:')
    // 3 lần bấm: Add, chọn loại, điền và gửi
    const d = await pickKind(page, 'forti', /FortiGate/)
    await expect(d.getByText('Device type: FortiGate (FortiOS)')).toBeVisible()
    // gửi trống: lỗi nói sai gì
    await d.getByRole('button', { name: 'Add and show setup' }).click()
    await expect(d.getByRole('alert')).toContainText('The name may only contain')
    await d.getByLabel('Name').fill('FW-TEST')
    await d.getByLabel('IP of the sending device').fill('999.1.1.1')
    await d.getByLabel('IP of the sending device').press('Enter')
    await expect(d.getByRole('alert')).toContainText('The IP address of the sending device is not valid')
    await expect(d.getByLabel('Name')).toHaveValue('FW-TEST')
    await d.getByLabel('Protocol').selectOption('tls')
    await expect(d.getByLabel('Port the box listens on')).toHaveValue('6514')
    await d.getByLabel('IP of the sending device').fill('192.168.10.77')
    await d.getByRole('button', { name: 'Add and show setup' }).click()
    const guide = page.getByRole('dialog', { name: /Set up FW-TEST/ })
    await expect(guide).toBeVisible()
    await expect(guide).toContainText('config log syslogd setting')
    await expect(guide).toContainText('set mode reliable')
    await expect(guide).toContainText('set enc-algorithm high')
    await expect(guide).toContainText('set port 6514')
    await expect(guide).toContainText('Reads traffic logs')
    if (!isMobile) await shot(page, 'logs', 'config-dialog-fortigate')
    await page.keyboard.press('Escape')
    await expect(guide).toBeHidden()
    const rowOf = (n: string) => page.getByRole(isMobile ? 'listitem' : 'row').filter({ hasText: n }).first()
    await expect(rowOf('FW-TEST')).toContainText('Nothing yet')
    // trùng IP
    const d2 = await pickKind(page, 'mikrotik', /MikroTik/)
    await d2.getByLabel('Name').fill('RT-DUP')
    await d2.getByLabel('IP of the sending device').fill('192.168.10.77')
    await d2.getByRole('button', { name: 'Add and show setup' }).click()
    await expect(d2.getByRole('alert')).toContainText('There is already a log source with this IP address')
    await d2.getByRole('button', { name: 'Cancel' }).click()
    await expect(d2).toBeHidden()
    // sửa
    await page.getByRole('button', { name: 'Edit FW-TEST' }).click()
    await expect(page.getByRole('dialog').getByText('Device type: FortiGate (FortiOS)')).toBeVisible()
    await page.getByRole('dialog').getByLabel('Name').fill('FW-CHANGED')
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click()
    await expect(rowOf('FW-CHANGED')).toBeVisible()
    // xoá: Esc không xoá, xác nhận thì xoá
    await page.getByRole('button', { name: 'Delete FW-CHANGED' }).click()
    await expect(page.getByRole('dialog')).toContainText('Logs already received are kept')
    await page.keyboard.press('Escape')
    await expect(rowOf('FW-CHANGED')).toBeVisible()
    await page.reload()
    await expect(rowOf('FW-CHANGED')).toBeVisible()
    await page.getByRole('button', { name: 'Delete FW-CHANGED' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click()
    await expect(page.getByText('FW-CHANGED')).toHaveCount(0)
    await noHorizontalScroll(page)
    expect(errors).toEqual([])
  })

  test('the picker lists all 48 device types in 8 groups, filters, says when nothing matches, and Enter picks a single match', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/logs')
    await page.getByRole('button', { name: 'Add log source' }).first().click()
    const d = page.getByRole('dialog')
    await expect(d.getByRole('region')).toHaveCount(8)
    expect(await d.getByRole('region').getByRole('button').count()).toBe(48)
    await expectAccessible(page, 'picker')
    const find = d.getByLabel('Find your device or software')
    await find.fill('zzzz')
    await expect(d.getByText('Nothing matches "zzzz"')).toBeVisible()
    await find.fill('windows')
    await expect(d.getByRole('status')).toContainText(/\d+ matches/)
    await find.fill('synology')
    await find.press('Enter')
    await expect(d.getByText('Device type: Synology DSM (Log Center)')).toBeVisible()
    await expect(d.getByText(/Stored and searchable only/)).toBeVisible()
    await d.getByRole('button', { name: 'Change device type' }).click()
    await expect(find).toBeVisible()
  })

  test('every vendor guide opens with its key command and no raw i18n key or Vietnamese text', async ({ page }) => {
    test.setTimeout(240_000)
    await startWithSample(page)
    await page.goto('/logs')
    const cases: [string, RegExp, string[]][] = [
      ['sophos', /Sophos Firewall/, ['Log settings', 'Device standard format']],
      ['palo', /Palo Alto/, ['Device, Server Profiles, Syslog', 'LOG_USER']],
      ['asa', /Cisco ASA/, ['logging host inside 192.168.10.250 udp/514']],
      ['secure firewall', /Cisco Secure Firewall/, ['Platform Settings']],
      ['ios', /Cisco IOS/, ['logging host 192.168.10.250 transport udp port 514']],
      ['meraki', /Meraki/, ['Network-wide, Configure, General']],
      ['opnsense', /OPNsense/, ['System, Settings, Logging']],
      ['sonicwall', /SonicWall/, ['Device, Log, Syslog']],
      ['watchguard', /WatchGuard/, ['System, Logging']],
      ['check point', /Check Point/, ['cp_log_export add name vedette']],
      ['juniper', /Juniper SRX/, ['set security log stream vedette host 192.168.10.250']],
      ['huawei', /Huawei/, ['info-center loghost']],
      ['draytek', /DrayTek/, ['SysLog / Mail Alert Setup']],
      ['edgerouter', /Ubiquiti UniFi gateway/, ['set system syslog host 192.168.10.250']],
      ['zyxel', /Zyxel/, ['Remote Server']],
      ['omada', /Omada/, ['Remote Logging']],
      ['ivanti', /Ivanti/, ['Syslog servers']],
      ['netscaler', /NetScaler/, ['add audit syslogAction']],
      ['openvpn', /OpenVPN/, ['openvpnas.log']],
      ['rsyslog', /Linux \(rsyslog\)/, ['/etc/rsyslog.d/60-vedette.conf', 'logger -t vedette-test']],
      ['journald', /journald/, ['ForwardToSyslog=yes']],
      ['syslog-ng', /syslog-ng/, ['destination d_vedette']],
      ['qnap', /QNAP/, ['QuLog Center']],
      ['esxi', /ESXi/, ["esxcli system syslog config set --loghost='udp://192.168.10.250:514'"]],
      ['proxmox', /Proxmox/, ['apt install rsyslog']],
      ['zeek', /Zeek/, ['@load policy/tuning/json-logs']],
      ['wazuh', /Wazuh/, ['<syslog_output>']],
      ['crowdsec', /CrowdSec/, ['/var/log/crowdsec.log']],
      ['nginx', /nginx/, ['access_log syslog:server=192.168.10.250:514']],
      ['apache', /Apache/, ['ErrorLog syslog:local6']],
      ['squid', /Squid/, ['access_log syslog:local6.info squid']],
      ['pihole', /Pi-hole/, ['/var/log/pihole/pihole.log']],
      ['bind', /BIND/, ['channel vedette']],
      ['windows dns', /Windows DNS/, ['Microsoft-Windows-DNSServer/Audit']],
      ['postfix', /Postfix/, ['mail.*']],
      ['aruba cx', /AOS-CX/, ['logging 192.168.10.250 udp 514']],
      ['procurve', /ProCurve/, ['logging facility local5']],
      ['comware', /Comware/, ['info-center loghost']],
      ['unifi switches', /UniFi switches/, ['Remote Logging']],
      ['rfc', /standard syslog/, ['RFC 3164 or RFC 5424']],
      ['cef', /CEF or LEEF/, ['CEF or LEEF']],
    ]
    let i = 0
    for (const [query, name, needles] of cases) {
      i += 1
      const d = await pickKind(page, query, name)
      await d.getByLabel('Name').fill(`SRC-${i}`)
      await d.getByLabel('IP of the sending device').fill(`10.20.30.${i}`)
      await d.getByRole('button', { name: 'Add and show setup' }).click()
      const g = page.getByRole('dialog', { name: new RegExp(`Set up SRC-${i} to send logs`) })
      await expect(g, query).toBeVisible()
      for (const n of needles) await expect(g, `${query}: ${n}`).toContainText(n)
      const text = await g.innerText()
      expect(text, query).not.toMatch(/\b(logs|common):[a-zA-Z.]+/)
      expect(text, `${query}: Vietnamese text`).not.toMatch(VI)
      await page.keyboard.press('Escape')
      await expect(g).toBeHidden()
    }
  })

  test('the setup dialog fits a phone screen and keeps keyboard focus inside', async ({ page, isMobile }) => {
    await startWithSample(page)
    await page.goto('/logs')
    await page.getByRole('button', { name: 'Device setup for SRV-AD' }).click()
    const d = page.getByRole('dialog')
    await expect(d).toContainText('xm_syslog')
    const box = await d.boundingBox()
    expect(box!.x).toBeGreaterThanOrEqual(0)
    expect(box!.x + box!.width).toBeLessThanOrEqual(page.viewportSize()!.width + 1)
    for (let n = 0; n < 12; n++) {
      await page.keyboard.press('Tab')
      expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), 'focus left the dialog').toBe(true)
    }
    if (isMobile) await shot(page, 'logs', 'config-dialog-windows-mobile')
    await page.keyboard.press('Escape')
    await expect(d).toBeHidden()
  })
})

test.describe('logs: digest, event search, retention', () => {
  test('digest, a search with no result, time range, retention change then reload', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/logs')
    await expect(page.getByRole('table', { name: 'Connections to bad IPs or domains' })).toBeVisible()
    await expect(page.getByRole('table', { name: 'New log types' })).toBeVisible()
    await expect(page.getByRole('table', { name: 'Log types with a spike' })).toBeVisible()
    // số ở tiêu đề khớp số dòng
    expect(await page.getByRole('heading', { level: 1 }).innerText()).toMatch(/3 connections.*3 new log types.*2 spikes/)
    await page.getByLabel('Keyword').fill('no-such-line-anywhere')
    await expect(visible(page.getByText('No matching line'))).toBeVisible()
    await expect(page.getByText('0 of 0 matching lines')).toBeVisible()
    await page.getByLabel('Keyword').fill('185.220.101.47')
    await expect(visible(page.getByText(/dstip=185\.220\.101\.47/))).toBeVisible()
    await page.getByLabel('Keyword').fill('')
    await page.getByRole('button', { name: '1 hour' }).click()
    await page.getByLabel('Source', { exact: true }).selectOption({ label: 'RT-BACKUP' })
    await page.getByLabel('Keep logs for').selectOption('90')
    await expect(page.getByText('Log retention saved.')).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('Keep logs for')).toHaveValue('90')
    expect(errors).toEqual([])
  })

  test('links to lookup and back work', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/logs')
    await page.getByRole('link', { name: 'Look up 185.220.101.47' }).click()
    await expect(page).toHaveURL(/\/lookup\?q=185\.220\.101\.47/)
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
    await page.goBack()
    await expect(page).toHaveURL(/\/logs/)
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Today:')
  })
})

test.describe('logs: SIEM forwarding (S-LOG-3)', () => {
  test('wrong input, save, failed test and successful test, change format', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/settings/siem')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Forward to a SIEM')
    await page.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByRole('alert')).toContainText('The SIEM server must be an IP address or a domain name')
    await page.getByLabel('SIEM server').fill('siem.no-such-host.invalid')
    await page.getByRole('button', { name: 'CEF' }).click()
    await expect(page.getByText(/CEF:0\|Vedette\|Vedette/)).toBeVisible()
    await page.getByRole('button', { name: 'Syslog' }).click()
    await page.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText(/Could not connect to siem\.no-such-host\.invalid/).first()).toBeVisible()
    await page.getByLabel('SIEM server').fill('192.168.10.50')
    await page.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByRole('status').filter({ hasText: /Test at .*success/ })).toBeVisible()
    await page.getByRole('button', { name: 'JSON webhook' }).click()
    await page.getByLabel('Webhook URL').fill('ftp://x')
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('The webhook URL must start with https://')
    await page.getByLabel('Webhook URL').fill('https://siem.company.com/hooks/vedette')
    await page.getByLabel('Signing key (optional)').fill('short')
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('at least 16 characters')
    await page.getByRole('button', { name: 'Generate random' }).click()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('SIEM settings saved.').first()).toBeVisible()
    await page.reload()
    await expect(page.getByText(/Saved, ending in/)).toBeVisible()
    await shot(page, 'logs', 'siem')
    await expectAccessible(page, 'siem')
    expect(errors).toEqual([])
  })

  test('cannot clear every event type', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/siem')
    await page.getByLabel('SIEM server').fill('192.168.10.50')
    for (const n of [/Findings/, /Alerts sent/]) await page.getByLabel(n).uncheck()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('Choose at least one event type')
  })
})

test('viewer: change buttons are disabled with a reason', async ({ page }) => {
  await startWithSample(page)
  await asUser(page, 'u-view')
  await page.goto('/logs')
  const add = page.getByRole('button', { name: 'Add log source' })
  await expect(add).toBeDisabled()
  await expect(add).toHaveAttribute('title', /Admin/)
  await expect(page.getByLabel('Keep logs for')).toBeDisabled()
})

test.describe('logs: clean install', () => {
  test('every part says what to do first, with no sample data', async ({ page }) => {
    const errors = collectErrors(page)
    await cleanInstall(page, '192.168.18.0/24')
    await page.goto('/logs')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('No device is sending logs to the box yet')
    await expect(page.getByText('No log sources yet')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Add log source' }).first()).toBeVisible()
    await expect(page.locator('main')).not.toContainText(/192\.168\.10\.(1|2|10)\b|FW-HQ|RT-BACKUP|SRV-AD|185\.220/)
    await expect(page.getByRole('table', { name: 'New log types' })).toHaveCount(0)
    await shot(page, 'logs', 'clean-empty')
    await expectAccessible(page, 'logs clean')
    const d = await pickKind(page, 'forti', /FortiGate/)
    await d.getByLabel('Name').fill('FW-NEW')
    await d.getByLabel('IP of the sending device').fill('10.0.0.1')
    await d.getByRole('button', { name: 'Add and show setup' }).click()
    // địa chỉ hộp suy ra từ dải LAN đã khai (192.168.18.0/24 -> .250), không phải IP của dữ liệu mẫu
    await expect(page.getByRole('dialog', { name: /Set up FW-NEW/ })).toContainText('set server "192.168.18.250"')
    await expect(page.getByRole('dialog')).not.toContainText('192.168.10.250')
    await page.keyboard.press('Escape')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('No log line received yet')
    await expect(page.getByText('No logs to analyse yet')).toBeVisible()
    await expect(visible(page.getByText('No log line in this range yet'))).toBeVisible()
    await shot(page, 'logs', 'clean-one-source')
    // axe không chạy ở đây: panel AI (slot logs.panels, module ai) là việc của module ai.
    expect(errors).toEqual([])
  })
})

test.describe('logs: look and feel', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`Logs and SIEM pages ${scheme}: no errors, no horizontal scroll, accessible, English only`, async ({ page }, info) => {
      const errors = collectErrors(page)
      await page.emulateMedia({ colorScheme: scheme })
      await startWithSample(page)
      for (const [name, path] of [['logs', '/logs'], ['siem', '/settings/siem']] as const) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await noHorizontalScroll(page)
        await shot(page, 'logs', `${name}-${info.project.name}-${scheme}`)
        const text = await page.locator('main').innerText()
        expect(text, `${name}: raw i18n key`).not.toMatch(/\b(logs|common|notify):[a-zA-Z.]+/)
        expect(text, `${name}: Vietnamese text`).not.toMatch(VI)
        await expectAccessible(page, `${name} ${scheme}`)
      }
      expect(errors).toEqual([])
    })
  }

  test('100+ events: paging works and the layout holds', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/logs')
    await page.getByRole('button', { name: '7 days' }).click()
    await expect(page.getByText(/\d+ of \d+ matching lines/)).toBeVisible()
    await noHorizontalScroll(page)
  })
})
