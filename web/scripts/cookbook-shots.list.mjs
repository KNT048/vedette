// The cookbook's shots, one entry per image in docs/cookbook/images/. `name` is the file name (it starts with the recipe
// number); `fresh` starts a new visitor (the setup wizard); `run` opens the screen, marks the callouts and saves the image.
// The callout numbers here are the numbers the recipe's text explains: change both together.

const main = (page) => page.locator('main')
const dialog = (page) => page.getByRole('dialog')
const TERMS = 'I have read, understood and agree to the terms of use'
/** The setup wizard up to its Account step, filled with example values. */
async function setupAccount(page) {
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: TERMS }).click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo')
  await page.getByLabel('Organization name', { exact: true }).fill('Example Company')
  await page.getByLabel('Administrator name', { exact: true }).fill('Alex Admin')
  await page.getByLabel('Sign-in email', { exact: true }).fill('admin@example.com')
  await page.getByLabel('Password', { exact: true }).fill('a-long-password-123')
  await page.getByLabel('Repeat password', { exact: true }).fill('a-long-password-123')
}
/** Agent intake is a module the sample data starts with off: turned on the way the Add a device dialog offers it. */
async function ensureAgentIntake(page) {
  await page.goto('/devices')
  await page.getByRole('button', { name: 'Add a device' }).click()
  const d = dialog(page)
  await d.getByRole('radio', { name: /osquery/ }).click()
  const on = d.getByRole('button', { name: 'Turn on Agent intake' })
  if (await on.count()) { await on.click(); await d.getByText('Linux', { exact: true }).waitFor() }
  await page.keyboard.press('Escape')
}
/** The box around a heading's panel: the nearest ancestor that also holds a button. */
const panelOf = (page, heading) => page.getByRole('heading', { name: heading }).locator('xpath=ancestor::*[.//button][1]')

export const SHOTS = [
  // 01 Install and setup
  {
    name: '01-setup-terms', fresh: true,
    async run({ page, mark, shoot }) {
      await page.goto('/setup')
      await page.getByRole('checkbox', { name: TERMS }).click()
      await mark(page.getByRole('list', { name: 'Setup steps' }), 1)
      await mark(page.getByRole('checkbox', { name: TERMS }).locator('..'), 2)
      await mark(page.getByRole('button', { name: 'Continue' }), 3)
      await shoot({ area: 'full' })
    },
  },
  {
    name: '01-setup-account', fresh: true,
    async run({ page, mark, shoot }) {
      await setupAccount(page)
      await mark(panelOf(page, 'Just want a look?'), 1)
      await mark(panelOf(page, 'Moving to a new box?'), 2)
      await mark(page.getByLabel('Setup code', { exact: true }), 3)
      await mark(page.getByLabel('Password', { exact: true }), 4)
      await shoot({ area: 'full' })
    },
  },
  {
    name: '01-setup-network', fresh: true,
    async run({ page, mark, shoot }) {
      await setupAccount(page)
      await page.getByRole('button', { name: 'Continue' }).click()
      await page.getByRole('checkbox', { name: /I confirm these ranges/ }).click()
      await mark(page.getByLabel('Range 1'), 1)
      await mark(page.getByRole('button', { name: 'Add range' }), 2)
      await mark(page.getByRole('checkbox', { name: /I confirm these ranges/ }).locator('xpath=ancestor::*[contains(., "Ticked:")][1]'), 3)
      await shoot({ area: 'full' })
    },
  },
  {
    name: '01-setup-modules', fresh: true,
    async run({ page, mark, shoot }) {
      await setupAccount(page)
      await page.getByRole('button', { name: 'Continue' }).click()
      await page.getByRole('button', { name: 'Continue' }).click()
      await mark(page.getByRole('radiogroup', { name: 'Choose a module bundle' }), 1)
      await mark(page.getByRole('button', { name: 'Finish setup' }), 2)
      await shoot({ area: 'full' })
    },
  },
  {
    name: '01-home', 
    async run({ page, mark, shoot }) {
      await page.goto('/')
      await mark(page.getByRole('heading', { level: 1 }), 1)
      await mark(main(page).getByText(/^Data updated/), 2)
      await shoot()
    },
  },

  // 02 Add devices
  {
    name: '02-devices-list',
    async run({ page, mark, shoot }) {
      await page.goto('/devices')
      await mark(page.getByRole('tab', { name: /To review/ }), 1)
      await mark(page.getByRole('link', { name: 'Sensor and agents' }), 2)
      await mark(page.getByRole('button', { name: 'Add a device' }), 3)
      await mark(page.getByRole('button', { name: 'Scan the LAN now' }), 4)
      await mark(page.getByRole('columnheader', { name: 'Sources' }), 5)
      await shoot()
    },
  },
  {
    name: '02-to-review',
    async run({ page, mark, shoot }) {
      await page.goto('/devices?tab=review')
      await mark(page.getByRole('button', { name: /^Add all/ }), 1)
      const row = main(page).getByRole('button', { name: 'Ignore' }).first().locator('xpath=ancestor::*[.//button[normalize-space()="Add device"]][1]')
      await mark(row, 2)
      await mark(page.getByText('Notify me about new devices', { exact: true }), 3)
      await shoot({ area: main(page), margin: 0 })
    },
  },
  {
    name: '02-add-manual', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/devices')
      await page.getByRole('button', { name: 'Add a device' }).click()
      const d = dialog(page)
      await d.getByLabel('IP address').fill('192.0.2.10')
      await d.getByLabel('Version (optional)').fill('7.4.5')
      await mark(d.getByRole('radiogroup').first(), 1)
      await mark(d.getByRole('combobox').first(), 2)
      await mark(d.getByLabel('Version (optional)'), 3)
      await mark(d.getByRole('button', { name: 'Add', exact: true }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '02-add-snmp', height: 1450,
    async run({ page, mark, shoot }) {
      await page.goto('/devices')
      await page.getByRole('button', { name: 'Add a device' }).click()
      const d = dialog(page)
      await d.getByRole('radio', { name: /SNMP/ }).click()
      await mark(d.getByText('Copy from another device').locator('xpath=ancestor::*[.//select or .//button[@role="combobox"]][1]'), 1)
      await mark(d.getByText('SNMP version').locator('xpath=ancestor::*[contains(., "clear text")][1]'), 2)
      await mark(d.getByText(/^Saving turns SNMP on/), 3)
      await mark(d.getByRole('button', { name: 'Add device and turn SNMP on' }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '02-add-osquery', height: 1100,
    async run({ page, mark, shoot }) {
      await page.goto('/devices')
      await page.getByRole('button', { name: 'Add a device' }).click()
      const d = dialog(page)
      await d.getByRole('radio', { name: /osquery/ }).click()
      const on = d.getByRole('button', { name: 'Turn on Agent intake' })
      if (await on.count()) await on.click()
      await d.getByText('Linux', { exact: true }).click()
      await d.getByRole('button', { name: 'Create install command' }).click()
      await mark(d.getByText('Operating system', { exact: true }).locator('..'), 1)
      await mark(d.getByText('Token', { exact: true }).locator('xpath=ancestor::*[contains(., "vdt_")][1]'), 2)
      await mark(d.getByText(/^Install commands use/).locator('..'), 3)
      await mark(d.getByText('Linux shell', { exact: true }).locator('xpath=ancestor::*[contains(., "sha256sum")][1]'), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '02-agents',
    async run({ page, mark, shoot }) {
      await ensureAgentIntake(page)
      await page.goto('/devices/setup?tab=agents')
      await mark(page.getByRole('tab', { name: 'Agents' }), 1)
      await mark(page.getByText('Enrollment tokens', { exact: true }).locator('xpath=following::table[1]'), 2)
      await mark(page.getByRole('button', { name: 'Remove unused tokens' }), 3)
      await mark(page.getByText('Machines with an agent', { exact: true }).locator('xpath=following::table[1]'), 4)
      await shoot({ area: main(page), margin: 0 })
    },
  },

  // 03 Read and fix a finding
  {
    name: '03-home-fix-first', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/')
      await mark(main(page).getByText('Exploited in the wild', { exact: true }).first().locator('xpath=ancestor::*[contains(., "Update recommended")][1]'), 1)
      await mark(page.getByRole('heading', { name: 'Fix first' }), 2)
      await mark(main(page).getByText(/^Update OpenSSH 10.2 → 10.6/).first(), 3)
      await mark(main(page).getByText(/^Not confirmed yet/).first(), 4)
      await shoot()
    },
  },
  {
    name: '03-findings-list', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/findings')
      await mark(page.getByRole('tab', { name: 'By device' }).locator('..'), 1)
      await mark(main(page).getByText(/^Update FortiOS 7.2 → 7.2.7/).first(), 2)
      await mark(main(page).getByRole('button', { name: /^Mark these as handled/ }).first(), 3)
      await mark(main(page).getByText(/^Confirmed: the device reports this version/).first(), 4)
      await shoot()
    },
  },
  {
    name: '03-finding-top', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/findings/fv-fw01-fos-1')
      await mark(page.getByRole('heading', { level: 1 }), 1, { tight: true })
      await mark(page.getByRole('button', { name: 'Mark as handled' }), 2)
      await mark(page.getByRole('heading', { name: 'Evidence' }).locator('xpath=ancestor::section[1]'), 3)
      await shoot()
    },
  },
  {
    name: '03-finding-what-to-do', height: 1300,
    async run({ page, mark, shoot }) {
      await page.goto('/findings/fv-fw01-fos-1')
      const sec = page.getByRole('heading', { name: 'What to do' }).locator('xpath=ancestor::section[1]')
      await mark(sec.getByText('1. Install the patch'), 1, { tight: true })
      await mark(sec.getByText(/^2\. Temporary workaround/), 2, { tight: true })
      await mark(sec.getByText(/^3\. Firewall configuration/), 3, { tight: true })
      await mark(sec.getByText(/^4\. Check that it is fixed/), 4, { tight: true })
      await shoot({ area: sec })
    },
  },
  {
    name: '03-mark-handled', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/findings/fv-fw01-fos-1')
      await page.getByRole('button', { name: 'Mark as handled' }).click()
      const d = dialog(page)
      await mark(d.getByRole('radiogroup'), 1)
      await mark(d.getByLabel(/^Note/), 2)
      await mark(d.getByRole('button', { name: /^Mark 1 finding/ }), 3)
      await shoot({ area: d, fixed: true })
    },
  },

  // 04 Alerts
  {
    name: '04-channels', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/channels')
      await mark(page.getByRole('button', { name: 'Set up Zalo OA' }), 1)
      await mark(page.getByRole('button', { name: 'Edit Email' }), 2)
      await mark(page.getByRole('button', { name: 'Send test Email' }), 3)
      await mark(main(page).getByText(/^Tested 18 Nov/), 4)
      await mark(page.locator('#quiet-hours legend'), 5, { tight: true })
      await shoot()
    },
  },
  {
    name: '04-email-form', height: 2300,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/channels')
      await page.getByRole('button', { name: 'Edit Email' }).click()
      const d = dialog(page)
      await mark(d.getByLabel('Provider'), 1)
      await mark(d.getByLabel('Send to'), 2)
      await mark(d.getByText('What to send', { exact: true }).locator('xpath=ancestor::*[.//*[@role="radiogroup"] or .//select][1]'), 3)
      await mark(d.getByRole('button', { name: 'Save and send test' }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '04-telegram-form', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/channels')
      await page.getByRole('button', { name: 'Edit Telegram' }).click()
      const d = dialog(page)
      await mark(d.getByLabel('Bot token'), 1)
      await mark(d.getByRole('button', { name: 'Find my chat' }), 2)
      await mark(d.getByLabel('Chat ID'), 3)
      await mark(d.getByRole('button', { name: 'Save and send test' }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '04-zalo-personal', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/channels')
      await page.getByRole('button', { name: 'Set up Zalo personal' }).click()
      const d = dialog(page)
      await mark(d.getByText(/^Unofficial channel/), 1)
      await mark(d.getByRole('button', { name: 'Sign in with a QR code' }), 2)
      await mark(d.getByText('Who receives alerts', { exact: true }), 3, { tight: true })
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '04-history', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/channels')
      const sec = page.getByRole('heading', { name: 'History' }).locator('xpath=ancestor::section[1]')
      await sec.scrollIntoViewIfNeeded()
      await mark(sec.getByRole('heading', { name: 'Not sent' }), 1, { tight: true })
      await mark(sec.getByText('Failed', { exact: true }).first(), 2)
      await mark(sec.getByRole('button', { name: /^Send again/ }).first(), 3)
      await shoot({ area: sec, maxHeight: 620 })
    },
  },

  // 05 External exposure
  {
    name: '05-exposure',
    async run({ page, mark, shoot }) {
      await page.goto('/exposure')
      await mark(page.getByRole('row', { name: /198\.51\.100\.2/ }), 1)
      await mark(page.getByRole('row', { name: /198\.51\.100\.3/ }), 2)
      await mark(main(page).getByRole('button', { name: 'Add target' }).first(), 3)
      await mark(page.getByRole('tab', { name: 'Settings' }), 4)
      await shoot()
    },
  },
  {
    name: '05-add-target',
    async run({ page, mark, shoot }) {
      await page.goto('/exposure')
      await main(page).getByRole('button', { name: 'Add target' }).first().click()
      const d = dialog(page)
      await mark(d.getByText('What to add', { exact: true }).locator('..'), 1)
      await mark(d.getByText('What to scan', { exact: true }).locator('..'), 2)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '05-target', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/exposure/xt-12')
      await mark(main(page).getByRole('button', { name: 'Scan now' }), 1)
      await mark(main(page).getByText(/^Scan now scope/), 2)
      await mark(main(page).getByText(/^Paused until the testing terms/), 3)
      await mark(page.getByRole('tab', { name: /^Issues/ }).locator('..'), 4)
      await shoot()
    },
  },
  {
    name: '05-prove-ownership', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/exposure/xt-13?tab=ownership')
      await mark(page.getByRole('tab', { name: /^Ownership/ }), 1)
      await mark(main(page).getByText(/^Prove the domain is yours/), 2)
      await mark(main(page).getByText('TXT record value', { exact: true }).locator('xpath=ancestor::*[contains(., "vedette-verify=")][1]'), 3)
      await mark(main(page).getByRole('button', { name: 'Check', exact: true }), 4)
      await shoot()
    },
  },
  {
    name: '05-testing-terms', height: 1200,
    async run({ page, mark, shoot }) {
      await page.goto('/exposure/xt-14?tab=ownership')
      const terms = page.getByRole('heading', { name: 'Testing terms (deep scan)' }).locator('xpath=ancestor::section[1]')
      await mark(terms, 1)
      await mark(terms.getByText(/^Include disruptive checks/), 2)
      await shoot({ area: terms })
    },
  },

  // 06 Honeypot
  {
    name: '06-honeypot',
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot')
      await mark(main(page).getByText('Trap IPs listening').locator('..'), 1)
      await mark(page.getByRole('tab', { name: /^Trap IPs/ }).locator('..'), 2)
      await mark(page.getByRole('heading', { name: 'Is this enough?' }), 3, { tight: true })
      await shoot()
    },
  },
  {
    name: '06-trap-ips', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot?tab=trap-ips')
      await mark(main(page).getByText('Suggested from your inventory').locator('..'), 1)
      await mark(main(page).getByRole('button', { name: 'Add a Trap IP' }), 2)
      await shoot({ area: main(page), margin: 0 })
    },
  },
  {
    name: '06-add-trap', height: 1500,
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot?tab=trap-ips')
      await main(page).getByRole('button', { name: 'Add a Trap IP' }).click()
      const d = dialog(page)
      await mark(d.getByLabel('Looks like'), 1)
      await mark(d.getByLabel('Name', { exact: true }), 2)
      await mark(d.getByLabel('Address'), 3)
      await mark(d.getByLabel('Vendor (MAC prefix)'), 4)
      await mark(d.locator('fieldset').filter({ hasText: 'Services' }), 5)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '06-add-token', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot?tab=tokens')
      await main(page).getByRole('button', { name: 'Add a token' }).click()
      const d = dialog(page)
      await mark(d.getByLabel('Start from'), 1)
      await mark(d.getByText('Token type', { exact: true }).locator('..'), 2)
      await mark(d.getByLabel('Where will you plant it?'), 3)
      await mark(d.getByRole('button', { name: 'Create token' }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '06-test-trap', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot?tab=services')
      const smb = page.getByRole('row', { name: /SMB \(file sharing\)/ })
      await smb.getByRole('button', { name: /Test trap/ }).click()
      await page.getByText(/test hit/i).first().waitFor()
      await mark(smb.getByRole('button', { name: /Test trap/ }), 1)
      await mark(page.locator('[data-sonner-toast]').first(), 2)
      await shoot({ toasts: true })
    },
  },
  {
    name: '06-hits', height: 800,
    async run({ page, mark, shoot }) {
      await page.goto('/honeypot?tab=hits')
      await mark(page.getByRole('table').getByRole('row').nth(1), 1)
      await shoot({ area: main(page), margin: 0 })
    },
  },

  // 07 Reports
  {
    name: '07-report', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/reports')
      await mark(main(page).getByText('Automatic sending is off').locator('..'), 1)
      await mark(page.getByRole('button', { name: /Print/ }), 2)
      await mark(page.getByRole('button', { name: 'Send now' }), 3)
      await mark(main(page).getByText('Do these first', { exact: true }), 4, { tight: true })
      await shoot()
    },
  },
  {
    name: '07-report-settings', height: 1200,
    async run({ page, mark, shoot }) {
      await page.goto('/reports?tab=settings')
      await mark(main(page).getByRole('button', { name: 'Change' }).first(), 1)
      await mark(main(page).getByLabel('Period'), 2)
      await mark(main(page).getByText(/^Sections/).first().locator('..'), 3)
      await mark(main(page).getByLabel('Add a recipient'), 4)
      await shoot({ area: main(page), margin: 0 })
    },
  },
  {
    name: '07-schedule', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/reports?tab=settings')
      await main(page).getByRole('button', { name: 'Change' }).first().click()
      const d = dialog(page)
      await d.getByText('Run on a schedule').click()
      await mark(d.getByText('Run on a schedule'), 1, { tight: true })
      await mark(d.getByLabel('Repeat'), 2)
      await mark(d.getByText(/^Next start/).first(), 3)
      await mark(d.getByRole('button', { name: 'Save' }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '07-history',
    async run({ page, mark, shoot }) {
      await page.goto('/reports?tab=history')
      await mark(page.getByRole('table').getByRole('row').nth(1), 1)
      await mark(main(page).getByText('Not delivered').first(), 2)
      await shoot({ area: main(page), margin: 0 })
    },
  },

  // 08 Updates, backup, restore
  {
    name: '08-updates-os', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/updates')
      await mark(page.getByRole('heading', { level: 1 }), 1, { tight: true })
      await mark(page.getByRole('button', { name: 'Check for OS updates' }), 2)
      await mark(main(page).getByText('Automatic security updates', { exact: true }).locator('..'), 3)
      await mark(main(page).getByText('Maintenance window', { exact: true }).locator('..'), 4)
      await mark(page.getByRole('button', { name: /^Install security updates/ }), 5)
      await shoot()
    },
  },
  {
    name: '08-updates-vedette', height: 1100,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/updates')
      const sec = page.getByRole('heading', { name: 'Vedette software', exact: true }).locator('xpath=ancestor::section[1]')
      await mark(page.getByRole('button', { name: 'Check for Vedette releases' }), 1)
      await mark(sec.getByText('Software channel', { exact: true }).locator('..'), 2)
      await mark(sec.getByText('Update method', { exact: true }).locator('..'), 3)
      await mark(page.getByRole('button', { name: 'Update Vedette software' }), 4)
      await mark(page.getByRole('button', { name: /^Back to .* Vedette software$/ }), 5)
      await shoot({ area: sec, maxHeight: 880 })
    },
  },
  {
    name: '08-update-dialog',
    async run({ page, mark, shoot }) {
      await page.goto('/settings/updates')
      await page.getByRole('button', { name: 'Update Vedette software' }).click()
      const d = dialog(page)
      await mark(d.getByText(/^It takes about/), 1)
      await mark(d.getByText(/^The database is backed up first/), 2)
      await mark(d.getByRole('button', { name: /^Update to/ }), 3)
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '08-data', height: 1000,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/data')
      await mark(page.getByRole('button', { name: 'Download backup' }), 1)
      await mark(page.getByRole('button', { name: 'Download decryption key' }), 2)
      await mark(page.getByRole('table').first(), 3)
      await mark(page.getByRole('button', { name: /^Restore/ }).first(), 4)
      await shoot()
    },
  },
  {
    name: '08-download-backup', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/data')
      await page.getByRole('button', { name: 'Download backup' }).click()
      const d = dialog(page)
      await mark(d.getByText(/^Protect the file with a password/).locator('..'), 1)
      await mark(d.getByLabel('Backup password'), 2)
      await mark(d.getByText('A lost password cannot be recovered'), 3, { tight: true })
      await shoot({ area: d, fixed: true })
    },
  },
  {
    name: '08-restore', height: 900,
    async run({ page, mark, shoot }) {
      await page.goto('/settings/data')
      // a backup row's own Restore, not "Restore from a file" above the list
      await page.getByRole('button', { name: 'Restore', exact: true }).first().click()
      const d = dialog(page)
      await mark(d.getByText(/^Before it restores/), 1)
      await mark(d.getByLabel('Your current password'), 2)
      await mark(d.getByText(/^I understand that data written/).locator('..'), 3)
      await mark(d.getByRole('button', { name: 'Restore', exact: true }), 4)
      await shoot({ area: d, fixed: true })
    },
  },
]
