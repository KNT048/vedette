import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { collection } from '@/mocks/db'
import type { Token, TrapIP } from './types'

const year = new Date().getFullYear()
const group = (name: string) => screen.findByRole('list', { name })
const rowOf = (sw: HTMLElement) => sw.closest('li')!
type StoredTrap = Pick<TrapIP, 'id' | 'name' | 'ip' | 'preset' | 'vendor' | 'services' | 'enabled' | 'created_at'>
const setTraps = (l: StoredTrap[]) => collection<StoredTrap[]>('hp_trap_ips', () => []).set(l)
const trap = (over: Partial<StoredTrap>): StoredTrap => ({
  id: 'tip-9', name: 'BUILD-SRV-02', ip: '192.168.10.244', preset: 'linux', vendor: 'vmware', services: ['ssh'], enabled: true, created_at: '2026-11-01T08:00:00Z', ...over,
})

describe('honey tokens: ready-made decoys', () => {
  it('a file switches on onto the decoy share and off again without asking when it never fired', async () => {
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const files = await group("Files on the decoy's share")
    const sw = within(files).getByRole('switch', { name: 'Payroll spreadsheet (.xlsx)' })
    expect(sw).not.toBeChecked()
    expect(rowOf(sw).textContent).toContain(`Puts Payroll-${year}.xlsx on the share.`)
    await userEvent.click(sw)
    await waitFor(() => expect(sw).toBeChecked())
    await waitFor(() => expect(rowOf(sw).textContent).toContain(`Payroll-${year}.xlsx is on \\\\FILESRV-OLD.`))
    // the full list carries it too, with Test
    expect(await screen.findByRole('button', { name: `Test token Payroll-${year}` })).toBeInTheDocument()
    await userEvent.click(sw)
    await waitFor(() => expect(sw).not.toBeChecked())
    expect(screen.queryByRole('dialog')).toBeNull()
    await waitFor(() => expect(screen.queryByRole('button', { name: `Test token Payroll-${year}` })).toBeNull())
  })

  it('a token made in an earlier year still counts as on', async () => {
    const old: Token = { id: 'tok-old', type: 'file', name: `Bank-accounts-${year - 1}`, value: `Bank-accounts-${year - 1}.xlsx`, password: null, plant_at: "The decoy's file share", created_at: '2025-03-01T08:00:00Z', last_triggered_at: null, triggers: 0 }
    server.use(http.get('*/api/v1/honeypot/tokens', () => HttpResponse.json({ items: [old] })))
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const files = await group("Files on the decoy's share")
    await waitFor(() => expect(within(files).getByRole('switch', { name: 'Bank account list (.xlsx)' })).toBeChecked())
  })

  it('turning off a decoy that fired asks first, says its hits stay, and deletes only on Turn off', async () => {
    const fired: Token = { id: 'tok-pw', type: 'file', name: 'Passwords', value: 'Passwords.xlsx', password: null, plant_at: "The decoy's file share", created_at: '2026-11-01T08:00:00Z', last_triggered_at: '2026-11-20T08:00:00Z', triggers: 2 }
    const deleted: string[] = []
    server.use(
      http.get('*/api/v1/honeypot/tokens', () => HttpResponse.json({ items: deleted.length ? [] : [fired] })),
      http.delete('*/api/v1/honeypot/tokens/:id', ({ params }) => { deleted.push(String(params.id)); return new HttpResponse(null, { status: 204 }) }),
    )
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const files = await group("Files on the decoy's share")
    const sw = within(files).getByRole('switch', { name: 'Password list (.xlsx)' })
    await waitFor(() => expect(sw).toBeChecked())
    expect(rowOf(sw).textContent).toMatch(/2 real triggers/)
    await userEvent.click(sw)
    const dlg = await screen.findByRole('dialog', { name: 'Turn off Password list (.xlsx)?' })
    expect(dlg.textContent).toContain("The file leaves the decoy's share.")
    expect(dlg.textContent).toContain('It fired 2 times. Those hits stay in Hits.')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(deleted).toEqual([])
    expect(sw).toBeChecked()
    await userEvent.click(sw)
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(deleted).toEqual(['tok-pw']))
    await waitFor(() => expect(sw).not.toBeChecked())
  })

  it('a link says it needs pasting, shows it with Copy, and asks before turning off because a new one would differ', async () => {
    const user = userEvent.setup()
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const links = await group('Links')
    expect(screen.getByText(/A link alerts only once it is pasted where someone will find it/)).toBeInTheDocument()
    const sw = within(links).getByRole('switch', { name: 'Router admin bookmark' })
    await user.click(sw)
    await waitFor(() => expect(sw).toBeChecked())
    const row = rowOf(sw)
    expect(row.textContent).toContain('Not alerting until pasted')
    expect(row.textContent).toContain('Paste it in: Intranet page about the network')
    const link = row.querySelector('pre')!.textContent!
    expect(link).toMatch(/^https:\/\/\S+\/t\/[a-z0-9]+$/)
    await user.click(within(row).getByRole('button', { name: 'Copy' }))
    expect(await navigator.clipboard.readText()).toBe(link)
    await user.click(sw)
    const dlg = await screen.findByRole('dialog', { name: 'Turn off Router admin bookmark?' })
    expect(dlg.textContent).toContain('Switched on again, it gets a new link')
  })

  it('an account is live on the trap logins: the row shows the user name the box made', async () => {
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const accounts = await group("Fake accounts on the decoy's services")
    const sw = within(accounts).getByRole('switch', { name: 'NAS admin login' })
    await userEvent.click(sw)
    await waitFor(() => expect(sw).toBeChecked())
    expect(rowOf(sw).textContent).toMatch(/Live: a sign-in as svc_[a-z]{6} on a Trap IP alerts\./)
    expect(rowOf(sw).textContent).toMatch(/user: svc_[a-z]{6}\s*password: \S+/)
  })

  it('no Trap IP with SMB: the files group says so, and one click adds SMB to a switched-on server', async () => {
    setTraps([trap({})])
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const notice = await screen.findByText('No Trap IP has SMB on, so these files are on no share yet.')
    const add = within(notice.closest('[role="status"]') as HTMLElement).getByRole('button', { name: 'Add SMB to BUILD-SRV-02' })
    // accounts are fine: SSH is a login service
    expect(screen.queryByText(/No Trap IP has a login service on/)).toBeNull()
    await userEvent.click(add)
    await waitFor(() => expect(screen.queryByText('No Trap IP has SMB on, so these files are on no share yet.')).toBeNull())
    expect(collection<StoredTrap[]>('hp_trap_ips', () => []).get()[0]!.services).toEqual(['smb', 'ssh'])
  })

  it('no Trap IP at all: both groups say why, with a link to add one; a viewer is told to ask an administrator', async () => {
    setTraps([])
    const { unmount } = renderApp('/honeypot?tab=tokens', { role: 'admin' })
    expect(await screen.findByRole('link', { name: 'Add a file server Trap IP' })).toHaveAttribute('href', '/honeypot?tab=trap-ips&add=file_server#trap-ips')
    expect(screen.getByRole('link', { name: 'Add a Linux server Trap IP' })).toHaveAttribute('href', '/honeypot?tab=trap-ips&add=linux#trap-ips')
    unmount()
    setTraps([trap({ enabled: false, services: ['smb', 'ssh'] })])
    renderApp('/honeypot?tab=tokens', { role: 'viewer' })
    expect(await screen.findByText('No Trap IP has SMB on, so these files are on no share yet.')).toBeInTheDocument()
    expect(screen.getAllByText('An administrator can turn it on.').length).toBe(2)
    expect(screen.queryByRole('button', { name: 'Turn on BUILD-SRV-02' })).toBeNull()
    expect(within(await group('Links')).getByRole('switch', { name: 'Internal wiki bookmark' })).toBeDisabled()
  })

  it('a switched-off Trap IP that has SMB is the one action: Turn on', async () => {
    setTraps([trap({ enabled: false, services: ['smb', 'ssh'] })])
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const btns = await screen.findAllByRole('button', { name: 'Turn on BUILD-SRV-02' })
    expect(btns.length).toBe(2) // files and accounts are both fixed by switching it on
    await userEvent.click(btns[0]!)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Turn on BUILD-SRV-02' })).toBeNull())
  })
})
