import { afterEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'

// D-604 (BN340, kien G16): a CVE only the platform or the package release settles asks its question on Needs your input, with every
// answer the box offers; each answer is an inventory correction (INV-41) and the item leaves once the box can decide. kien G15
// follow-up: a row a sensor reported takes a typed version too (a correction of that row).
const T = { timeout: 5000 }
const patches: { url: string; body: unknown }[] = []
server.events.on('request:start', ({ request }) => {
  if (request.method === 'PATCH') void request.clone().json().then((body: unknown) => patches.push({ url: new URL(request.url).pathname, body }))
})
afterEach(() => { patches.length = 0 })

const expand = async (device: string) => {
  const list = await screen.findByRole('list', { name: 'Devices that need your input, the most urgent first' }, T)
  await userEvent.click(await within(list).findByRole('button', { name: new RegExp(`^${device}`) }, T))
  return screen.findByRole('listitem', { name: device }, T)
}
const bn340 = () => assetsStore.get().find((a) => a.id === 'a-bn340')!
/** BN340 with Alpine set by a person: the package release is the question. */
const alpine = () => assetsStore.update((l) => l.map((a) => (a.id === 'a-bn340' ? { ...a, os: { value: 'Alpine Linux 3.23', source: 'manual', confidence: 1, seen_at: new Date().toISOString() } } : a)))

describe('Needs your input › the platform question (D-604, kien G16)', () => {
  it('shows the question, the command that prints the answer, and every answer; an OS is one click (PATCH os)', async () => {
    renderApp('/findings?tab=input')
    const block = await expand('BN340')
    expect(block).toHaveTextContent(/Is the OpenSSH on BN340 Alpine Linux's openssh-server package, or another build\?/)
    expect(within(block).getByText('cat /etc/alpine-release')).toBeInTheDocument()
    for (const a of ['Alpine Linux 3.22', 'Alpine Linux 3.23', 'Another system']) expect(within(block).getByRole('button', { name: a })).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(within(block).getByRole('button', { name: 'Alpine Linux 3.23' }))
    await waitFor(() => expect(patches).toContainEqual({ url: '/api/v1/inventory/devices/a-bn340', body: { os: 'Alpine Linux 3.23' } }), T)
    expect(bn340().os).toMatchObject({ value: 'Alpine Linux 3.23', source: 'manual' })
    // the box asks the next question: the package release, its field open at once, with the command from the question
    expect(await within(block).findByText(/Which openssh-server package release does BN340 have\?/, undefined, T)).toBeInTheDocument()
    expect(within(block).getByLabelText('Package release of OpenSSH')).toHaveAccessibleDescription('apk info -e -v openssh-server prints it on the device: paste the whole line or just the release.')
  })

  it('the package release saves on the row (PATCH pkg_version), the whole apk line accepted, and the item leaves', async () => {
    alpine()
    renderApp('/findings?tab=input')
    const block = await expand('BN340')
    await userEvent.type(await within(block).findByLabelText('Package release of OpenSSH', undefined, T), 'openssh-server-10.2_p1-r1')
    await userEvent.click(within(block).getByRole('button', { name: 'Save and check' }))
    await waitFor(() => expect(patches).toContainEqual({ url: '/api/v1/inventory/devices/a-bn340/software/s-bn340-ssh', body: { pkg_version: 'openssh-server-10.2_p1-r1' } }), T)
    expect(await screen.findByText('Saved. Vedette checked OpenSSH again.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'BN340' })).toBeNull(), T)
    // a correction of the scanned row (INV-41): the scan's row stays, the person's row carries the release
    expect(bn340().software).toEqual(expect.arrayContaining([expect.objectContaining({ id: 's-bn340-ssh', source: 'nmap' }), expect.objectContaining({ corrects: 's-bn340-ssh', source: 'manual', pkg_version: 'openssh-server-10.2_p1-r1' })]))
  })

  it('the bare release is accepted too', async () => {
    alpine()
    renderApp('/findings?tab=input')
    const block = await expand('BN340')
    await userEvent.type(await within(block).findByLabelText('Package release of OpenSSH', undefined, T), '10.2_p1-r1')
    await userEvent.click(within(block).getByRole('button', { name: 'Save and check' }))
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'BN340' })).toBeNull(), T)
  })

  it('errors show at the field: the server\'s 400 bad_pkg_version, and question.error for a release the box could not read', async () => {
    alpine()
    renderApp('/findings?tab=input')
    const block = await expand('BN340')
    const save = await within(block).findByRole('button', { name: 'Save and check' }, T)
    await userEvent.click(save)
    expect(within(block).getByRole('alert')).toHaveTextContent('Type the package release, as the command on the device prints it.')
    await userEvent.type(within(block).getByLabelText('Package release of OpenSSH'), '10.2 p1')
    await userEvent.click(save)
    expect(await within(block).findByRole('alert', undefined, T)).toHaveTextContent(/The package release may only contain/)
    expect(within(block).getByLabelText('Package release of OpenSSH')).toHaveAttribute('aria-invalid', 'true')
    // a release the server stores but cannot read comes back as the question's error, at the field
    const field = within(block).getByLabelText('Package release of OpenSSH')
    await userEvent.clear(field)
    await userEvent.type(field, 'latest')
    await userEvent.click(save)
    await waitFor(() => expect(within(screen.getByRole('listitem', { name: 'BN340' })).getByRole('alert')).toHaveTextContent('Vedette could not read the release you entered ("latest")'), T)
  })

  it('Another system asks for both the OS and the package release', async () => {
    renderApp('/findings?tab=input')
    const block = await expand('BN340')
    await userEvent.click(await within(block).findByRole('button', { name: 'Another system' }, T))
    const form = within(block).getByRole('form', { name: 'Another system' })
    // the platform question's command prints Alpine's release, not a package release: the field does not offer it as its hint
    expect(within(form).getByLabelText('Package release of OpenSSH')).toHaveAccessibleDescription("As the device's package manager shows it.")
    await userEvent.click(within(form).getByRole('button', { name: 'Save and check' }))
    expect(within(form).getAllByRole('alert').map((a) => a.textContent)).toEqual(['Type the operating system the device runs, for example Debian 12.', 'Type the package release, as the command on the device prints it.'])
    await userEvent.type(within(form).getByLabelText('Operating system of the device'), 'Debian 13')
    await userEvent.type(within(form).getByLabelText('Package release of OpenSSH'), '1:10.2p1-1')
    await userEvent.click(within(form).getByRole('button', { name: 'Save and check' }))
    await waitFor(() => expect(patches).toEqual([
      { url: '/api/v1/inventory/devices/a-bn340', body: { os: 'Debian 13' } },
      { url: '/api/v1/inventory/devices/a-bn340/software/s-bn340-ssh', body: { pkg_version: '1:10.2p1-1' } },
    ]), T)
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'BN340' })).toBeNull(), T)
  })

  it('kien G15 follow-up: a row a sensor reported takes a typed version in place, as a correction of that row', async () => {
    renderApp('/findings?tab=input')
    const cam = await expand('CAM-GATE')
    expect(await within(cam).findByText(/Type the version it runs: Vedette checks with yours until you clear it on the device page\./, undefined, T)).toBeInTheDocument()
    await userEvent.type(within(cam).getByLabelText('Version of Hikvision camera'), '5.7.3')
    await userEvent.click(within(cam).getByRole('button', { name: 'Save and check' }))
    await waitFor(() => expect(patches).toContainEqual({ url: '/api/v1/inventory/devices/a-cam01/software/s-cam01', body: { version: '5.7.3' } }), T)
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'CAM-GATE' })).toBeNull(), T)
    const sw = assetsStore.get().find((a) => a.id === 'a-cam01')!.software
    expect(sw).toEqual([expect.objectContaining({ id: 's-cam01', source: 'passive', version: null }), expect.objectContaining({ corrects: 's-cam01', source: 'manual', version: '5.7.3' })])
  })

  it('a viewer reads the question; the answers are locked', async () => {
    renderApp('/findings?tab=input', { role: 'viewer' })
    const block = await expand('BN340')
    expect(await within(block).findByRole('button', { name: 'Alpine Linux 3.23' }, T)).toBeDisabled()
    expect(within(block).getByRole('button', { name: 'Another system' })).toBeDisabled()
  })
})
