import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { InfoTip } from '@/components/common/InfoTip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { QueryState } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Segmented } from '@/components/ui/segmented'
import { kindLabel } from '@/lib/deviceTypes'
import { fmtRelative } from '@/lib/format'
import { InstallPanel, TokenError } from './AgentsSection'
import type { Platform } from './agentConfig'
import { useAgentActions, useAgents } from './api'
import { nameOf } from './nameOf'
import type { AgentsResponse, AgentToken, CreateTokenResult, DeviceDetail } from './types'

/** What the box can install osquery on: Linux and Windows servers. A Mac (or any other system) is told so instead of being offered a command. */
export type KnownOs = Platform | 'unsupported'
type PickOs = Platform

const MAC_RE = /\b(mac\s?os|os\s?x|darwin|macintosh)\b/i
const WINDOWS_RE = /\bwindows\b/i
const LINUX_RE = /\b(linux|ubuntu|debian|centos|rocky|alma|red\s?hat|rhel|fedora|alpine|suse|opensuse|arch|amazon linux|oracle linux|raspbian|kali|mint)\b/i

/** The operating system of a device as its sources read it (or as a person set it), reduced to what osquery installs on; null when it is not known. */
export function osOf(d: DeviceDetail): KnownOs | null {
  const text = d.asset.os?.value ?? ''
  if (!text.trim()) return null
  if (WINDOWS_RE.test(text)) return 'windows'
  if (MAC_RE.test(text)) return 'unsupported'
  if (LINUX_RE.test(text)) return 'linux'
  return null
}

/** One shared way to install the osquery agent, used by the device page (the device's own system is known) and by Add a device (the
 *  person picks it first): the operating system, then the one install command for it, always shown, and the manual way (package
 *  download and the enrollment steps) folded until opened. The enrollment token is made by one click on "Create install command",
 *  never by opening the dialog or choosing a system; it is shown once with the command. `onCreated` tells the caller a secret is on screen (Add a device then keeps
 *  its method picker out of the way, so the only copy is not lost). */
export function AgentInstall({ tokenName, known = null, deviceId, onCreated }: { tokenName: string; known?: KnownOs | null; deviceId?: string; onCreated?: (on: boolean) => void }) {
  const q = useAgents(true)
  return <QueryState query={q}>{(data) => <InstallFlow data={data} tokenName={tokenName} known={known} deviceId={deviceId} onCreated={onCreated} />}</QueryState>
}

function InstallFlow({ data, tokenName, known, deviceId, onCreated }: { data: AgentsResponse; tokenName: string; known: KnownOs | null; deviceId?: string; onCreated?: (on: boolean) => void }) {
  const { t } = useTranslation('inventory')
  const { create, revoke } = useAgentActions()
  const [platform, setPlatform] = useState<PickOs | null>(known && known !== 'unsupported' ? known : null)
  const [changing, setChanging] = useState(false)
  const [token, setToken] = useState<CreateTokenResult | null>(null)
  const [error, setError] = useState<unknown>(null)

  // The token is made by the button only, once: choosing or switching the system afterwards only changes the command.
  const make = () => {
    setError(null)
    // made for a device, the token is that device's: its agent row offers Show setup until a machine enrolls with it
    create.mutate({ name: tokenName.slice(0, 64), kind: 'osquery', expires_in_days: 7, device_id: deviceId }, {
      onSuccess: (r) => { setToken(r); onCreated?.(true) },
      onError: setError,
    })
  }

  // Install commands this flow made earlier for the same use (this device, or any machine from Add a device) that no machine enrolled
  // with yet: each click makes a new token, so say so and offer to revoke them instead of leaving a trail until they expire. A token
  // for any machine is this flow's only when it carries the flow's name (madeHere): one made in Settings is never offered.
  const [opened] = useState(() => Date.now())
  const madeHere = deviceId ? () => true : sameNameShape(tokenName)
  const unused = data.tokens.filter((k) => k.kind === 'osquery' && k.hosts === 0 && (k.device_id ?? undefined) === deviceId && madeHere(k.name)
    && (!k.expires_at || Date.parse(k.expires_at) > opened))
  // the line counts them from the oldest (the box lists tokens newest first)
  const oldest = unused.reduce<(typeof unused)[number] | undefined>((a, k) => (!a || Date.parse(k.created_at) < Date.parse(a.created_at) ? k : a), undefined)
  const revokeUnused = async () => {
    try {
      for (const k of unused) await revoke.mutateAsync(k.id)
      toast.success(t('agents.unused.revoked', { count: unused.length }))
    } catch (e) { setError(e) }
  }

  if (known === 'unsupported' && !platform) {
    return (
      <div className="grid min-w-0 gap-3">
        <div className="flex items-center gap-1"><p className="text-meta text-muted">{t('addDialog.osquery.noMac')}</p><InfoTip topic={t('addDialog.osquery.noMacTopic')}>{t('addDialog.osquery.noMacInfo')}</InfoTip></div>
        <OsPicker platform={platform} onChange={setPlatform} />
      </div>
    )
  }
  const detected = known && known !== 'unsupported' ? known : null
  const run = platform
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {detected && !changing ? (
        <p className="text-meta text-muted">
          {t('agents.platform.detected', { os: t(`agents.platform.${detected}`) })}{' '}
          {token ? null : <Button size="sm" onClick={() => setChanging(true)}>{t('agents.platform.change')}</Button>}
        </p>
      ) : <OsPicker platform={platform} onChange={setPlatform} />}
      <p className="text-meta text-muted">{t('agents.serverOnly')}</p>
      {error ? <TokenError error={error} onRemoved={() => setError(null)} /> : null}
      <BusyNote busy={create.isPending}>{t('agents.install.preparing')}</BusyNote>
      {run && !token && unused.length ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted">
          {t('agents.unused.line', { count: unused.length, when: fmtRelative(oldest!.created_at) })}
          <Button size="sm" variant="ghost" busy={revoke.isPending} busyLabel={t('common:busy.removing')} onClick={() => void revokeUnused()}>{t('agents.unused.revoke', { count: unused.length })}</Button>
        </p>
      ) : null}
      {run && !token ? <Button variant="primary" className="justify-self-start" busy={create.isPending} busyLabel={t('common:busy.creating')} onClick={make}>{t('agents.createCommand')}</Button> : null}
      {token && run ? (
        <>
          <CodeBlock label={t('agents.tokenLabel')} code={token.secret} />
          <div className="flex items-center gap-1"><p className="text-meta text-warn">{t('agents.tokenOnce')}</p><InfoTip>{t('agents.tokenOnceInfo')}</InfoTip></div>
          <InstallPanel data={data} token={token.secret} platform={run} />
          <DialogFooter><DialogClose asChild><Button variant="primary">{t('agents.done')}</Button></DialogClose></DialogFooter>
        </>
      ) : null}
    </div>
  )
}

const DAY_RE = /\d{4}-\d{2}-\d{2}/g
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Whether a token name is `name` made on any day: the dates in it ("osquery install 2026-11-24, from Add a device") may differ. */
function sameNameShape(name: string): (other: string) => boolean {
  const re = new RegExp(`^${name.slice(0, 64).split(DAY_RE).map(escapeRe).join('\\d{4}-\\d{2}-\\d{2}')}$`)
  return (other) => re.test(other)
}

function OsPicker({ platform, onChange }: { platform: PickOs | null; onChange: (p: PickOs) => void }) {
  const { t } = useTranslation('inventory')
  return (
    <div className="grid gap-1.5">
      <span className="text-sm font-medium">{t('agents.platform.label')}</span>
      <Segmented<PickOs> label={t('agents.platform.label')} value={(platform ?? '') as PickOs} onChange={onChange}
        options={[{ value: 'windows', label: t('agents.platform.windows') }, { value: 'linux', label: t('agents.platform.linux') }]} />
      {platform ? null : <p className="text-meta text-muted">{t('agents.platform.pick')}</p>}
    </div>
  )
}

/** "Create agent token" on a device's page: the install for THIS device, with its system already chosen when it is known; the token
 *  is made for the device. */
export function InstallOnDeviceDialog({ d, onClose }: { d: DeviceDetail; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={t('agents.onDevice.title', { name })} description={t('agents.onDevice.body')}>
        <AgentInstall tokenName={name} known={osOf(d)} deviceId={d.asset.id} />
      </DialogContent>
    </Dialog>
  )
}

/** "Show setup" on a device's page: the token made for this device (its secret was shown once, when it was made) and the install
 *  command for the device's system with the token's place marked; a new token for the device is one click away when the old one
 *  is lost. */
export function AgentSetupDialog({ d, token, onClose }: { d: DeviceDetail; token: AgentToken | null; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const q = useAgents(true)
  const [fresh, setFresh] = useState(false)
  const known = osOf(d)
  const [picked, setPicked] = useState<PickOs | null>(known && known !== 'unsupported' ? known : null)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={t('agents.setup.title', { name })} description={t('agents.setup.body')}>
        {fresh || !token ? <AgentInstall tokenName={name} known={known} deviceId={d.asset.id} /> : (
          <QueryState query={q}>
            {(data) => (
              <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
                <p className="text-sm" data-testid="agent-setup-token">
                  <span className="font-medium">{token.name}</span>{' '}
                  <span className="whitespace-nowrap font-mono text-meta">{t('agents.tokenMask', { last4: token.last4 })}</span>{' '}
                  <span className="text-meta text-muted">{token.expires_at ? t('agents.setup.expires', { when: fmtRelative(token.expires_at) }) : t('agents.noExpiry')}</span>
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-meta text-muted">{t('agents.setup.lost')}</p>
                  <Button size="sm" onClick={() => setFresh(true)}>{t('agents.setup.newToken')}</Button>
                </div>
                <OsPicker platform={picked} onChange={setPicked} />
                {picked ? <InstallPanel data={data} token="<TOKEN>" platform={picked} /> : null}
                <DialogFooter><DialogClose asChild><Button>{t('common:close')}</Button></DialogClose></DialogFooter>
              </div>
            )}
          </QueryState>
        )}
      </DialogContent>
    </Dialog>
  )
}
