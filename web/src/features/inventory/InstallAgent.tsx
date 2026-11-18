import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { InfoTip } from '@/components/common/InfoTip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { QueryState } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Segmented } from '@/components/ui/segmented'
import { kindLabel } from '@/lib/deviceTypes'
import { InstallPanel, TokenError } from './AgentsSection'
import type { Platform } from './agentConfig'
import { useAgentActions, useAgents } from './api'
import { nameOf } from './nameOf'
import type { AgentsResponse, CreateTokenResult, DeviceDetail } from './types'

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
export function AgentInstall({ tokenName, known = null, onCreated }: { tokenName: string; known?: KnownOs | null; onCreated?: (on: boolean) => void }) {
  const q = useAgents(true)
  return <QueryState query={q}>{(data) => <InstallFlow data={data} tokenName={tokenName} known={known} onCreated={onCreated} />}</QueryState>
}

function InstallFlow({ data, tokenName, known, onCreated }: { data: AgentsResponse; tokenName: string; known: KnownOs | null; onCreated?: (on: boolean) => void }) {
  const { t } = useTranslation('inventory')
  const { create } = useAgentActions()
  const [platform, setPlatform] = useState<PickOs | null>(known && known !== 'unsupported' ? known : null)
  const [changing, setChanging] = useState(false)
  const [token, setToken] = useState<CreateTokenResult | null>(null)
  const [error, setError] = useState<unknown>(null)

  // The token is made by the button only, once: choosing or switching the system afterwards only changes the command.
  const make = () => {
    setError(null)
    create.mutate({ name: tokenName.slice(0, 64), kind: 'osquery', expires_in_days: 7 }, {
      onSuccess: (r) => { setToken(r); onCreated?.(true) },
      onError: setError,
    })
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
      {run ? <p className="text-meta text-muted">{t('agents.serverOnly')}</p> : null}
      {error ? <TokenError error={error} onRemoved={() => setError(null)} /> : null}
      <BusyNote busy={create.isPending}>{t('agents.install.preparing')}</BusyNote>
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

/** "Install osquery" on a device's page: the install for THIS device, with its system already chosen when it is known. */
export function InstallOnDeviceDialog({ d, onClose }: { d: DeviceDetail; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={t('agents.onDevice.title', { name })} description={t('agents.onDevice.body')}>
        <AgentInstall tokenName={name} known={osOf(d)} />
      </DialogContent>
    </Dialog>
  )
}
