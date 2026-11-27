import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { Download, Plus } from 'lucide-react'
import { Notice, Section } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { EmptyState, ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { dayOf, fmtDateTime, fmtRelative } from '@/lib/format'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { linuxOneLiner, OSQUERY_SCHEDULE, osquerySteps, windowsOneLiner, wazuhReaderSteps, type Platform } from './agentConfig'
import { NO_BOX_ADDRESS } from './installScripts'
import { ApiError } from '@/lib/api'
import { useAgentActions, useAgents, useWazuhActions } from './api'
import { errMsg } from './kinds'
import { AGENT_COMMANDS, boxHostPort } from './AgentQuiet'
import { InfoLine } from '@/components/common/InfoLine'
import type { AgentNode, AgentToken, AgentsResponse, CreateTokenResult, OsqueryPackage, WazuhConnection } from './types'

/** Only the preview build with the mock API: the "Send sample data" button simulates one agent report (the real build does not have it). */
const MOCK_BUILD = import.meta.env.DEV || import.meta.env.VITE_API_MOCK !== 'off'

/** Numbered commands; `within` numbers them as the sub-steps of that step (1a, 1b …) when they sit under a numbered step. */
function Steps({ items, ns, within }: { items: { key: string; file: string; code: string }[]; ns: string; within?: number }) {
  const { t } = useTranslation('inventory')
  return (
    <ol className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {items.map((s, i) => (
        <li key={s.key} className="grid gap-1.5">
          <p className="text-sm font-medium">{within ? `${within}${String.fromCharCode(97 + i)}` : i + 1}. {t(`${ns}.${s.key}`)}</p>
          <CodeBlock label={s.file} code={s.code} />
        </li>
      ))}
    </ol>
  )
}

/** The box knows no address other machines can reach (opened as localhost, no other name configured). A command pinned to
 *  <VEDETTE_BOX_IP> passes its hash check and then fails on every server, so none is shown: say how to give the box an address. */
function NoBoxAddress() {
  const { t } = useTranslation('inventory')
  const install = useInstallKind()
  return (
    <Notice tone="warn" role="status" className="mb-0" title={t('agents.noAddress.title')}
      actions={install === 'container' ? undefined : <Link to="/settings/network?tab=box-address" className="text-sm text-accent underline-offset-4 hover:underline">{t('agents.boxAddress.change')}</Link>}
      info={<><p>{t(install === 'container' ? 'agents.noAddress.container' : 'agents.noAddress.appliance')}</p><p>{t('agents.noAddress.token')}</p></>}>
      <p className="text-ink">{t('agents.noAddress.body')}</p>
    </Notice>
  )
}

/** Say which address the commands carry and where it is changed; when the page was opened at another host, say that
 *  agents will not use that one. No lookup of the name is made. */
function BoxAddressNote({ box }: { box: string }) {
  const { t } = useTranslation('inventory')
  const install = useInstallKind()
  let host = box
  try { host = new URL(box).hostname } catch { /* shown as given */ }
  const here = window.location.hostname
  return (
    <div className="grid gap-1 text-meta">
      <p>
        {t('agents.boxAddress.uses', { url: box })}{' '}
        {install === 'container'
          ? t('agents.boxAddress.container')
          : <Link to="/settings/network?tab=box-address" className="text-accent underline-offset-4 hover:underline">{t('agents.boxAddress.change')}</Link>}
      </p>
      {here && host.toLowerCase() !== here.toLowerCase() ? <p className="text-muted">{t('agents.boxAddress.otherHost', { here, box: host })}</p> : null}
    </div>
  )
}

/** The command that installs a package already on the server, run in the folder that holds it (osquery install docs: dpkg -i, rpm -Uvh, msiexec). */
const INSTALL_HINT: Record<OsqueryPackage['format'], (file: string) => string> = {
  deb: (f) => `sudo dpkg -i ${f}`,
  rpm: (f) => `sudo rpm -Uvh ${f}`,
  msi: (f) => `msiexec /i ${f} /qn`,
}

/** The packages the box serves, each a direct download from this origin (the public mirror route: the browser saves it
 *  under its own name), with what it is for, its size, the SHA-256 of the box's SHA256SUMS and the one line that installs it. */
function PackageTable({ packages }: { packages: OsqueryPackage[] }) {
  const { t } = useTranslation('inventory')
  return (
    // On a phone the table keeps its width and scrolls inside this box (the links in it are focusable), instead of breaking file names per letter.
    <div className="overflow-x-auto">
      <table className="w-full min-w-[46rem] text-left text-meta">
        <caption className="sr-only">{t('agents.download.caption')}</caption>
        <thead className="text-muted"><tr>
          <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.file')}</th>
          <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.for')}</th>
          <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.size')}</th>
          <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.sha')}</th>
          <th scope="col" className="py-1 font-medium">{t('agents.download.col.install')}</th>
        </tr></thead>
        <tbody>
          {packages.map((p) => (
            <tr key={p.file} className="border-t border-rule align-top">
              <td className="py-1.5 pr-3">
                <a href={`/api/v1/install/osquery/${encodeURIComponent(p.file)}`} download={p.file} aria-label={t('agents.download.link', { file: p.file })}
                  className="inline-flex items-center gap-1 whitespace-nowrap text-accent underline-offset-4 hover:underline">
                  <Download className="size-3.5 shrink-0" aria-hidden />{p.file}
                </a>
              </td>
              <td className="py-1.5 pr-3">{t(`agents.download.format.${p.format}`)} · {p.format === 'msi' ? 'x64' : p.arch}</td>
              <td className="whitespace-nowrap py-1.5 pr-3">{t('agents.download.size', { mb: (p.size / 1e6).toFixed(1) })}</td>
              <td className="py-1.5 pr-3"><code className="break-all font-mono text-caption">{p.sha256}</code></td>
              <td className="py-1.5"><code className="break-all font-mono text-caption">{INSTALL_HINT[p.format](p.file)}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** The token dialog's copy of the table, for the OS chosen there. */
function Downloads({ packages }: { packages: OsqueryPackage[] }) {
  const { t } = useTranslation('inventory')
  return (
    <div className="grid gap-1.5">
      <div className="flex items-center gap-1"><p className="text-sm font-medium">{t('agents.download.title')}</p><InfoTip topic={t('agents.download.title')}>{t('agents.download.bodyInfo')}</InfoTip></div>
      <p className="text-meta text-muted">{t('agents.download.body')}</p>
      <PackageTable packages={packages} />
    </div>
  )
}

/** A one-line install and uninstall command for Linux or Windows Server, a readable script, a direct package download, and a manual install under "Advanced". */
export function InstallPanel({ data, token, platform: fixed }: { data: AgentsResponse; token: string; platform?: Platform }) {
  const { t } = useTranslation('inventory')
  const [picked, setPlatform] = useState<Platform>('linux')
  const platform = fixed ?? picked
  const box = data.server_url
  if (box.includes(NO_BOX_ADDRESS)) return <NoBoxAddress />
  const inst = data.install[platform]
  const packages = data.install.packages.filter((p) => p.platform === platform)
  const one = platform === 'linux' ? linuxOneLiner : windowsOneLiner
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <BoxAddressNote box={box} />
      {fixed ? null : (
        <div className="grid gap-1.5">
          <span className="text-sm font-medium">{t('agents.platform.label')}</span>
          <Segmented<Platform> label={t('agents.platform.label')} value={platform} onChange={setPlatform}
            options={[{ value: 'linux', label: t('agents.platform.linux') }, { value: 'windows', label: t('agents.platform.windows') }]} />
          <p className="text-meta text-muted">{t('agents.serverOnly')}</p>
        </div>
      )}
      <div className="grid gap-1.5">
        <div className="flex items-center gap-1">
          <p className="text-sm font-medium">{t('agents.install.title')}</p>
          <InfoTip topic={t('agents.install.title')}>
            <p>{t(`agents.install.${platform}HowInfo`)}</p>
            <p>{t('agents.install.shaHint')}</p>
            {platform === 'windows' ? <p>{t('agents.install.windowsWhy')}</p> : null}
          </InfoTip>
        </div>
        <p className="text-meta text-muted">{t(`agents.install.${platform}How`)}</p>
        {packages.length ? null : <Notice tone="warn" role="status" className="mb-0" title={t('agents.download.none')} info={t('agents.download.noneInfo')} />}
        <CodeBlock label={t(`agents.install.${platform}Label`)} code={one(box, inst.sha256, token)} />
        {platform === 'linux' ? <p className="text-meta text-muted">{t('agents.install.worksOn')}</p> : null}
        <p className="text-meta"><span className="font-medium">{t('agents.install.sha')}:</span> <code className="break-all font-mono text-meta">{inst.sha256}</code></p>
      </div>
      <details className="rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('agents.install.readFirst')}</summary>
        <p className="my-2 text-meta text-muted">{t('agents.install.readFirstBody')}</p>
        <CodeBlock label={inst.url} code={inst.script} />
      </details>
      {/* Removing the agent is a later job: folded, so the uninstall command is never copied for the install one */}
      <details className="rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('agents.install.uninstall')}</summary>
        <div className="mt-2"><CodeBlock label={t(`agents.install.${platform}UninstallLabel`)} code={one(box, inst.sha256, token, 'uninstall')} /></div>
      </details>
      <div className="flex items-center gap-1"><p className="text-meta text-muted">{t('agents.install.security')}</p><InfoTip>{t('agents.install.securityInfo')}</InfoTip></div>
      {/* The manual way (package download, then the enrollment steps) stays folded until the person opens it. */}
      <details className="rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('agents.install.advanced')}</summary>
        <div className="mt-3 grid min-w-0 gap-4 [&>*]:min-w-0">
          {packages.length ? <Downloads packages={packages} /> : null}
          {platform === 'linux' ? <p className="text-meta text-muted">{t('agents.install.otherDistros')}</p> : null}
          <div className="flex items-center gap-1">
            <p className="text-meta text-muted">{t('agents.install.advancedBody')}</p>
            <InfoTip topic={t('agents.install.advanced')}><p>{t('agents.install.advancedBodyInfo')}</p><p>{t('agents.fingerprint')}</p><p>{t('agents.ownPaths')}</p></InfoTip>
          </div>
          <Steps items={osquerySteps(platform, box, token, packages)} ns={`agents.steps.${platform}`} />
          <div className="grid gap-1.5">
            <div className="flex items-center gap-1">
              <p className="text-sm font-medium">{t('agents.install.queries')}</p>
              <InfoTip topic={t('agents.install.queries')}><p>{t('agents.install.queriesBodyInfo')}</p><p>{t('agents.install.queriesBodyInfo2')}</p></InfoTip>
            </div>
            <p className="text-meta text-muted">{t('agents.install.queriesBody')}</p>
            <CodeBlock label="schedule" code={OSQUERY_SCHEDULE} />
          </div>
        </div>
      </details>
    </div>
  )
}

/** The error of making a token. At the token limit it says so and offers, right there, to remove the tokens nobody used. */
export function TokenError({ error, onRemoved }: { error: unknown; onRemoved: () => void }) {
  const { t } = useTranslation('inventory')
  const { removeUnused } = useAgentActions()
  const full = error instanceof ApiError && error.code === 'too_many_tokens'
  return (
    <Notice tone="danger" role="alert" className="mb-0" title={errMsg(error)}
      actions={full ? (
        /* empty-guard: a toast after the action, not a link or button that leads anywhere */
        <Button size="sm" busy={removeUnused.isPending} busyLabel={t('common:busy.removing')}
          onClick={() => removeUnused.mutate(undefined, { onSuccess: (r) => { toast.success(t('agents.removeUnused.done', { count: r.removed })); onRemoved() }, onError: (e) => toast.error(errMsg(e)) })}>{t('agents.removeUnused.button')}</Button>
      ) : undefined} />
  )
}

/** The osquery install dialog's content: one button, "Create install command", makes ONE token (named after the device, or "osquery
 *  install <date>") and shows the command with the token; opening the dialog makes nothing, and the same command stays until it is
 *  closed. Inside CreateDialog, Settings > Engines and the Add a device dialog's osquery method; `onCreated` lets the dialog widen and
 *  retitle itself once the token exists. */
export function OsqueryEnrol({ data, tokenName, onCreated }: { data: AgentsResponse; tokenName?: string; onCreated?: (r: CreateTokenResult) => void }) {
  const { t } = useTranslation('inventory')
  const { create } = useAgentActions()
  const [error, setError] = useState<unknown>(null)
  const [result, setResult] = useState<CreateTokenResult | null>(null)
  function make() {
    setError(null)
    const name = (tokenName ?? t('agents.defaultTokenName', { day: dayOf(new Date().toISOString()) })).slice(0, 64)
    create.mutate({ name, kind: 'osquery', expires_in_days: 7 }, { onSuccess: (r) => { setResult(r); onCreated?.(r) }, onError: setError })
  }
  if (result) {
    return (
      <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
        <CodeBlock label={t('agents.tokenLabel')} code={result.secret} />
        <div className="flex items-center gap-1"><p className="text-meta text-warn">{t('agents.tokenOnce')}</p><InfoTip>{t('agents.tokenOnceInfo')}</InfoTip></div>
        <InstallPanel data={data} token={result.secret} />
        <DialogFooter><DialogClose asChild><Button variant="primary">{t('agents.done')}</Button></DialogClose></DialogFooter>
      </div>
    )
  }
  return (
    <div className="grid gap-4">
      <p className="text-meta text-muted">{t('agents.serverOnly')}</p>
      <InfoLine className="text-meta text-muted" topic={t('agents.createNote')} info={t('agents.createNoteInfo')}>{t('agents.createNote')}</InfoLine>
      {error ? <TokenError error={error} onRemoved={() => setError(null)} /> : null}
      <DialogFooter>
        <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
        <Button variant="primary" busy={create.isPending} busyLabel={t('common:busy.creating')} onClick={make}>{t('agents.createCommand')}</Button>
      </DialogFooter>
    </div>
  )
}

function CreateDialog({ open, onOpenChange, data }: { open: boolean; onOpenChange: (o: boolean) => void; data: AgentsResponse }) {
  const { t } = useTranslation('inventory')
  const [result, setResult] = useState<CreateTokenResult | null>(null)
  function close(o: boolean) { onOpenChange(o); if (!o) setResult(null) }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent wide={!!result} title={result ? t('agents.createdTitle', { name: result.token.name }) : t('agents.createTitle')} description={result ? t('agents.createdBody') : t('agents.recommendation')}>
        <OsqueryEnrol data={data} onCreated={setResult} />
      </DialogContent>
    </Dialog>
  )
}

const INTERVALS = [5, 15, 60, 360, 1440]
/** The words for an interval: a preset's, or the minutes themselves when the schedule editor saved another one. */
const everyWords = (t: (k: string, o?: Record<string, unknown>) => string, m: number) => (INTERVALS.includes(m) ? t(`agents.wazuh.intervalOption.${m}`) : t('agents.wazuh.intervalOption.other', { count: m }))

function WazuhDialog({ open, onOpenChange, current }: { open: boolean; onOpenChange: (o: boolean) => void; current: WazuhConnection | null }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide title={t('agents.wazuh.formTitle')} description={t('agents.wazuh.formBody')} info={t('agents.wazuh.formBodyInfo')}>
        <WazuhForm current={current} onSaved={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}

/** The Wazuh connection form (read-only API user, Test, Save), in WazuhDialog and in the Add a device dialog's Wazuh method (#849). */
export function WazuhForm({ current, onSaved }: { current: WazuhConnection | null; onSaved: () => void }) {
  const { t } = useTranslation('inventory')
  const { test, save } = useWazuhActions()
  const [url, setUrl] = useState(current?.url ?? '')
  const [username, setUsername] = useState(current?.username ?? 'vedette')
  const [password, setPassword] = useState('')
  const [interval, setInterval] = useState(current?.interval_minutes ?? 60)
  const [error, setError] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)
  const input = { url, username, password: password || undefined, interval_minutes: interval }
  function doTest() {
    setError(null); setOk(null)
    test.mutate(input, { onSuccess: (r) => setOk(t('agents.wazuh.testOk', { version: r.version, count: r.agents })), onError: (e) => setError(errMsg(e)) })
  }
  function submit(e: FormEvent) {
    e.preventDefault(); setError(null); setOk(null)
    save.mutate(input, { onSuccess: () => { toast.success(t('agents.wazuh.saved')); onSaved() }, onError: (er) => setError(errMsg(er)) })
  }
  return (
        <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
          <details className="rounded-md border border-rule p-3" open={!current}>
            <summary className="cursor-pointer text-sm font-medium">{t('agents.wazuh.stepsTitle')}</summary>
            <div className="my-2 flex items-center gap-1"><p className="text-meta text-muted">{t('agents.wazuh.stepsBody')}</p><InfoTip topic={t('agents.wazuh.stepsTitle')}>{t('agents.wazuh.stepsBodyInfo')}</InfoTip></div>
            <Steps items={wazuhReaderSteps()} ns="agents.wazuh.steps" within={1} />
          </details>
          <form onSubmit={submit} className="grid gap-4" noValidate>
            <p className="text-sm font-medium">{t('agents.wazuh.connectTitle')}</p>
            <Field label={t('agents.wazuh.url')} htmlFor="wazuh-url" hint={t('agents.wazuh.urlHint')}><Input id="wazuh-url" value={url} placeholder="https://wazuh-manager:55000" autoComplete="off" onChange={(e) => setUrl(e.target.value)} aria-describedby="wazuh-url-hint" /></Field>
            <Field label={t('agents.wazuh.username')} htmlFor="wazuh-user"><Input id="wazuh-user" value={username} maxLength={64} autoComplete="off" onChange={(e) => setUsername(e.target.value)} /></Field>
            <Field label={t('agents.wazuh.password')} htmlFor="wazuh-pass" hint={current ? t('agents.wazuh.passwordKeep') : t('agents.wazuh.passwordHint')}>
              <Input id="wazuh-pass" type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} aria-describedby="wazuh-pass-hint" />
            </Field>
            <Field label={t('agents.wazuh.interval')} htmlFor="wazuh-interval" className="max-w-xs">
              <Select id="wazuh-interval" value={interval} onChange={(e) => setInterval(Number(e.target.value))}>{(INTERVALS.includes(interval) ? INTERVALS : [...INTERVALS, interval].sort((a, b) => a - b)).map((m) => <option key={m} value={m}>{everyWords(t, m)}</option>)}</Select>
              <p className="text-meta text-muted">{t('agents.wazuh.limit')}</p>
            </Field>
            {ok ? <p role="status" className="rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm">{ok}</p> : null}
            {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
            <DialogFooter>
              <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
              <Button disabled={save.isPending} busy={test.isPending} busyLabel={t('common:busy.testing')} aria-describedby="wazuh-wait" onClick={doTest}>{t('agents.wazuh.test')}</Button>
              <Button type="submit" variant="primary" disabled={test.isPending} busy={save.isPending} busyLabel={t('common:busy.saving')} aria-describedby="wazuh-wait">{t('agents.wazuh.save')}</Button>
            </DialogFooter>
            {/* Test and Save both reach the Wazuh manager, up to 30 s (wazuhTestBudget) */}
            <BusyNote id="wazuh-wait" busy={test.isPending || save.isPending}>{t('agents.wazuh.waiting')}</BusyNote>
          </form>
        </div>
  )
}

function WazuhCard({ w }: { w: WazuhConnection | null }) {
  const { t } = useTranslation('inventory')
  const act = useWazuhActions()
  const [editing, setEditing] = useState(false)
  const [leaving, setLeaving] = useState(false)
  return (
    <div className="grid gap-3 rounded-md border border-rule bg-surface p-4">
      {w ? (
        <>
          <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
            <dt className="text-meta text-muted">{t('agents.wazuh.url')}</dt><dd className="[overflow-wrap:anywhere]">{w.url}</dd>
            <dt className="text-meta text-muted">{t('agents.wazuh.username')}</dt><dd>{w.username}, {t('agents.tokenMask', { last4: w.password_last4 })}</dd>
            <dt className="text-meta text-muted">{t('agents.wazuh.interval')}</dt><dd>{everyWords(t, w.interval_minutes)}<span className="block text-meta text-muted">{t('agents.wazuh.limit')}</span></dd>
            <dt className="text-meta text-muted">{t('agents.wazuh.statusLabel')}</dt>
            <dd className="flex flex-wrap items-center gap-2"><Chip tone={w.status === 'connected' ? 'ok' : w.status === 'error' ? 'danger' : 'off'}>{t(`agents.wazuh.status.${w.status}`)}</Chip>
              <span className="text-meta text-muted">{w.last_sync ? `${t('agents.wazuh.lastSync', { when: fmtRelative(w.last_sync) })}. ${t('agents.wazuh.summary', { agents: w.agents, packages: w.packages })}` : t('agents.wazuh.noSync')}</span></dd>
          </dl>
          {w.status === 'error' && w.error ? <p role="status" className="max-w-3xl text-sm text-danger">{w.error}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => setEditing(true)}>{t('agents.wazuh.edit')}</Button>
            {MOCK_BUILD ? <Button size="sm" busy={act.sample.isPending} busyLabel={t('common:busy.sending')} title={t('agents.sampleHint')}
              onClick={() => act.sample.mutate(undefined, { onSuccess: (r) => toast.success(t('agents.sampled', { devices: r.devices, software: r.software })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.sample')}</Button> : null}
            <Button size="sm" onClick={() => setLeaving(true)}>{t('agents.wazuh.disconnect')}</Button>
          </div>
          {editing ? <WazuhDialog key="edit" open onOpenChange={(o) => { if (!o) setEditing(false) }} current={w} /> : null}
          <Dialog open={leaving} onOpenChange={setLeaving}>
            <DialogContent title={t('agents.wazuh.disconnectTitle')} description={t('agents.wazuh.disconnectBody')}>
              <DialogFooter>
                <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
                <Button variant="danger" busy={act.disconnect.isPending} busyLabel={t('agents.wazuh.disconnecting')} onClick={() => act.disconnect.mutate(undefined, { onSuccess: () => { toast.success(t('agents.wazuh.disconnected')); setLeaving(false) }, onError: (e) => toast.error(errMsg(e)) })}>{t('agents.wazuh.disconnect')}</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      ) : (
        <div><Button onClick={() => setEditing(true)}><Plus />{t('agents.wazuh.connect')}</Button>
          {editing ? <WazuhDialog key="new" open onOpenChange={(o) => { if (!o) setEditing(false) }} current={null} /> : null}</div>
      )}
    </div>
  )
}

/** The Wazuh tab: Vedette reads agents and packages from the Wazuh server API. Needs module agent-intake. */
export function WazuhSection() {
  const { t } = useTranslation('inventory')
  const on = useModuleEnabled('agent-intake') === true
  const q = useAgents(on)
  return (
    <Section id="wazuh" label={t('agents.wazuh.title')} description={t('agents.wazuh.intro')} info={t('agents.wazuh.introInfo')} stories={['S-INV-4']}>
      <RequireModule module="agent-intake" fallback={<ModuleOff module="agent-intake">{t('agents.off')}</ModuleOff>}>
        <QueryState query={q}>{(d) => <WazuhCard w={d.wazuh} />}</QueryState>
      </RequireModule>
    </Section>
  )
}

/** Every enrolled agent with its state from its own check-ins; a quiet or never-reporting one says what to run on the machine. */
function MachinesTable({ nodes, box }: { nodes: AgentNode[]; box: string }) {
  const { t } = useTranslation('inventory')
  const { removeNode } = useAgentActions()
  const hp = boxHostPort(box)
  const columns: ColumnDef<AgentNode>[] = [
    { id: 'host', header: t('agents.machines.col.host'), accessorFn: (n) => n.host, cell: ({ row }) => <span className="font-medium">{row.original.host}</span> },
    { id: 'system', header: t('agents.machines.col.system'), accessorFn: (n) => n.os, cell: ({ row }) => t(`agents.machines.system.${row.original.os}`) },
    { id: 'state', header: t('agents.machines.col.state'), accessorFn: (n) => n.state, cell: ({ row }) => (
      <span className="grid gap-0.5">
        <Chip tone={row.original.state === 'reporting' ? 'ok' : row.original.state === 'replaced' ? 'off' : 'warn'}>{t(`agents.state.${row.original.state}`)}</Chip>
        {row.original.state === 'quiet' && row.original.quiet_since ? <span className="text-caption text-muted">{t('agents.machines.quietSince', { when: fmtDateTime(row.original.quiet_since) })}</span> : null}
      </span>
    ) },
    { id: 'heard', header: t('agents.machines.col.heard'), accessorFn: (n) => Date.parse(n.last_seen), cell: ({ row }) => <time dateTime={row.original.last_seen} title={fmtDateTime(row.original.last_seen)}>{fmtRelative(row.original.last_seen)}</time> },
    { id: 'todo', header: t('agents.machines.col.todo'), enableSorting: false, cell: ({ row }) => {
      const n = row.original
      const remove = (
        <Button size="sm" aria-label={t('agents.machines.removeLabel', { host: n.host })} busy={removeNode.isPending && removeNode.variables === n.id} busyLabel={t('common:busy.removing')}
          onClick={() => removeNode.mutate(n.id, { onSuccess: () => toast.success(t('agents.machines.removed', { host: n.host })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.machines.remove')}</Button>
      )
      if (n.state === 'reporting') return remove
      if (n.state === 'replaced') return <span className="grid justify-items-start gap-1"><span className="text-caption text-muted">{t('agents.machines.replacedNote')}</span>{remove}</span>
      if (n.state === 'never_reported') return <span className="grid justify-items-start gap-1"><span className="text-caption text-muted">{t('agents.machines.neverNote')}</span>{remove}</span>
      const cmd = AGENT_COMMANDS[n.os]
      return (
        <span className="grid justify-items-start gap-0.5 text-caption">
          <span className="text-muted">{t('agents.quiet.stopped')}</span>
          <code className="break-all font-mono">{cmd.check}</code><code className="break-all font-mono">{cmd.restart}</code>
          {hp ? <><span className="text-muted">{t('agents.quiet.running')}</span><code className="break-all font-mono">{cmd.reach(hp.host, hp.port)}</code></> : null}
          {remove}
        </span>
      )
    } },
  ]
  return (
    <div className="grid gap-1.5">
      <h3 className="text-sm font-medium">{t('agents.machines.title')}</h3>
      <p className="max-w-3xl text-meta text-muted">{t('agents.machines.body')}</p>
      {nodes.length ? <DataTable urlKey="agents-machines" caption={t('agents.machines.caption')} data={nodes} columns={columns} /> : <p className="text-meta text-muted">{t('agents.machines.none')}</p>}
    </div>
  )
}

/** S-INV-4: osquery (a token + a one-line install command for Linux and Windows Server) and Wazuh (Vedette pulls over the API). Needs the agent-intake module. */
export function AgentsSection() {
  const { t } = useTranslation('inventory')
  const { revoke, sampleToken, removeUnused } = useAgentActions()
  const on = useModuleEnabled('agent-intake') === true
  const q = useAgents(on)
  const [creating, setCreating] = useState(false)
  const [showing, setShowing] = useState<AgentToken | null>(null)
  const [revoking, setRevoking] = useState<AgentToken | null>(null)
  const isExpired = (a: AgentToken) => a.expires_at !== null && new Date(a.expires_at).getTime() < Date.now()
  const columns: ColumnDef<AgentToken>[] = [
    { id: 'name', header: t('agents.col.name'), accessorFn: (a) => a.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'madeBy', header: t('agents.col.madeBy'), accessorFn: (a) => a.created_by ?? '', cell: ({ row }) => row.original.created_by ?? <span className="text-muted">{t('agents.unknownMaker')}</span> },
    { id: 'madeAt', header: t('agents.col.madeAt'), accessorFn: (a) => Date.parse(a.created_at), cell: ({ row }) => <time dateTime={row.original.created_at} title={fmtDateTime(row.original.created_at)}>{fmtRelative(row.original.created_at)}</time> },
    { id: 'token', header: t('agents.col.token'), enableSorting: false, accessorFn: (a) => a.last4, cell: ({ row }) => <span className="whitespace-nowrap">{t('agents.tokenMask', { last4: row.original.last4 })}</span> },
    { id: 'expires', header: t('agents.col.expires'), accessorFn: (a) => a.expires_at ?? '9999', cell: ({ row }) => isExpired(row.original)
      ? <Chip tone="danger">{t('agents.expired')}</Chip>
      : row.original.expires_at ? <time dateTime={row.original.expires_at} title={fmtDateTime(row.original.expires_at)}>{fmtRelative(row.original.expires_at)}</time> : <span className="text-muted">{t('agents.noExpiry')}</span> },
    { id: 'received', header: t('agents.col.received'), accessorFn: (a) => (a.last_received ? new Date(a.last_received).getTime() : 0), cell: ({ row }) => row.original.last_received
      ? <time dateTime={row.original.last_received} title={fmtDateTime(row.original.last_received)}>{fmtRelative(row.original.last_received)}</time>
      : <span className="text-warn">{t('agents.never')}</span> },
    { id: 'hosts', header: t('agents.col.hosts'), accessorFn: (a) => a.hosts },
    { id: 'actions', header: () => <span className="sr-only">{t('agents.col.actions')}</span>, enableSorting: false, cell: ({ row }) => (
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => setShowing(row.original)} aria-label={t('agents.showConfig', { name: row.original.name })}>{t('agents.config')}</Button>
        {MOCK_BUILD ? <Button size="sm" disabled={sampleToken.isPending} busy={sampleToken.isPending && sampleToken.variables === row.original.id} busyLabel={t('common:busy.sending')} title={t('agents.sampleHint')} aria-label={t('agents.sampleFor', { name: row.original.name })}
          onClick={() => sampleToken.mutate(row.original.id, { onSuccess: (r) => toast.success(t('agents.sampled', { devices: r.devices, software: r.software })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.sample')}</Button> : null}
        <Button size="sm" onClick={() => setRevoking(row.original)} aria-label={t('agents.revoke', { name: row.original.name })}>{t('agents.revokeBtn')}</Button>
      </div>
    ) },
  ]
  return (
    <Section id="agents" label={t('agents.title')} description={t('agents.description')} info={<><p>{t('agents.descriptionInfo')}</p><p>{t('agents.osquery.introInfo')}</p></>} stories={['S-INV-4']}>
      <RequireModule module="agent-intake" fallback={<ModuleOff module="agent-intake">{t('agents.off')}</ModuleOff>}>
        <QueryState query={q}>
          {(d) => (
            <div className="grid gap-6">
              <div className="grid min-w-0 gap-5 [&>*]:min-w-0">
                <div className="grid gap-2">
                  <div className="flex flex-wrap items-end justify-between gap-3">
                    <div className="grid gap-1">
                      <div className="flex items-center gap-1"><h2 className="text-sm font-semibold">{t('agents.page.tokenTitle')}</h2><InfoTip topic={t('agents.page.tokenTitle')}><p>{t('agents.page.tokenBody')}</p><p>{t('agents.page.tokenBodyInfo')}</p></InfoTip></div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {/* empty-guard: a toast after the action, not a link or button that leads anywhere */}
                      {d.tokens.some((k) => k.hosts === 0 && Date.now() - Date.parse(k.created_at) > 3_600_000) ? <Button busy={removeUnused.isPending} busyLabel={t('common:busy.removing')} title={t('agents.removeUnused.hint')}
                        onClick={() => removeUnused.mutate(undefined, { onSuccess: (r) => toast.success(t('agents.removeUnused.done', { count: r.removed })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.removeUnused.button')}</Button> : null}
                      <Button onClick={() => setCreating(true)}><Plus />{t('agents.create')}</Button>
                    </div>
                  </div>
                  {d.tokens.length ? <DataTable urlKey="agent-tokens" caption={t('agents.caption')} data={d.tokens} columns={columns} /> : <EmptyState title={t('agents.empty')}>{t('agents.emptyBody')}</EmptyState>}
                </div>
                {d.tokens.length ? <MachinesTable nodes={d.nodes} box={d.server_url} /> : null}
                {/* The packages are one folded line at the bottom: the install command downloads the right one by itself. */}
                {d.install.packages.length ? (
                  <details className="rounded-md border border-rule p-3">
                    <summary className="cursor-pointer text-sm font-medium">{t('agents.page.downloadTitle', { version: d.install.osquery_version })}</summary>
                    <div className="mt-2 grid gap-2">
                      <div className="flex items-center gap-1"><p className="max-w-3xl text-meta text-muted">{t('agents.page.downloadBody', { version: d.install.osquery_version })}</p><InfoTip topic={t('agents.page.downloadTitle', { version: d.install.osquery_version })}><p>{t('agents.page.downloadBodyInfo')}</p><p>{t('agents.page.checkHint')}</p></InfoTip></div>
                      <PackageTable packages={d.install.packages} />
                    </div>
                  </details>
                ) : <Notice tone="warn" role="status" className="mb-0 max-w-3xl" title={t('agents.page.none')} info={t('agents.page.noneInfo')} />}
              </div>
              <CreateDialog open={creating} onOpenChange={setCreating} data={d} />
              <Dialog open={!!showing} onOpenChange={(o) => { if (!o) setShowing(null) }}>
                <DialogContent wide title={t('agents.configTitle', { name: showing?.name ?? '' })} description={t('agents.configBody')} info={t('agents.configBodyInfo')}>
                  {showing ? <InstallPanel data={d} token="<TOKEN>" /> : null}
                  <DialogFooter><DialogClose asChild><Button>{t('common:close')}</Button></DialogClose></DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          )}
        </QueryState>
      </RequireModule>
      <Dialog open={!!revoking} onOpenChange={(o) => { if (!o) setRevoking(null) }}>
        <DialogContent title={t('agents.revokeTitle', { name: revoking?.name ?? '' })} description={t('agents.revokeBody')}>
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="danger" busy={revoke.isPending} busyLabel={t('agents.revoking')} onClick={() => revoking && revoke.mutate(revoking.id, { onSuccess: () => { toast.success(t('agents.revoked', { name: revoking.name })); setRevoking(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('agents.revokeConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}
