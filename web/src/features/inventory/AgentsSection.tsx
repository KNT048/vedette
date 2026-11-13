import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { Download, Plus } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { EmptyState, ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { linuxOneLiner, OSQUERY_SCHEDULE, osquerySteps, windowsOneLiner, wazuhReaderSteps, type Platform } from './agentConfig'
import { NO_BOX_ADDRESS } from './installScripts'
import { useAgentActions, useAgents, useWazuhActions } from './api'
import { errMsg } from './kinds'
import type { AgentToken, AgentsResponse, CreateTokenResult, OsqueryPackage, WazuhConnection } from './types'

/** Chỉ bản xem thử có mock API: nút "Send sample data" giả lập một lần agent báo về (bản thật không có). */
const MOCK_BUILD = import.meta.env.DEV || import.meta.env.VITE_API_MOCK !== 'off'

function Steps({ items, ns }: { items: { key: string; file: string; code: string }[]; ns: string }) {
  const { t } = useTranslation('inventory')
  return (
    <ol className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {items.map((s, i) => (
        <li key={s.key} className="grid gap-1.5">
          <p className="text-sm font-medium">{i + 1}. {t(`${ns}.${s.key}`)}</p>
          <CodeBlock label={s.file} code={s.code} />
        </li>
      ))}
    </ol>
  )
}

/** D-399 (2): the box knows no address other machines can reach (opened as localhost, no other name configured). A command pinned to
 *  <VEDETTE_BOX_IP> passes its hash check and then fails on every server, so none is shown: say how to give the box an address. */
function NoBoxAddress() {
  const { t } = useTranslation('inventory')
  const install = useInstallKind()
  return (
    <div role="status" className="grid gap-1.5 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">
      <p className="font-medium">{t('agents.noAddress.title')}</p>
      <p>{t(install === 'container' ? 'agents.noAddress.container' : 'agents.noAddress.appliance')}</p>
      <p className="text-[13px] text-muted">{t('agents.noAddress.token')}</p>
    </div>
  )
}

/** D-465 (review M2): say which address the commands carry and where it is changed; when the page was opened at another host, say that
 *  agents will not use that one. No lookup of the name is made. */
function BoxAddressNote({ box }: { box: string }) {
  const { t } = useTranslation('inventory')
  const install = useInstallKind()
  let host = box
  try { host = new URL(box).hostname } catch { /* shown as given */ }
  const here = window.location.hostname
  return (
    <div className="grid gap-1 text-[13px]">
      <p>
        {t('agents.boxAddress.uses', { url: box })}{' '}
        {install === 'container'
          ? t('agents.boxAddress.container')
          : <Link to="/settings/network#box-address" className="text-accent underline-offset-4 hover:underline">{t('agents.boxAddress.change')}</Link>}
      </p>
      {here && host.toLowerCase() !== here.toLowerCase() ? <p className="text-muted">{t('agents.boxAddress.otherHost', { here, box: host })}</p> : null}
    </div>
  )
}

/** D-404: the packages the box serves for the chosen OS, each a direct download from this origin (the public mirror route of D-169: the
 *  browser saves it under its own name), with what it is for, its size and the SHA-256 of the box's SHA256SUMS. */
function Downloads({ packages }: { packages: OsqueryPackage[] }) {
  const { t } = useTranslation('inventory')
  return (
    <div className="grid gap-1.5">
      <p className="text-sm font-medium">{t('agents.download.title')}</p>
      <p className="text-[13px] text-muted">{t('agents.download.body')}</p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <caption className="sr-only">{t('agents.download.caption')}</caption>
          <thead className="text-muted"><tr>
            <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.file')}</th>
            <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.for')}</th>
            <th scope="col" className="py-1 pr-3 font-medium">{t('agents.download.col.size')}</th>
            <th scope="col" className="py-1 font-medium">{t('agents.download.col.sha')}</th>
          </tr></thead>
          <tbody>
            {packages.map((p) => (
              <tr key={p.file} className="border-t border-rule align-top">
                <td className="py-1.5 pr-3">
                  <a href={`/api/v1/install/osquery/${encodeURIComponent(p.file)}`} download={p.file} aria-label={t('agents.download.link', { file: p.file })}
                    className="inline-flex items-center gap-1 font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">
                    <Download className="size-3.5 shrink-0" aria-hidden />{p.file}
                  </a>
                </td>
                <td className="py-1.5 pr-3">{t(`agents.download.format.${p.format}`)} · {p.format === 'msi' ? 'x64' : p.arch}</td>
                <td className="whitespace-nowrap py-1.5 pr-3">{t('agents.download.size', { mb: (p.size / 1e6).toFixed(1) })}</td>
                <td className="py-1.5"><code className="break-all font-mono text-[12px]">{p.sha256}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Một dòng lệnh cài và gỡ cho Linux hoặc Windows Server, script đọc được, tải gói trực tiếp (D-404), và cài tay ở mục "Advanced". */
function InstallPanel({ data, token }: { data: AgentsResponse; token: string }) {
  const { t } = useTranslation('inventory')
  const [platform, setPlatform] = useState<Platform>('linux')
  const box = data.server_url
  if (box.includes(NO_BOX_ADDRESS)) return <NoBoxAddress />
  const inst = data.install[platform]
  const packages = data.install.packages.filter((p) => p.platform === platform)
  const one = platform === 'linux' ? linuxOneLiner : windowsOneLiner
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <BoxAddressNote box={box} />
      <div className="grid gap-1.5">
        <span className="text-sm font-medium">{t('agents.platform.label')}</span>
        <Segmented<Platform> label={t('agents.platform.label')} value={platform} onChange={setPlatform}
          options={[{ value: 'linux', label: t('agents.platform.linux') }, { value: 'windows', label: t('agents.platform.windows') }]} />
        <p className="text-[13px] text-muted">{t('agents.serverOnly')}</p>
      </div>
      <div className="grid gap-1.5">
        <p className="text-sm font-medium">{t('agents.install.title')}</p>
        <p className="text-[13px] text-muted">{t(`agents.install.${platform}How`)}</p>
        {packages.length ? null : <p role="status" className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">{t('agents.download.none')}</p>}
        <CodeBlock label={t(`agents.install.${platform}Label`)} code={one(box, inst.sha256, token)} />
        <p className="text-[13px]"><span className="font-medium">{t('agents.install.sha')}:</span> <code className="break-all font-mono text-[12.5px]">{inst.sha256}</code></p>
        <p className="text-[13px] text-muted">{t('agents.install.shaHint')}</p>
        {platform === 'windows' ? <p className="text-[13px] text-muted">{t('agents.install.windowsWhy')}</p> : null}
      </div>
      <details className="rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('agents.install.readFirst')}</summary>
        <p className="my-2 text-[13px] text-muted">{t('agents.install.readFirstBody')}</p>
        <CodeBlock label={inst.url} code={inst.script} />
      </details>
      {packages.length ? <Downloads packages={packages} /> : null}
      <div className="grid gap-1.5">
        <p className="text-sm font-medium">{t('agents.install.uninstall')}</p>
        <CodeBlock label={t(`agents.install.${platform}Label`)} code={one(box, inst.sha256, token, 'uninstall')} />
      </div>
      <p className="text-[13px] text-muted">{t('agents.install.security')}</p>
      <details className="rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('agents.install.advanced')}</summary>
        <div className="mt-3 grid min-w-0 gap-4 [&>*]:min-w-0">
          <p className="text-[13px] text-muted">{t('agents.install.advancedBody')}</p>
          <Steps items={osquerySteps(platform, box, token, packages)} ns={`agents.steps.${platform}`} />
          <div className="grid gap-1.5">
            <p className="text-sm font-medium">{t('agents.install.queries')}</p>
            <p className="text-[13px] text-muted">{t('agents.install.queriesBody')}</p>
            <CodeBlock label="schedule" code={OSQUERY_SCHEDULE} />
          </div>
          <p className="text-[13px] text-muted">{t('agents.fingerprint')}</p>
          <p className="text-[13px] text-muted">{t('agents.ownPaths')}</p>
        </div>
      </details>
    </div>
  )
}

function CreateDialog({ open, onOpenChange, data }: { open: boolean; onOpenChange: (o: boolean) => void; data: AgentsResponse }) {
  const { t } = useTranslation('inventory')
  const { create } = useAgentActions()
  const [name, setName] = useState('')
  const [days, setDays] = useState(7)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CreateTokenResult | null>(null)
  function close(o: boolean) { onOpenChange(o); if (!o) { setName(''); setDays(7); setError(null); setResult(null) } }
  function submit(e: FormEvent) {
    e.preventDefault(); setError(null)
    create.mutate({ name, kind: 'osquery', expires_in_days: days }, { onSuccess: setResult, onError: (er) => setError(errMsg(er)) })
  }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent wide={!!result} title={result ? t('agents.createdTitle', { name: result.token.name }) : t('agents.createTitle')} description={result ? t('agents.createdBody') : t('agents.recommendation')}>
        {result ? (
          <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
            <CodeBlock label={t('agents.tokenLabel')} code={result.secret} />
            <p className="text-[13px] text-warn">{t('agents.tokenOnce')}</p>
            <InstallPanel data={data} token={result.secret} />
            <DialogFooter><DialogClose asChild><Button variant="primary">{t('agents.done')}</Button></DialogClose></DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} className="grid gap-4" noValidate>
            <p className="text-[13px] text-muted">{t('agents.serverOnly')}</p>
            <Field label={t('agents.name')} htmlFor="agent-name" hint={t('agents.nameHint')}><Input id="agent-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} aria-describedby="agent-name-hint" /></Field>
            <Field label={t('agents.expiry')} htmlFor="agent-expiry" hint={t('agents.expiryHint')}>
              <Select id="agent-expiry" className="max-w-xs" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-describedby="agent-expiry-hint">
                {[1, 7, 30, 90, 0].map((d) => <option key={d} value={d}>{t(`agents.expiryOption.${d}`)}</option>)}
              </Select>
            </Field>
            {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
            <DialogFooter>
              <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
              <Button type="submit" variant="primary" disabled={!name.trim() || create.isPending}>{t('agents.createSubmit')}</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

const INTERVALS = [5, 15, 60, 360, 1440]

function WazuhDialog({ open, onOpenChange, current }: { open: boolean; onOpenChange: (o: boolean) => void; current: WazuhConnection | null }) {
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
    save.mutate(input, { onSuccess: () => { toast.success(t('agents.wazuh.saved')); onOpenChange(false) }, onError: (er) => setError(errMsg(er)) })
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide title={t('agents.wazuh.formTitle')} description={t('agents.wazuh.formBody')}>
        <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
          <details className="rounded-md border border-rule p-3" open={!current}>
            <summary className="cursor-pointer text-sm font-medium">{t('agents.wazuh.stepsTitle')}</summary>
            <p className="my-2 text-[13px] text-muted">{t('agents.wazuh.stepsBody')}</p>
            <Steps items={wazuhReaderSteps()} ns="agents.wazuh.steps" />
          </details>
          <form onSubmit={submit} className="grid gap-4" noValidate>
            <p className="text-sm font-medium">{t('agents.wazuh.connectTitle')}</p>
            <Field label={t('agents.wazuh.url')} htmlFor="wazuh-url" hint={t('agents.wazuh.urlHint')}><Input id="wazuh-url" value={url} placeholder="https://wazuh-manager:55000" autoComplete="off" onChange={(e) => setUrl(e.target.value)} aria-describedby="wazuh-url-hint" /></Field>
            <Field label={t('agents.wazuh.username')} htmlFor="wazuh-user"><Input id="wazuh-user" value={username} maxLength={64} autoComplete="off" onChange={(e) => setUsername(e.target.value)} /></Field>
            <Field label={t('agents.wazuh.password')} htmlFor="wazuh-pass" hint={current ? t('agents.wazuh.passwordKeep') : t('agents.wazuh.passwordHint')}>
              <Input id="wazuh-pass" type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} aria-describedby="wazuh-pass-hint" />
            </Field>
            <Field label={t('agents.wazuh.interval')} htmlFor="wazuh-interval" className="max-w-xs">
              <Select id="wazuh-interval" value={interval} onChange={(e) => setInterval(Number(e.target.value))}>{INTERVALS.map((m) => <option key={m} value={m}>{t(`agents.wazuh.intervalOption.${m}`)}</option>)}</Select>
            </Field>
            {ok ? <p role="status" className="rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm">{ok}</p> : null}
            {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
            <DialogFooter>
              <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
              <Button disabled={test.isPending || save.isPending} onClick={doTest}>{t('agents.wazuh.test')}</Button>
              <Button type="submit" variant="primary" disabled={save.isPending || test.isPending}>{t('agents.wazuh.save')}</Button>
            </DialogFooter>
          </form>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function WazuhCard({ w }: { w: WazuhConnection | null }) {
  const { t } = useTranslation('inventory')
  const act = useWazuhActions()
  const [editing, setEditing] = useState(false)
  const [leaving, setLeaving] = useState(false)
  return (
    <div className="grid gap-3 rounded-md border border-rule bg-surface p-4">
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">{t('agents.wazuh.title')}</h3>
        <p className="max-w-3xl text-[13px] text-muted">{t('agents.wazuh.intro')}</p>
      </div>
      {w ? (
        <>
          <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
            <dt className="text-[13px] text-muted">{t('agents.wazuh.url')}</dt><dd className="[overflow-wrap:anywhere]">{w.url}</dd>
            <dt className="text-[13px] text-muted">{t('agents.wazuh.username')}</dt><dd>{w.username}, {t('agents.tokenMask', { last4: w.password_last4 })}</dd>
            <dt className="text-[13px] text-muted">{t('agents.wazuh.interval')}</dt><dd>{t(`agents.wazuh.intervalOption.${w.interval_minutes}`)}</dd>
            <dt className="text-[13px] text-muted">{t('agents.wazuh.statusLabel')}</dt>
            <dd className="flex flex-wrap items-center gap-2"><Chip tone={w.status === 'connected' ? 'ok' : w.status === 'error' ? 'danger' : 'off'}>{t(`agents.wazuh.status.${w.status}`)}</Chip>
              <span className="text-[13px] text-muted">{w.last_sync ? `${t('agents.wazuh.lastSync', { when: fmtRelative(w.last_sync) })}. ${t('agents.wazuh.summary', { agents: w.agents, packages: w.packages })}` : t('agents.wazuh.noSync')}</span></dd>
          </dl>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => setEditing(true)}>{t('agents.wazuh.edit')}</Button>
            {MOCK_BUILD ? <Button size="sm" disabled={act.sample.isPending} title={t('agents.sampleHint')}
              onClick={() => act.sample.mutate(undefined, { onSuccess: (r) => toast.success(t('agents.sampled', { devices: r.devices, software: r.software })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.sample')}</Button> : null}
            <Button size="sm" onClick={() => setLeaving(true)}>{t('agents.wazuh.disconnect')}</Button>
          </div>
          {editing ? <WazuhDialog key="edit" open onOpenChange={(o) => { if (!o) setEditing(false) }} current={w} /> : null}
          <Dialog open={leaving} onOpenChange={setLeaving}>
            <DialogContent title={t('agents.wazuh.disconnectTitle')} description={t('agents.wazuh.disconnectBody')}>
              <DialogFooter>
                <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
                <Button variant="danger" disabled={act.disconnect.isPending} onClick={() => act.disconnect.mutate(undefined, { onSuccess: () => { toast.success(t('agents.wazuh.disconnected')); setLeaving(false) }, onError: (e) => toast.error(errMsg(e)) })}>{t('agents.wazuh.disconnect')}</Button>
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

/** S-INV-4: osquery (token + một dòng lệnh cài cho Linux và Windows Server) và Wazuh (Vedette kéo qua API). Cần module agent-intake. */
export function AgentsSection() {
  const { t } = useTranslation('inventory')
  const { revoke, sampleToken } = useAgentActions()
  const on = useModuleEnabled('agent-intake') === true
  const q = useAgents(on)
  const [creating, setCreating] = useState(false)
  const [showing, setShowing] = useState<AgentToken | null>(null)
  const [revoking, setRevoking] = useState<AgentToken | null>(null)
  const isExpired = (a: AgentToken) => a.expires_at !== null && new Date(a.expires_at).getTime() < Date.now()
  const columns: ColumnDef<AgentToken>[] = [
    { id: 'name', header: t('agents.col.name'), accessorFn: (a) => a.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
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
        {MOCK_BUILD ? <Button size="sm" disabled={sampleToken.isPending} title={t('agents.sampleHint')} aria-label={t('agents.sampleFor', { name: row.original.name })}
          onClick={() => sampleToken.mutate(row.original.id, { onSuccess: (r) => toast.success(t('agents.sampled', { devices: r.devices, software: r.software })), onError: (e) => toast.error(errMsg(e)) })}>{t('agents.sample')}</Button> : null}
        <Button size="sm" onClick={() => setRevoking(row.original)} aria-label={t('agents.revoke', { name: row.original.name })}>{t('agents.revokeBtn')}</Button>
      </div>
    ) },
  ]
  return (
    <Section id="agents" title={t('agents.title')} description={t('agents.description')} stories={['S-INV-4']}
      actions={<Button disabled={!on} title={on ? undefined : t('agents.off')} onClick={() => setCreating(true)}><Plus />{t('agents.create')}</Button>}>
      <RequireModule module="agent-intake" fallback={<ModuleOff module="agent-intake">{t('agents.off')}</ModuleOff>}>
        <QueryState query={q}>
          {(d) => (
            <div className="grid gap-6">
              <p className="max-w-3xl rounded-md border border-rule bg-sunken px-3 py-2 text-sm">{t('agents.recommendation')}</p>
              <div className="grid gap-2">
                <h3 className="text-sm font-semibold">{t('agents.osquery.title')}</h3>
                <p className="max-w-3xl text-[13px] text-muted">{t('agents.osquery.intro')}</p>
                {d.tokens.length ? <DataTable caption={t('agents.caption')} data={d.tokens} columns={columns} /> : <EmptyState title={t('agents.empty')}>{t('agents.emptyBody')}</EmptyState>}
              </div>
              <WazuhCard w={d.wazuh} />
              <CreateDialog open={creating} onOpenChange={setCreating} data={d} />
              <Dialog open={!!showing} onOpenChange={(o) => { if (!o) setShowing(null) }}>
                <DialogContent wide title={t('agents.configTitle', { name: showing?.name ?? '' })} description={t('agents.configBody')}>
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
            <Button variant="danger" disabled={revoke.isPending} onClick={() => revoking && revoke.mutate(revoking.id, { onSuccess: () => { toast.success(t('agents.revoked', { name: revoking.name })); setRevoking(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('agents.revokeConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}
