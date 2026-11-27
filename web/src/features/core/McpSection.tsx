import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Notice, PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import { Card } from '@/components/common/Card'
import { Loading, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useMcp, useMcpMutations, useToggleModule } from './api'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { useScope } from '@/lib/v1'
import { errMsg, useGate } from './parts'
import type { McpState, McpToken } from './types'

/** The switch is the mcp-server module's own (PATCH /modules/mcp-server): the section reads /core/mcp only while it is on. */
function McpSwitch({ on }: { on: boolean }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const toggle = useToggleModule()
  const container = useInstallKind() === 'container'
  async function flip(v: boolean) {
    try { await toggle.mutateAsync({ id: 'mcp-server', enabled: v }); toast.success(v ? t('mcp.enabledToast') : t('mcp.disabledToast')) } catch (e) { toast.error(errMsg(e, t)) }
  }
  return (
    <Card className="mb-6 flex flex-wrap items-center gap-3">
      <Switch id="mcp-switch" checked={on} disabled={gate.disabled || toggle.isPending} title={gate.title} aria-label={on ? t('mcp.switchOff') : t('mcp.switch')} onCheckedChange={(v) => void flip(v)} />
      <label htmlFor="mcp-switch" className="text-sm font-medium">{on ? t('mcp.switchOff') : t('mcp.switch')}</label>
      {on ? <Chip tone="ok">{t('mcp.readOnly')}</Chip> : null}
      <span className="text-meta text-muted">{on ? t(container ? 'mcp.onHintContainer' : 'mcp.onHint') : t('mcp.offHint')}</span>
      {on && container ? <InfoTip topic={t('mcp.onHintContainer')}>{t('mcp.onHintContainerInfo')}</InfoTip> : null}
    </Card>
  )
}

/** `locked` (#819: on here, not offered in v1): everything is shown and tokens can be revoked; no new token. */
function Body({ s, locked = false }: { s: McpState; locked?: boolean }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const m = useMcpMutations()
  const container = useInstallKind() === 'container' // The port is on the localhost of the machine that runs the container (S-CORE-9)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<string[]>(['assets', 'findings', 'feeds'])
  const [formErr, setFormErr] = useState<string | null>(null)
  const [created, setCreated] = useState<{ token: string; name: string } | null>(null)
  const [adding, setAdding] = useState(false)
  const [askRevoke, setAskRevoke] = useState<McpToken | null>(null)

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setFormErr(null)
    if (!name.trim()) { setFormErr(t('mcp.token.nameError')); return }
    if (!scopes.length) { setFormErr(t('mcp.token.scopeError')); return }
    try { const r = await m.create.mutateAsync({ name: name.trim(), scopes }); setName(''); setAdding(false); setCreated({ token: r.token, name: r.item.name }) } catch (err) { setFormErr(errMsg(err, t)) }
  }
  async function revoke(tk: McpToken) {
    try { await m.revoke.mutateAsync(tk.id); setAskRevoke(null); toast.success(t('mcp.token.revoked', { name: tk.name })) } catch (e) { setAskRevoke(null); toast.error(errMsg(e, t)) }
  }

  const tokenCols: ColumnDef<McpToken>[] = [
    { id: 'name', header: t('mcp.token.col.name'), accessorFn: (x) => x.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'scopes', header: t('mcp.token.col.scopes'), accessorFn: (x) => x.scopes.join(','), cell: ({ row }) => row.original.scopes.map((x) => t(`mcp.scope.${x}`)).join(', ') },
    { id: 'last4', header: t('mcp.token.col.last4'), accessorFn: (x) => x.last4, cell: ({ row }) => <span className="font-mono text-meta">…{row.original.last4}</span> },
    { id: 'created', header: t('mcp.token.col.created'), accessorFn: (x) => x.created_at, cell: ({ row }) => fmtDateTime(row.original.created_at) },
    { id: 'used', header: t('mcp.token.col.used'), accessorFn: (x) => x.last_used ?? '', cell: ({ row }) => (row.original.last_used ? fmtRelative(row.original.last_used) : t('mcp.token.never')) },
    { id: 'rev', header: t('mcp.token.col.revoke'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => <Button size="sm" variant="danger" aria-label={t('mcp.token.revokeOf', { name: row.original.name })} disabled={gate.disabled || m.revoke.isPending} busy={m.revoke.isPending && m.revoke.variables === row.original.id} busyLabel={t('mcp.token.revoking')} title={gate.title} onClick={() => setAskRevoke(row.original)}>{t('mcp.token.revoke')}</Button> },
  ]
  const toolCols: ColumnDef<{ name: string; scope: string }>[] = [
    { id: 'name', header: t('mcp.tools.col.name'), accessorFn: (x) => x.name, cell: ({ row }) => <span className="font-mono text-meta">{row.original.name}</span> },
    { id: 'what', header: t('mcp.tools.col.what'), accessorFn: (x) => x.name, cell: ({ row }) => t(`mcp.tools.${row.original.name}`) },
    { id: 'scope', header: t('mcp.tools.col.scope'), accessorFn: (x) => x.scope, cell: ({ row }) => t(`mcp.scope.${row.original.scope}`) },
  ]

  return (
    <>
      <McpSwitch on />
      {s.enabled ? (
        <>
          {!s.listening ? <Notice tone="danger" role="alert" className="mb-6" title={s.listen_error ?? t('mcp.notListening')} info={t('mcp.notListeningInfo')}>{t('mcp.notListeningHint')}</Notice> : null}
          <Section title={t('mcp.connect')} description={t('mcp.connectDesc')} info={<><p>{t(container ? 'mcp.remoteContainer' : 'mcp.remote')}</p><p>{t('mcp.verify')}</p></>}>
            <KeyValue items={[
              { label: t('mcp.bind'), value: <span><span className="font-mono text-meta">{s.bind}:{s.port}</span> {t('mcp.bindNote')}</span> },
              { label: t('mcp.endpoint'), value: <span className="font-mono text-meta">{s.endpoint}</span> },
            ]} />
            <div className="mt-3"><CodeBlock label={t('mcp.clientConfig')} code={JSON.stringify({ mcpServers: { vedette: { type: 'http', url: s.endpoint, headers: { Authorization: 'Bearer <token>' } } } }, null, 2)} /></div>
          </Section>

          <Section title={t('mcp.token.title')} description={t('mcp.token.desc')}>
            {locked ? null : <div className="mb-4"><Button variant="primary" disabled={gate.disabled} title={gate.title} onClick={() => { setFormErr(null); setAdding(true) }}><Plus />{t('mcp.token.create')}</Button></div>}
            <Dialog open={adding} onOpenChange={setAdding}>
              {adding ? (
                <DialogContent title={t('mcp.token.create')}>
                  <form onSubmit={(e) => void create(e)} className="grid gap-4" noValidate>
                    <Field label={t('mcp.token.name')} hint={t('mcp.token.nameHint')} htmlFor="mcp-name" error={formErr ?? undefined}><Input id="mcp-name" value={name} disabled={gate.disabled} aria-invalid={!!formErr} onChange={(e) => setName(e.target.value)} /></Field>
                    <fieldset className="grid gap-2">
                      <legend className="text-sm font-medium">{t('mcp.token.scopes')}</legend>
                      {s.scopes.map((sc) => (
                        <div key={sc} className="flex items-center gap-2">
                          <Checkbox id={`sc-${sc}`} checked={scopes.includes(sc)} disabled={gate.disabled} onCheckedChange={(v) => setScopes(v === true ? [...scopes, sc] : scopes.filter((x) => x !== sc))} />
                          <label htmlFor={`sc-${sc}`} className="text-sm">{t(`mcp.scope.${sc}`)}</label>
                        </div>
                      ))}
                    </fieldset>
                    <DialogFooter>
                      <Button type="button" onClick={() => setAdding(false)}>{t('common:cancel')}</Button>
                      <Button type="submit" variant="primary" disabled={gate.disabled} busy={m.create.isPending} busyLabel={t('common:busy.creating')} title={gate.title}>{t('mcp.token.create')}</Button>
                    </DialogFooter>
                  </form>
                </DialogContent>
              ) : null}
            </Dialog>
            <DataTable urlKey="mcp-tokens" data={s.tokens} columns={tokenCols} caption={t('mcp.token.title')} empty={t('mcp.token.empty')} />
          </Section>

          <Section title={t('mcp.tools.title')} description={t('mcp.tools.desc')} info={t('mcp.tools.info')}>
            <DataTable urlKey="mcp-tools" data={s.tools} columns={toolCols} caption={t('mcp.tools.title')} />
          </Section>
        </>
      ) : null}

      <Dialog open={!!askRevoke} onOpenChange={(o) => !o && setAskRevoke(null)}>
        <DialogContent title={t('mcp.token.revokeAsk.title', { name: askRevoke?.name ?? '' })} description={t('mcp.token.revokeAsk.body')} info={t('mcp.token.revokeAsk.info')}>
          <DialogFooter>
            <Button onClick={() => setAskRevoke(null)}>{t('common:cancel')}</Button>
            <Button variant="danger" busy={m.revoke.isPending} busyLabel={t('mcp.token.revoking')} onClick={() => askRevoke && void revoke(askRevoke)}>{t('mcp.token.revoke')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!created} onOpenChange={(o) => !o && setCreated(null)}>
        <DialogContent title={t('mcp.token.createdTitle', { name: created?.name ?? '' })} description={t('mcp.token.createdBody')} info={t('mcp.token.createdInfo')}>
          {created ? <CodeBlock label={t('mcp.token.label')} code={created.token} /> : null}
          <DialogFooter><Button variant="primary" onClick={() => setCreated(null)}>{t('mcp.token.done')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

export default function McpSection() {
  const { t } = useTranslation('core')
  const on = useModuleEnabled('mcp-server')
  // Left out of v1. A box that has it on keeps its tokens visible, Revoke and the off switch; no new token. The line
  // under the title says so (PageHeader, PageModule from the section).
  const leaving = useScope('mcp-server') === 'leaving'
  const q = useMcp(on === true)
  const status = on === false ? t('mcp.titleOff') : q.data ? t('mcp.titleOn', { count: q.data.tokens.length }) : null
  return (
    <>
      <PageHeader title={t('settings.mcp')} meta={status ? `${status}. ${t('mcp.meta')}` : t('mcp.meta')} info={t('mcp.metaInfo')} stories={['S-MCP-1']} />
      {on === undefined ? <Loading /> : on ? <QueryState query={q}>{(s) => <Body s={s} locked={leaving} />}</QueryState> : <McpSwitch on={false} />}
    </>
  )
}
