import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { CONNECTION_KINDS, usesUsername } from '@/lib/connections'
import { useConnections, useRemoveConnection, useSaveConnection, useTestConnection } from './api'
import { CONNECTOR_AUTH } from './contract'
import { errMsg } from './parts'
import type { Connector, ConnectorInput, ConnectorKind } from './types'

const KINDS: ConnectorKind[] = [...CONNECTION_KINDS]
const AUTHS = ['none', 'token', 'basic', 'ssh-key'] as const
const asInput = (c: Connector, over: Partial<ConnectorInput> = {}): ConnectorInput => ({ name: c.name, kind: c.kind, target: c.target, asset_id: c.asset_id, auth_type: c.auth.type, username: c.username, allow: c.allow, enabled: c.enabled, ...over })

/**
 * Settings → Connections (D-93; S-AI-7, S-RESP-4): HTTP API, SSH/CLI, RESTCONF, automation platform and MCP server connections, generic kinds only (D-58).
 * They live in core, so the page is always there, also when the AI module is off. Write tools run only through approved response actions (D-41).
 * Every request goes to the address typed here and nowhere else: privacy flow 12.
 */
export default function ConnectionsSection() {
  const { t } = useTranslation('core')
  const conns = useConnections()
  const save = useSaveConnection()
  const remove = useRemoveConnection()
  const test = useTestConnection()
  const [edit, setEdit] = useState<Connector | 'new' | null>(null)
  const [del, setDel] = useState<Connector | null>(null)
  const [result, setResult] = useState<{ id: string; ok?: string; error?: string } | null>(null)
  const fail = (e: unknown) => toast.error(errMsg(e, t))
  function runTest(c: Connector) {
    setResult(null)
    test.mutate(c.id, { onSuccess: (r) => setResult({ id: c.id, ok: r.message }), onError: (e) => setResult({ id: c.id, error: errMsg(e, t) }) })
  }
  const count = conns.data?.items.length ?? 0
  return (
    <>
      <PageHeader title={t('connections.title')} meta={t('connections.meta')} stories={['S-AI-7', 'S-RESP-4']} actions={count > 0 ? <Button variant="primary" onClick={() => setEdit('new')}>{t('connections.add')}</Button> : undefined} />
      <Panel className="mb-4 grid gap-1.5 p-4 text-sm">
        <p><strong>{t('connections.writeNoteLead')}</strong> {t('connections.writeNote')}</p>
        <p className="text-muted">{t('connections.privacyNote')} <Link className="text-accent underline underline-offset-4" to="/settings/privacy">{t('connections.privacyLink')}</Link></p>
      </Panel>
      <QueryState query={conns}>
        {({ items }) => items.length === 0 ? (
          <EmptyState title={t('connections.empty')} action={<Button variant="primary" onClick={() => setEdit('new')}>{t('connections.add')}</Button>}>{t('connections.emptyBody')}</EmptyState>
        ) : (
          <ul aria-label={t('connections.title')} className="grid gap-4">
            {items.map((c) => {
              const unsupported = c.kind === 'mcp-stdio'
              return (
                <li key={c.id}>
                  <Panel className={`grid gap-3 p-4 ${c.enabled && !unsupported ? '' : 'opacity-70'}`}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="grid min-w-0 gap-1">
                        <h2 className="flex flex-wrap items-center gap-2 text-sm font-semibold">{c.name} <Chip tone="off">{t(`connections.kind.${c.kind}`)}</Chip>
                          {unsupported ? <Chip tone="warn">{t('connections.unsupported')}</Chip> : <Chip tone={c.status === 'ok' ? 'ok' : c.status === 'error' ? 'danger' : 'warn'}>{t(`connections.status.${c.status}`)}</Chip>}</h2>
                        <p className="break-all font-mono text-[12.5px] text-muted">{c.target}</p>
                        <p className="text-[13px] text-muted">
                          {c.auth.type === 'none' ? t('connections.noAuth') : t('connections.authEnds', { type: t(`connections.auth.${c.auth.type}`), last4: c.auth.last4 })}
                          {c.username ? ` · ${t('connections.asUser', { user: c.username })}` : ''}
                          {c.last_test ? ` · ${t('connections.tested', { when: fmtRelative(c.last_test) })}` : ` · ${t('connections.neverTested')}`}
                        </p>
                        {c.pin ? <p className="text-[13px] text-muted">{c.pin.kind === 'ssh_hostkey' ? t('connections.pinSsh') : t('connections.pinTls')}: <code className="break-all font-mono text-[12px] text-ink">{c.pin.value}</code>, {t('connections.pinSeen', { when: fmtRelative(c.pin.first_seen) })}</p> : null}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Switch checked={c.enabled} disabled={unsupported} aria-label={t('connections.enable', { name: c.name })} onCheckedChange={(enabled) => save.mutate({ id: c.id, ...asInput(c, { enabled }) }, { onError: fail })} />
                        <Button size="sm" onClick={() => runTest(c)} disabled={test.isPending || unsupported} aria-label={t('connections.testNamed', { name: c.name })}>{test.isPending && test.variables === c.id ? t('connections.testing') : t('connections.test')}</Button>
                        <Button size="sm" onClick={() => setEdit(c)} disabled={unsupported} aria-label={t('connections.editNamed', { name: c.name })}>{t('connections.edit')}</Button>
                        <Button size="sm" onClick={() => { remove.reset(); setDel(c) }} aria-label={t('connections.deleteNamed', { name: c.name })}>{t('connections.delete')}</Button>
                      </div>
                    </div>
                    {unsupported ? <p className="text-[13px]">{t('connections.unsupportedBody')}</p> : null}
                    {result?.id === c.id ? (result.ok ? <p role="status" className="text-sm"><Chip tone="ok">{t('connections.testOk')}</Chip> {result.ok}</p> : <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{result.error}</p>) : null}
                    <div>
                      <h3 className="mb-1 text-[13px] font-medium">{t('connections.allowTitle')}</h3>
                      <ul aria-label={t('connections.allowFor', { name: c.name })} className="flex flex-wrap gap-1.5">{c.allow.map((a) => <li key={a}><code className="rounded-[4px] border border-rule bg-sunken px-1.5 py-0.5 font-mono text-[12px]">{a}</code></li>)}</ul>
                    </div>
                    {!unsupported ? (
                      <div>
                        <h3 className="mb-1 text-[13px] font-medium">{t('connections.toolsTitle')}</h3>
                        <ul aria-label={t('connections.toolsFor', { name: c.name })} className="grid gap-1.5">
                          {c.tools.map((tl) => (
                            <li key={tl.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                              <Switch checked={tl.enabled} aria-label={t('connections.toolEnable', { tool: tl.name, name: c.name })} onCheckedChange={(enabled) => save.mutate({ id: c.id, ...asInput(c, { tools: c.tools.map((x) => ({ name: x.name, enabled: x.name === tl.name ? enabled : x.enabled })) }) }, { onError: fail })} />
                              <code className="font-mono text-[12.5px]">{tl.name}</code>
                              <Chip tone={tl.access === 'write' ? 'warn' : 'off'}>{t(`connections.access.${tl.access}`)}</Chip>
                              <span className="min-w-0 flex-1 basis-60 text-muted">{tl.description}</span>
                            </li>
                          ))}
                        </ul>
                        {c.tools.some((x) => x.access === 'write') ? <p className="mt-2 text-[13px] text-muted">{t('connections.writeOnlyApproved')}</p> : null}
                      </div>
                    ) : null}
                  </Panel>
                </li>
              )
            })}
          </ul>
        )}
      </QueryState>
      {edit ? <ConnDialog conn={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
      {del ? (
        <Dialog open onOpenChange={(o) => { if (!o) setDel(null) }}>
          <DialogContent title={t('connections.deleteTitle', { name: del.name })} description={t('connections.deleteBody')}>
            {remove.error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{errMsg(remove.error, t)}</p> : null}
            <DialogFooter>
              <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
              <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('connections.deleted')) } })}>{t('connections.delete')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

const TARGET_EXAMPLE: Record<ConnectorKind, string> = { http: 'https://192.168.10.1', ssh: '192.168.10.30:22', 'netconf-restconf': 'https://192.168.10.2', automation: 'https://automation.example.local', 'mcp-http': 'https://mcp.example.local/mcp', 'mcp-stdio': '' }
const ALLOW_EXAMPLE: Record<ConnectorKind, string> = { http: 'https://192.168.10.1/api/', ssh: 'uname -a\nss -tlnp', 'netconf-restconf': 'https://192.168.10.2/restconf/', automation: 'https://automation.example.local/api/', 'mcp-http': 'mcp.example.local', 'mcp-stdio': '' }
const defaultAuth = (k: ConnectorKind): (typeof AUTHS)[number] => (k === 'ssh' ? 'ssh-key' : k === 'http' ? 'none' : 'token')

function ConnDialog({ conn, onClose }: { conn: Connector | null; onClose: () => void }) {
  const { t } = useTranslation('core')
  const save = useSaveConnection()
  const [name, setName] = useState(conn?.name ?? '')
  const [kind, setKind] = useState<ConnectorKind>(conn?.kind ?? 'http')
  const [target, setTarget] = useState(conn?.target ?? TARGET_EXAMPLE.http)
  const [auth, setAuth] = useState<(typeof AUTHS)[number]>(conn?.auth.type ?? 'token')
  const [username, setUsername] = useState(conn?.username ?? '')
  const [secret, setSecret] = useState('')
  const [allow, setAllow] = useState((conn?.allow ?? []).join('\n'))
  const [enabled, setEnabled] = useState(conn?.enabled ?? true)
  const [forget, setForget] = useState(false)
  const [errs, setErrs] = useState<Partial<Record<'name' | 'target' | 'username' | 'secret' | 'allow', string>>>({})
  const keep = !!conn?.auth.last4 && conn.auth.type === auth && conn.kind === kind
  const pin = conn && conn.kind === kind && conn.auth.type === auth && conn.target === target.trim() ? conn.pin : null
  const clear = (k: keyof typeof errs) => setErrs((e) => ({ ...e, [k]: undefined }))
  // A kind changes what the address, the sign-in and the allow-list mean, so nothing typed for the old kind is carried over.
  // Going back to the saved kind of an existing connection restores its saved values.
  function pickKind(k: ConnectorKind) {
    setKind(k); setErrs({}); setSecret(''); setForget(false)
    if (conn && k === conn.kind) { setTarget(conn.target); setAuth(conn.auth.type); setUsername(conn.username ?? ''); setAllow(conn.allow.join('\n')); return }
    setTarget(TARGET_EXAMPLE[k]); setAllow(''); setUsername(''); setAuth(defaultAuth(k))
  }
  const needsUser = usesUsername(kind, auth)
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const n: typeof errs = {}
    if (!name.trim()) n.name = t('connections.errName')
    if (!target.trim()) n.target = t('connections.errTarget')
    if (needsUser && !username.trim()) n.username = t('connections.errUsername')
    if (auth !== 'none' && !secret && !keep) n.secret = t('connections.errSecret')
    const list = allow.split('\n').map((x) => x.trim()).filter(Boolean)
    if (list.length === 0) n.allow = t('connections.errAllow')
    setErrs(n)
    if (Object.keys(n).length) return
    save.mutate({ id: conn?.id, name: name.trim(), kind, target: target.trim(), asset_id: conn?.asset_id ?? null, auth_type: auth, username: needsUser ? username.trim() : null, secret: secret || undefined, clear_pin: forget && !!pin ? true : undefined, allow: list, enabled, tools: conn?.tools.map((x) => ({ name: x.name, enabled: x.enabled })) }, { onSuccess: () => { toast.success(conn ? t('connections.saved') : t('connections.added')); onClose() } })
  }
  const srv = (k: keyof typeof errs) => errs[k]
  const title = conn ? t('connections.editTitle', { name: conn.name }) : t('connections.addTitle')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={title} description={t('connections.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={title}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('connections.f.name')} htmlFor="cn-name" error={srv('name')}><Input id="cn-name" value={name} maxLength={40} autoComplete="off" onChange={(e) => { setName(e.target.value); clear('name') }} aria-invalid={srv('name') ? true : undefined} aria-describedby={srv('name') ? 'cn-name-error' : undefined} /></Field>
            <Field label={t('connections.f.kind')} htmlFor="cn-kind"><Select id="cn-kind" value={kind} onChange={(e) => pickKind(e.target.value as ConnectorKind)}>{KINDS.map((k) => <option key={k} value={k} disabled={k === 'mcp-stdio'}>{t(`connections.kind.${k}`)}{k === 'mcp-stdio' ? ` (${t('connections.f.kindNo')})` : ''}</option>)}</Select></Field>
            <Field label={t(`connections.f.target_${kind}`)} htmlFor="cn-target" hint={t('connections.f.targetExample', { example: TARGET_EXAMPLE[kind] })} error={srv('target')} className="sm:col-span-2"><Input id="cn-target" value={target} autoComplete="off" onChange={(e) => { setTarget(e.target.value); clear('target') }} aria-invalid={srv('target') ? true : undefined} aria-describedby={srv('target') ? 'cn-target-error' : 'cn-target-hint'} /></Field>
            <Field label={t('connections.f.auth')} htmlFor="cn-auth"><Select id="cn-auth" value={auth} onChange={(e) => { setAuth(e.target.value as (typeof AUTHS)[number]); clear('secret'); clear('username') }}>{AUTHS.map((a) => { const no = !CONNECTOR_AUTH[kind].includes(a); return <option key={a} value={a} disabled={no}>{t(`connections.auth.${a}`)}{no ? ` (${t('connections.authNo')})` : ''}</option> })}</Select></Field>
            {needsUser ? <Field label={t('connections.f.username')} htmlFor="cn-username" hint={t(kind === 'ssh' ? 'connections.f.usernameHintSsh' : 'connections.f.usernameHintBasic')} error={srv('username')}><Input id="cn-username" value={username} maxLength={64} autoComplete="off" spellCheck={false} onChange={(e) => { setUsername(e.target.value); clear('username') }} aria-invalid={srv('username') ? true : undefined} aria-describedby={srv('username') ? 'cn-username-error' : 'cn-username-hint'} /></Field> : null}
            {auth !== 'none' ? <Field label={t('connections.f.secret')} htmlFor="cn-secret" error={srv('secret')} hint={keep ? t('connections.f.secretSaved', { last4: conn!.auth.last4 }) : t('connections.f.secretHint')}><Input id="cn-secret" type="password" autoComplete="off" value={secret} placeholder={keep ? `••••${conn!.auth.last4}` : ''} onChange={(e) => { setSecret(e.target.value); clear('secret') }} aria-invalid={srv('secret') ? true : undefined} aria-describedby={srv('secret') ? 'cn-secret-error' : 'cn-secret-hint'} /></Field> : null}
            <Field label={t('connections.f.allow')} htmlFor="cn-allow" hint={t(`connections.f.allowHint_${kind}`, { example: ALLOW_EXAMPLE[kind].includes('\n') ? ALLOW_EXAMPLE[kind].split('\n').map((x) => `"${x}"`).join(', ') : ALLOW_EXAMPLE[kind] })} error={srv('allow')} className="sm:col-span-2"><Textarea id="cn-allow" className="font-mono text-[13px]" value={allow} onChange={(e) => { setAllow(e.target.value); clear('allow') }} aria-invalid={srv('allow') ? true : undefined} aria-describedby={srv('allow') ? 'cn-allow-error' : 'cn-allow-hint'} /></Field>
          </div>
          {pin ? (
            <div className="grid gap-2 rounded-md border border-rule bg-sunken px-3 py-3 text-sm">
              <div role="group" aria-label={t('connections.f.pin')} className="grid gap-0.5">
                <span className="text-[13px] font-medium" aria-hidden>{t('connections.f.pin')}</span>
                <span className="text-[13px] text-muted">{pin.kind === 'ssh_hostkey' ? t('connections.f.pinSsh') : t('connections.f.pinTls')}</span>
                <code className="break-all font-mono text-[12px]">{pin.value}</code>
                <span className="text-[13px] text-muted">{t('connections.f.pinSeen', { when: fmtRelative(pin.first_seen) })}</span>
              </div>
              <div className="flex items-center gap-3"><Switch id="cn-forget" checked={forget} onCheckedChange={setForget} aria-describedby="cn-forget-hint" /><Label htmlFor="cn-forget" className="font-normal">{t('connections.f.forget')}</Label></div>
              <p id="cn-forget-hint" className="text-[13px] text-muted">{t('connections.f.forgetHint')}</p>
            </div>
          ) : conn ? <p className="text-[13px] text-muted">{t('connections.f.pinNone')}</p> : null}
          <div className="flex items-center gap-3"><Switch id="cn-enabled" checked={enabled} onCheckedChange={setEnabled} /><Label htmlFor="cn-enabled" className="font-normal">{t('connections.enabled')}</Label></div>
          <p className="text-[13px] text-muted">{t('connections.writeNote')}</p>
          {save.error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{errMsg(save.error, t)}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? t('connections.saving') : conn ? t('common:save') : t('connections.addConfirm')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
