import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useConnections, useRemoveConnection, useSaveConnection, useTestConnection } from '../harness-api'
import { ActionError } from '../parts'
import type { Connector, ConnectorInput, ConnectorKind } from '../types'
import { ConfirmDelete } from './shared'

const KINDS: ConnectorKind[] = ['device-api', 'ssh', 'http', 'mcp-http', 'mcp-stdio']
const VENDORS = ['fortinet', 'mikrotik', 'pfsense', 'other'] as const
const AUTHS = ['none', 'token', 'basic', 'ssh-key'] as const
const asInput = (c: Connector, over: Partial<ConnectorInput> = {}): ConnectorInput => ({ name: c.name, kind: c.kind, vendor: c.vendor, target: c.target, asset_id: c.asset_id, auth_type: c.auth.type, allow: c.allow, enabled: c.enabled, ...over })

/** Kết nối ra ngoài cho AI (D-39): API thiết bị, SSH, HTTP, máy chủ MCP. Công cụ ghi chỉ chạy qua hành động được duyệt (D-41). */
export default function ConnectionsTab() {
  const { t } = useTranslation('ai')
  const conns = useConnections()
  const save = useSaveConnection()
  const remove = useRemoveConnection()
  const test = useTestConnection()
  const [edit, setEdit] = useState<Connector | 'new' | null>(null)
  const [del, setDel] = useState<Connector | null>(null)
  const [result, setResult] = useState<{ id: string; ok?: string; error?: string } | null>(null)
  const fail = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  function runTest(c: Connector) {
    setResult(null)
    test.mutate(c.id, { onSuccess: (r) => setResult({ id: c.id, ok: r.message }), onError: (e) => setResult({ id: c.id, error: e instanceof Error ? e.message : String(e) }) })
  }
  return (
    <>
      <Section title={t('harness.conn.title')} description={t('harness.conn.body')} stories={['S-AI-7']} actions={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.conn.add')}</Button>}>
        <Panel className="mb-4 p-4 text-sm" ><p><strong>{t('harness.conn.writeNoteLead')}</strong> {t('harness.conn.writeNote')}</p></Panel>
        <QueryState query={conns}>
          {({ items }) => items.length === 0 ? (
            <EmptyState title={t('harness.conn.empty')} action={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.conn.add')}</Button>}>{t('harness.conn.emptyBody')}</EmptyState>
          ) : (
            <ul aria-label={t('harness.conn.title')} className="grid gap-4">
              {items.map((c) => (
                <li key={c.id}>
                  <Panel className={`grid gap-3 p-4 ${c.enabled ? '' : 'opacity-70'}`}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="grid gap-1">
                        <h3 className="flex flex-wrap items-center gap-2 text-sm font-semibold">{c.name} <Chip tone="off">{t(`harness.conn.kind.${c.kind}`)}</Chip>
                          <Chip tone={c.status === 'ok' ? 'ok' : c.status === 'error' ? 'danger' : 'warn'}>{t(`harness.conn.status.${c.status}`)}</Chip></h3>
                        <p className="font-mono text-[12.5px] text-muted">{c.target}</p>
                        <p className="text-[13px] text-muted">{c.auth.type === 'none' ? t('harness.conn.noAuth') : t('harness.conn.authEnds', { type: t(`harness.conn.auth.${c.auth.type}`), last4: c.auth.last4 })}{c.last_test ? ` · ${t('harness.conn.tested', { when: fmtRelative(c.last_test) })}` : ` · ${t('harness.conn.neverTested')}`}</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Switch checked={c.enabled} aria-label={t('harness.conn.enable', { name: c.name })} onCheckedChange={(enabled) => save.mutate({ id: c.id, ...asInput(c, { enabled }) }, { onError: fail })} />
                        <Button size="sm" onClick={() => runTest(c)} disabled={test.isPending} aria-label={t('harness.conn.testNamed', { name: c.name })}>{test.isPending && test.variables === c.id ? t('harness.conn.testing') : t('harness.conn.test')}</Button>
                        <Button size="sm" onClick={() => setEdit(c)} aria-label={t('harness.editNamed', { name: c.name })}>{t('harness.edit')}</Button>
                        <Button size="sm" onClick={() => setDel(c)} aria-label={t('harness.deleteNamed', { name: c.name })}>{t('harness.delete')}</Button>
                      </div>
                    </div>
                    {result?.id === c.id ? (result.ok ? <p role="status" className="text-sm"><Chip tone="ok">{t('harness.conn.testOk')}</Chip> {result.ok}</p> : <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{result.error}</p>) : null}
                    <div>
                      <p className="mb-1 text-[13px] font-medium">{t('harness.conn.allowTitle')}</p>
                      <ul aria-label={t('harness.conn.allowFor', { name: c.name })} className="flex flex-wrap gap-1.5">{c.allow.map((a) => <li key={a}><code className="rounded-[4px] border border-rule bg-sunken px-1.5 py-0.5 font-mono text-[12px]">{a}</code></li>)}</ul>
                    </div>
                    <div>
                      <p className="mb-1 text-[13px] font-medium">{t('harness.conn.toolsTitle')}</p>
                      <ul aria-label={t('harness.conn.toolsFor', { name: c.name })} className="grid gap-1.5">
                        {c.tools.map((tl) => (
                          <li key={tl.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                            <Switch checked={tl.enabled} aria-label={t('harness.conn.toolEnable', { tool: tl.name, name: c.name })} onCheckedChange={(enabled) => save.mutate({ id: c.id, ...asInput(c, { tools: c.tools.map((x) => ({ name: x.name, enabled: x.name === tl.name ? enabled : x.enabled })) }) }, { onError: fail })} />
                            <code className="font-mono text-[12.5px]">{tl.name}</code>
                            <Chip tone={tl.access === 'write' ? 'warn' : 'off'}>{t(`harness.conn.access.${tl.access}`)}</Chip>
                            <span className="min-w-0 flex-1 basis-60 text-muted">{tl.description}</span>
                          </li>
                        ))}
                      </ul>
                      {c.tools.some((x) => x.access === 'write') ? <p className="mt-2 text-[13px] text-muted">{t('harness.conn.writeOnlyApproved')}</p> : null}
                    </div>
                  </Panel>
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      </Section>
      {edit ? <ConnDialog conn={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
      {del ? <ConfirmDelete title={t('harness.conn.deleteTitle', { name: del.name })} body={t('harness.conn.deleteBody')} pending={remove.isPending} error={remove.error} onClose={() => setDel(null)} onConfirm={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('harness.conn.deleted')) } })} /> : null}
    </>
  )
}

const TARGET_EXAMPLE: Record<ConnectorKind, string> = { 'device-api': 'https://192.168.10.1', ssh: '192.168.10.30:22', http: 'https://', 'mcp-http': 'https://mcp.example.local/mcp', 'mcp-stdio': 'npx some-mcp-server' }
const ALLOW_EXAMPLE: Record<ConnectorKind, string> = { 'device-api': 'https://192.168.10.1/api/v2/', ssh: 'uname -a\nss -tlnp', http: 'https://www.cisa.gov/', 'mcp-http': 'mcp.example.local', 'mcp-stdio': 'api.example.com' }

function ConnDialog({ conn, onClose }: { conn: Connector | null; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const save = useSaveConnection()
  const [name, setName] = useState(conn?.name ?? '')
  const [kind, setKind] = useState<ConnectorKind>(conn?.kind ?? 'device-api')
  const [vendor, setVendor] = useState<(typeof VENDORS)[number]>(conn?.vendor ?? 'fortinet')
  const [target, setTarget] = useState(conn?.target ?? TARGET_EXAMPLE['device-api'])
  const [auth, setAuth] = useState<(typeof AUTHS)[number]>(conn?.auth.type ?? 'token')
  const [secret, setSecret] = useState('')
  const [allow, setAllow] = useState((conn?.allow ?? []).join('\n'))
  const [enabled, setEnabled] = useState(conn?.enabled ?? true)
  const [errs, setErrs] = useState<Partial<Record<'name' | 'target' | 'secret' | 'allow', string>>>({})
  const keep = !!conn?.auth.last4 && conn.auth.type === auth
  const clear = (k: keyof typeof errs) => setErrs((e) => ({ ...e, [k]: undefined }))
  function pickKind(k: ConnectorKind) {
    setKind(k)
    if (!conn) { setTarget(TARGET_EXAMPLE[k]); setAuth(k === 'ssh' ? 'ssh-key' : k === 'http' ? 'none' : k === 'mcp-stdio' ? 'none' : 'token') }
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const n: typeof errs = {}
    if (!name.trim()) n.name = t('harness.conn.errName')
    if (!target.trim()) n.target = t('harness.conn.errTarget')
    if (auth !== 'none' && !secret && !keep) n.secret = t('harness.conn.errSecret')
    const list = allow.split('\n').map((x) => x.trim()).filter(Boolean)
    if (list.length === 0) n.allow = t('harness.conn.errAllow')
    setErrs(n)
    if (Object.keys(n).length) return
    save.mutate({ id: conn?.id, name: name.trim(), kind, vendor: kind === 'device-api' ? vendor : null, target: target.trim(), asset_id: conn?.asset_id ?? null, auth_type: auth, secret: secret || undefined, allow: list, enabled, tools: conn?.tools.map((x) => ({ name: x.name, enabled: x.enabled })) }, { onSuccess: () => { toast.success(conn ? t('harness.conn.saved') : t('harness.conn.added')); onClose() } })
  }
  const srv = (k: 'name' | 'target' | 'secret' | 'allow') => errs[k]
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={conn ? t('harness.conn.editTitle', { name: conn.name }) : t('harness.conn.addTitle')} description={t('harness.conn.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={conn ? t('harness.conn.editTitle', { name: conn.name }) : t('harness.conn.addTitle')}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('harness.conn.f.name')} htmlFor="cn-name" error={srv('name')}><Input id="cn-name" value={name} maxLength={40} autoComplete="off" onChange={(e) => { setName(e.target.value); clear('name') }} aria-invalid={srv('name') ? true : undefined} aria-describedby={srv('name') ? 'cn-name-error' : undefined} /></Field>
            <Field label={t('harness.conn.f.kind')} htmlFor="cn-kind"><Select id="cn-kind" value={kind} onChange={(e) => pickKind(e.target.value as ConnectorKind)}>{KINDS.map((k) => <option key={k} value={k}>{t(`harness.conn.kind.${k}`)}</option>)}</Select></Field>
            {kind === 'device-api' ? <Field label={t('harness.conn.f.vendor')} htmlFor="cn-vendor" className="sm:col-span-2"><Select id="cn-vendor" value={vendor} onChange={(e) => setVendor(e.target.value as (typeof VENDORS)[number])}>{VENDORS.map((v) => <option key={v} value={v}>{t(`harness.conn.vendor.${v}`)}</option>)}</Select></Field> : null}
            <Field label={t(`harness.conn.f.target_${kind}`)} htmlFor="cn-target" hint={t('harness.conn.f.targetExample', { example: TARGET_EXAMPLE[kind] })} error={srv('target')} className="sm:col-span-2"><Input id="cn-target" value={target} autoComplete="off" onChange={(e) => { setTarget(e.target.value); clear('target') }} aria-invalid={srv('target') ? true : undefined} aria-describedby={srv('target') ? 'cn-target-error' : 'cn-target-hint'} /></Field>
            <Field label={t('harness.conn.f.auth')} htmlFor="cn-auth"><Select id="cn-auth" value={auth} onChange={(e) => { setAuth(e.target.value as (typeof AUTHS)[number]); clear('secret') }}>{AUTHS.map((a) => <option key={a} value={a}>{t(`harness.conn.auth.${a}`)}</option>)}</Select></Field>
            {auth !== 'none' ? <Field label={t('harness.conn.f.secret')} htmlFor="cn-secret" error={srv('secret')} hint={keep ? t('harness.conn.f.secretSaved', { last4: conn!.auth.last4 }) : t('harness.conn.f.secretHint')}><Input id="cn-secret" type="password" autoComplete="off" value={secret} placeholder={keep ? `••••${conn!.auth.last4}` : ''} onChange={(e) => { setSecret(e.target.value); clear('secret') }} aria-invalid={srv('secret') ? true : undefined} aria-describedby={srv('secret') ? 'cn-secret-error' : 'cn-secret-hint'} /></Field> : <span />}
            <Field label={t('harness.conn.f.allow')} htmlFor="cn-allow" hint={t(`harness.conn.f.allowHint_${kind}`, { example: ALLOW_EXAMPLE[kind] })} error={srv('allow')} className="sm:col-span-2"><Textarea id="cn-allow" className="font-mono text-[13px]" value={allow} onChange={(e) => { setAllow(e.target.value); clear('allow') }} aria-invalid={srv('allow') ? true : undefined} aria-describedby={srv('allow') ? 'cn-allow-error' : 'cn-allow-hint'} /></Field>
          </div>
          <div className="flex items-center gap-3"><Switch id="cn-enabled" checked={enabled} onCheckedChange={setEnabled} /><Label htmlFor="cn-enabled" className="font-normal">{t('harness.enabled')}</Label></div>
          <p className="text-[13px] text-muted">{t('harness.conn.writeNote')}</p>
          <ActionError error={save.error} />
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? t('harness.saving') : conn ? t('common:save') : t('harness.conn.addConfirm')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
