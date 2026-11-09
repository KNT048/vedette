import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { Panel } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { errText, useCatalog, useDeleteAction, useSaveAction } from './api'
import { RiskChip } from './parts'
import { EMPTY_TPL, isMcp, KIND_FIELDS, kindProblem, tplEmpty, validateTpl, vendorExample, type ConnKind, type Tpl, type TplField } from './logic'
import type { Catalog, CatalogAction, CatalogInput, Connection, Risk } from './types'

const METHODS: Tpl['method'][] = ['', 'GET', 'PUT', 'POST', 'DELETE']
const PACKS = ['box', 'fortigate', 'mikrotik', 'pfsense', 'opnsense', 'switch', 'dns', 'generic'] as const

/** Connections that can carry actions come first; a read-only one is shown but cannot be chosen. */
export function ConnectionOptions({ connections }: { connections: Connection[] }) {
  const { t } = useTranslation('response')
  return <>{connections.map((c) => <option key={c.id} value={c.id} disabled={c.read_only}>{c.name}{c.read_only ? ` (${t('catalog.readOnly')})` : c.enabled ? '' : ` (${t('rules.disabled')})`}</option>)}</>
}

/** MCP arguments as name/value rows; the stored form is the JSON body. */
function ArgRows({ id, body, onChange }: { id: string; body: string; onChange: (body: string) => void }) {
  const { t } = useTranslation('response')
  const parse = () => { try { const o = JSON.parse(body || '{}') as Record<string, unknown>; return Object.entries(o).map(([k, v]) => ({ k, v: String(v) })) } catch { return [] } }
  const [rows, setRows] = useState<{ k: string; v: string }[]>(parse)
  const set = (r: { k: string; v: string }[]) => { setRows(r); onChange(r.some((x) => x.k.trim()) ? JSON.stringify(Object.fromEntries(r.filter((x) => x.k.trim()).map((x) => [x.k.trim(), x.v]))) : '') }
  return (
    <div className="grid gap-2">
      {rows.map((r, i) => (
        <div key={i} className="grid gap-2 sm:grid-cols-2">
          <Input aria-label={t('catalog.argName')} id={`${id}-k${i}`} value={r.k} spellCheck={false} onChange={(e) => set(rows.map((x, j) => (j === i ? { ...x, k: e.target.value } : x)))} placeholder="address" />
          <div className="flex gap-2"><Input aria-label={t('catalog.argValue')} value={r.v} spellCheck={false} onChange={(e) => set(rows.map((x, j) => (j === i ? { ...x, v: e.target.value } : x)))} placeholder="{ip}" /><Button size="icon" variant="ghost" aria-label={t('catalog.argRemove')} onClick={() => set(rows.filter((_, j) => j !== i))}><Trash2 className="size-4" aria-hidden /></Button></div>
        </div>
      ))}
      <div><Button size="sm" onClick={() => set([...rows, { k: '', v: '' }])}><Plus className="size-4" aria-hidden />{t('catalog.argAdd')}</Button></div>
    </div>
  )
}

/** Only the fields of the connection kind. Nothing else is rendered, so nothing from another kind can leak in. */
function TplFields({ id, legend, kind, value, onChange, tools, tool, onTool, hint }: { id: string; legend: string; kind: ConnKind; value: Tpl; onChange: (t: Tpl) => void; tools: string[]; tool: string | null; onTool: (v: string | null) => void; hint?: string }) {
  const { t } = useTranslation('response')
  const has = (f: TplField) => KIND_FIELDS[kind].includes(f)
  return (
    <fieldset className="grid gap-3 rounded-md border border-rule p-3">
      <legend className="px-1 text-sm font-medium">{legend}</legend>
      {isMcp(kind) ? (
        <>
          <Field htmlFor={`${id}-tool`} label={t('catalog.tool')}>
            <Select id={`${id}-tool`} value={tool ?? ''} onChange={(e) => onTool(e.target.value || null)}><option value="">{t('catalog.pickTool')}</option>{tools.map((x) => <option key={x} value={x}>{x}</option>)}</Select>
          </Field>
          <div className="grid gap-1.5"><span className="text-sm font-medium">{t('catalog.args')}</span><ArgRows id={id} body={value.body} onChange={(body) => onChange({ ...value, body })} /></div>
        </>
      ) : null}
      {has('cli') ? <Field htmlFor={`${id}-cli`} label={t('catalog.command')} hint={hint}><Textarea id={`${id}-cli`} className="min-h-20" spellCheck={false} value={value.cli} onChange={(e) => onChange({ ...value, cli: e.target.value })} /></Field> : null}
      {has('method') ? (
        <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
          <Field htmlFor={`${id}-method`} label={t('catalog.method')}><Select id={`${id}-method`} value={value.method} onChange={(e) => onChange({ ...value, method: e.target.value as Tpl['method'] })}>{METHODS.map((m) => <option key={m} value={m}>{m || t('catalog.chooseMethod')}</option>)}</Select></Field>
          <Field htmlFor={`${id}-path`} label={t('catalog.path')} hint={t('catalog.pathHint')}><Input id={`${id}-path`} spellCheck={false} value={value.path} placeholder="/api/..." onChange={(e) => onChange({ ...value, path: e.target.value })} /></Field>
        </div>
      ) : null}
      {has('headers') ? <Field htmlFor={`${id}-headers`} label={t('catalog.headers')} hint={t('catalog.headersHint')}><Textarea id={`${id}-headers`} className="min-h-16" spellCheck={false} value={value.headers} onChange={(e) => onChange({ ...value, headers: e.target.value })} /></Field> : null}
      {has('body') && !isMcp(kind) ? <Field htmlFor={`${id}-body`} label={t('catalog.body')}><Input id={`${id}-body`} spellCheck={false} value={value.body} placeholder='{"name":"{text}"}' onChange={(e) => onChange({ ...value, body: e.target.value })} /></Field> : null}
    </fieldset>
  )
}

/** Add or edit a custom action. The form follows the kind of the chosen connection (API, SSH, MCP); switching the connection clears what does not apply. */
export function ActionDialog({ action, cat, onClose, onSaved }: { action: CatalogAction | null; cat: Catalog; onClose: () => void; onSaved?: (a: CatalogAction) => void }) {
  const { t } = useTranslation('response')
  const save = useSaveAction()
  const usable = cat.connections.filter((c) => !c.read_only)
  const start = (c: Connection | undefined): Pick<CatalogInput, 'connection_id' | 'tool' | 'rollback_tool' | 'run' | 'rollback' | 'verify'> => {
    const ex = vendorExample(c?.kind ?? null, c?.vendor ?? null) // prefill only from this connection's vendor
    return { connection_id: c?.id ?? '', tool: null, rollback_tool: null, run: { ...EMPTY_TPL, ...ex.run }, rollback: { ...EMPTY_TPL, ...ex.rollback }, verify: EMPTY_TPL }
  }
  const [f, setF] = useState<CatalogInput>(action
    ? { name: action.name, description: action.description, connection_id: action.connection_id ?? '', tool: action.tool, rollback_tool: action.rollback_tool, run: action.run, rollback: action.rollback, verify: action.verify, risk: action.risk, enabled: action.enabled, ai_may_propose: action.ai_may_propose }
    : { name: '', description: '', risk: 'medium', enabled: false, ai_may_propose: false, ...start(usable.find((c) => c.enabled) ?? usable[0]) })
  const [error, setError] = useState<string | undefined>()
  const conn = cat.connections.find((c) => c.id === f.connection_id)
  const kind = conn?.kind as ConnKind | undefined
  const set = (p: Partial<CatalogInput>) => { setF({ ...f, ...p }); setError(undefined) }
  const ex = vendorExample(kind ?? null, conn?.vendor ?? null)
  const submit = () => {
    if (!conn || !kind) { setError(t('catalog.noWritable')); return }
    const bad = (['run', 'rollback'] as const).map((k) => kindProblem(kind, f[k], t(k === 'run' ? 'catalog.runLegend' : 'catalog.rollbackLegend')) ?? (isMcp(kind) ? null : validateTpl(f[k], t(k === 'run' ? 'catalog.runLegend' : 'catalog.rollbackLegend')))).find(Boolean)
      ?? (!isMcp(kind) && !tplEmpty(f.verify) ? validateTpl(f.verify, t('catalog.verifyLegend')) : null)
    if (bad) { setError(bad); return }
    save.mutate({ id: action?.id, input: { ...f, tool: isMcp(kind) ? f.tool : null, rollback_tool: isMcp(kind) ? f.rollback_tool : null, verify: isMcp(kind) ? EMPTY_TPL : f.verify } }, { onSuccess: (a) => { toast.success(t('common:saved')); onSaved?.(a); onClose() }, onError: (er) => setError(errText(er)) })
  }
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={action ? t('catalog.editTitle') : t('catalog.addTitle')} description={t('catalog.dialogHint')} wide>
        <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); submit() }}>
          <Field htmlFor="ca-name" label={t('catalog.name')}><Input id="ca-name" value={f.name} maxLength={80} onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field htmlFor="ca-desc" label={t('catalog.description')} hint={t('catalog.descriptionHint')}><Textarea id="ca-desc" className="min-h-16" maxLength={300} value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field htmlFor="ca-conn" label={t('catalog.connection')} hint={usable.length ? t(`catalog.kinds.${kind ?? 'none'}`) : t('catalog.noWritable')}>
              <Select id="ca-conn" value={f.connection_id} onChange={(e) => { const c = cat.connections.find((x) => x.id === e.target.value); setF({ ...f, ...start(c) }); setError(undefined) }}>
                {!conn ? <option value="">{t('catalog.chooseConnection')}</option> : null}
                <ConnectionOptions connections={cat.connections} />
              </Select>
            </Field>
            <Field htmlFor="ca-risk" label={t('catalog.risk')}><Select id="ca-risk" value={f.risk} onChange={(e) => set({ risk: e.target.value as Risk })}>{(['low', 'medium', 'high'] as Risk[]).map((r) => <option key={r} value={r}>{t(`catalog.risks.${r}`)}</option>)}</Select></Field>
          </div>
          {kind ? (
            <>
              <p className="text-[13px] text-muted">{t('catalog.placeholders')}</p>
              {ex.hint ? <p className="rounded-md border border-dashed border-rule px-3 py-2 text-[13px] text-muted">{ex.hint}</p> : null}
              <TplFields key={`run-${f.connection_id}`} id="ca-run" legend={t('catalog.runLegend')} kind={kind} value={f.run} onChange={(run) => set({ run })} tools={conn?.write_tools ?? []} tool={f.tool} onTool={(tool) => set({ tool })} />
              <TplFields key={`rb-${f.connection_id}`} id="ca-rb" legend={t('catalog.rollbackLegend')} kind={kind} value={f.rollback} onChange={(rollback) => set({ rollback })} tools={conn?.write_tools ?? []} tool={f.rollback_tool} onTool={(rollback_tool) => set({ rollback_tool })} />
              {!isMcp(kind) ? <TplFields key={`vf-${f.connection_id}`} id="ca-vf" legend={t('catalog.verifyLegend')} kind={kind} value={f.verify} onChange={(verify) => set({ verify })} tools={[]} tool={null} onTool={() => undefined} hint={t('catalog.verifyHint')} /> : null}
            </>
          ) : null}
          <div className="flex items-center gap-2.5">
            <Switch id="ca-ai" checked={f.ai_may_propose} onCheckedChange={(v) => set({ ai_may_propose: v })} />
            <label htmlFor="ca-ai" className="grid text-sm"><span className="font-medium">{t('catalog.aiMay')}</span><span className="text-[13px] text-muted">{t('catalog.aiMayHint')}</span></label>
          </div>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
          <DialogFooter>
            <Button type="button" onClick={onClose}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" disabled={save.isPending || !conn}>{t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Settings, AI response: the action catalog by vendor pack. An action is allowed when it is enabled. */
export function CatalogEditor() {
  const { t } = useTranslation('response')
  const q = useCatalog()
  const save = useSaveAction()
  const del = useDeleteAction()
  const [edit, setEdit] = useState<CatalogAction | 'new' | null>(null)
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const cat = q.data
  const fail = (e: unknown) => toast.error(errText(e))
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div><h3 className="text-sm font-medium">{t('catalog.title')}</h3><p className="text-[13px] text-muted">{t('catalog.hint')}</p></div>
        <Button onClick={() => setEdit('new')}><Plus className="size-4" aria-hidden />{t('catalog.add')}</Button>
      </div>
      {PACKS.map((pack) => {
        const items = cat.items.filter((a) => a.pack === pack)
        if (!items.length) return null
        return (
          <section key={pack} className="grid gap-2" aria-label={t(`catalog.packs.${pack}`)}>
            <h4 className="mt-2 text-[13px] font-medium text-muted">{t(`catalog.packs.${pack}`)}</h4>
            {items.map((a) => (
              <Panel key={a.id} className="grid gap-2 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-3">
                    <Switch aria-label={t('catalog.allow', { name: a.name })} checked={a.enabled} disabled={save.isPending} onCheckedChange={(v) => save.mutate({ id: a.id, input: { enabled: v } }, { onError: fail })} />
                    <span className="text-sm font-medium">{a.name}</span>
                    <RiskChip risk={a.risk} />
                    {a.builtin ? <Chip tone="off">{t('catalog.builtin')}</Chip> : <Chip tone="accent">{t('catalog.custom')}</Chip>}
                    {!a.reversible ? <Chip tone="off">{t('catalog.noUndo')}</Chip> : null}
                  </div>
                  {!a.builtin ? (
                    <div className="flex gap-1">
                      <Button size="sm" variant="ghost" aria-label={t('catalog.edit', { name: a.name })} onClick={() => setEdit(a)}><Pencil className="size-4" aria-hidden />{t('common:edit')}</Button>
                      <Button size="sm" variant="ghost" aria-label={t('catalog.delete', { name: a.name })} disabled={del.isPending} onClick={() => del.mutate(a.id, { onSuccess: () => toast.success(t('catalog.deleted')), onError: fail })}><Trash2 className="size-4" aria-hidden />{t('common:delete')}</Button>
                    </div>
                  ) : null}
                </div>
                <p className="text-[13px] text-muted">{a.description}</p>
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px]">
                  <div className="flex items-center gap-2">
                    <Switch id={`ai-${a.id}`} aria-label={t('catalog.aiMayFor', { name: a.name })} checked={a.ai_may_propose} disabled={save.isPending} onCheckedChange={(v) => save.mutate({ id: a.id, input: { ai_may_propose: v } }, { onError: fail })} />
                    <label htmlFor={`ai-${a.id}`} className="text-muted">{t('catalog.aiMay')}</label>
                  </div>
                  {a.device ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <label htmlFor={`cc-${a.id}`} className="text-muted">{t('catalog.connection')}:</label>
                      {a.builtin ? <Select id={`cc-${a.id}`} className="h-8 w-auto" value={a.connection_id ?? ''} onChange={(e) => save.mutate({ id: a.id, input: { connection_id: e.target.value } }, { onError: fail })}>{a.connection_id ? null : <option value="">{t('catalog.chooseConnection')}</option>}<ConnectionOptions connections={cat.connections} /></Select> : <span>{a.connection}</span>}
                      {!a.available ? <span className="text-warn">{a.unavailable_reason} <Link className="text-accent underline underline-offset-4" to="/settings/ai">{t('plans.toAi')}</Link></span> : null}
                    </div>
                  ) : <span className="text-muted">{t('catalog.boxOnly')}</span>}
                </div>
              </Panel>
            ))}
          </section>
        )
      })}
      {edit ? <ActionDialog key={edit === 'new' ? 'new' : edit.id} action={edit === 'new' ? null : edit} cat={cat} onClose={() => setEdit(null)} /> : null}
    </div>
  )
}
