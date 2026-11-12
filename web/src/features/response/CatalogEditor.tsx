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
import { EMPTY_TPL, isMcp, KIND_FIELDS, kindHint, kindProblem, MAX_EXPECT, MAX_REFUSE, MAX_REFUSE_LEN, needsPrecheck, readBackProblem, cliProblem, TEXT_RE, tplEmpty, validatePrecheck, validateTpl, type ConnKind, type Tpl, type TplField } from './logic'
import { CLI_BAN } from './templates'
import type { Catalog, CatalogAction, CatalogInput, Connection, Risk } from './types'

const METHODS: Tpl['method'][] = ['', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE']
/** Packs come from the template library (data): box first, then the library's packs in their order, generic last. */
const packsOf = (items: CatalogAction[]) => { const named = [...new Set(items.map((a) => a.pack))].filter((p) => p !== 'box' && p !== 'generic'); return [...(items.some((a) => a.pack === 'box') ? ['box'] : []), ...named, ...(items.some((a) => a.pack === 'generic') ? ['generic'] : [])] }

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

/** The refusal texts, one per line. The text box keeps what is typed (a new empty line while typing); the form gets the non-empty lines. */
function RefuseText({ id, value, onChange }: { id: string; value: string[]; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(value.join('\n'))
  return <Textarea id={id} className="min-h-16" spellCheck={false} value={text} onChange={(e) => { setText(e.target.value); onChange(e.target.value.split('\n').filter((x) => x !== '')) }} />
}

/** Only the fields of the connection kind. Nothing else is rendered, so nothing from another kind can leak in. */
function TplFields({ id, legend, kind, value, onChange, tools, tool, onTool, hint, readOnly, expect, error, children }: { id: string; legend: string; kind: ConnKind; value: Tpl; onChange: (t: Tpl) => void; tools: string[]; tool: string | null; onTool: (v: string | null) => void; hint?: string; readOnly?: boolean; expect?: boolean; error?: string; children?: React.ReactNode }) {
  const { t } = useTranslation('response')
  const has = (f: TplField) => KIND_FIELDS[kind].includes(f)
  const bad = error ? { 'aria-invalid': true, 'aria-describedby': `${id}-error` } : {} // the error of the group is under it (D-390)
  return (
    <fieldset id={id} tabIndex={-1} className="grid gap-3 rounded-md border border-rule p-3">
      <legend className="px-1 text-sm font-medium">{legend}</legend>
      {isMcp(kind) ? (
        <>
          <Field htmlFor={`${id}-tool`} label={t('catalog.tool')}>
            <Select id={`${id}-tool`} {...bad} value={tool ?? ''} onChange={(e) => onTool(e.target.value || null)}><option value="">{t('catalog.pickTool')}</option>{tools.map((x) => <option key={x} value={x}>{x}</option>)}</Select>
          </Field>
          <div className="grid gap-1.5"><span className="text-sm font-medium">{t('catalog.args')}</span><ArgRows id={id} body={value.body} onChange={(body) => onChange({ ...value, body })} /></div>
        </>
      ) : null}
      {has('cli') ? <Field htmlFor={`${id}-cli`} label={t('catalog.command')} hint={hint}><Textarea id={`${id}-cli`} {...bad} className="min-h-20" spellCheck={false} value={value.cli} onChange={(e) => onChange({ ...value, cli: e.target.value })} /></Field> : null}
      {has('method') ? (
        <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
          <Field htmlFor={`${id}-method`} label={t('catalog.method')}><Select id={`${id}-method`} value={value.method} onChange={(e) => onChange({ ...value, method: e.target.value as Tpl['method'] })}>{METHODS.filter((m) => !readOnly || m === '' || m === 'GET').map((m) => <option key={m} value={m}>{m || t('catalog.chooseMethod')}</option>)}</Select></Field>
          <Field htmlFor={`${id}-path`} label={t('catalog.path')} hint={t('catalog.pathHint')}><Input id={`${id}-path`} {...bad} spellCheck={false} value={value.path} placeholder="/api/..." onChange={(e) => onChange({ ...value, path: e.target.value })} /></Field>
        </div>
      ) : null}
      {has('headers') ? <Field htmlFor={`${id}-headers`} label={t('catalog.headers')} hint={t('catalog.headersHint')}><Textarea id={`${id}-headers`} className="min-h-16" spellCheck={false} value={value.headers} onChange={(e) => onChange({ ...value, headers: e.target.value })} /></Field> : null}
      {has('body') && !isMcp(kind) && !readOnly ? <Field htmlFor={`${id}-body`} label={t('catalog.body')}><Input id={`${id}-body`} spellCheck={false} value={value.body} placeholder='{"name":"{text}"}' onChange={(e) => onChange({ ...value, body: e.target.value })} /></Field> : null}
      {expect ? <Field htmlFor={`${id}-expect`} label={t('catalog.expect')} hint={t('catalog.expectHint')}><Input id={`${id}-expect`} spellCheck={false} maxLength={MAX_EXPECT} value={value.expect ?? ''} onChange={(e) => onChange({ ...value, expect: e.target.value })} /></Field> : null}
      {children}
      {error ? <p id={`${id}-error`} className="text-[13px] text-danger [overflow-wrap:anywhere]">{error}</p> : null}
    </fieldset>
  )
}

/** Add or edit a custom action. The form follows the kind of the chosen connection (API, SSH, MCP); switching the connection clears what does not apply. */
export function ActionDialog({ action, cat, onClose, onSaved }: { action: CatalogAction | null; cat: Catalog; onClose: () => void; onSaved?: (a: CatalogAction) => void }) {
  const { t } = useTranslation('response')
  const save = useSaveAction()
  const usable = cat.connections.filter((c) => !c.read_only)
  const start = (c: Connection | undefined): Pick<CatalogInput, 'connection_id' | 'tool' | 'rollback_tool' | 'run' | 'rollback' | 'verify' | 'precheck' | 'precheck_refuse' | 'precheck_expect'> => {
    const ex = kindHint(c?.kind ?? null)
    return { connection_id: c?.id ?? '', tool: null, rollback_tool: null, run: { ...EMPTY_TPL, ...ex.run }, rollback: { ...EMPTY_TPL, ...ex.rollback }, verify: EMPTY_TPL, precheck: EMPTY_TPL, precheck_refuse: [], precheck_expect: '' }
  }
  const [f, setF] = useState<CatalogInput>(action
    ? { name: action.name, description: action.description, connection_id: action.connection_id ?? '', tool: action.tool, rollback_tool: action.rollback_tool, run: action.run, rollback: action.rollback, verify: action.verify, precheck: action.precheck, precheck_refuse: action.precheck_refuse, precheck_expect: action.precheck_expect, risk: action.risk, enabled: action.enabled, ai_may_propose: action.ai_may_propose }
    : { name: '', description: '', risk: 'medium', enabled: false, ai_may_propose: false, ...start(usable.find((c) => c.enabled) ?? usable[0]) })
  const [error, setError] = useState<string | undefined>()
  const [errs, setErrs] = useState<Record<string, string>>({}) // by the id of the field or group they belong to (D-390)
  const conn = cat.connections.find((c) => c.id === f.connection_id)
  const kind = conn?.kind as ConnKind | undefined
  const set = (p: Partial<CatalogInput>) => { setF({ ...f, ...p }); setError(undefined); setErrs({}) }
  const focus = (id: string) => setTimeout(() => { const el = [`${id}-cli`, `${id}-path`, `${id}-tool`, id].map((x) => document.getElementById(x)).find(Boolean); el?.focus(); el?.scrollIntoView?.({ block: 'center' }) })
  /** Show errors under their field or group; a message that names none goes in the box above the buttons. */
  const show = (e: Record<string, string>, rest: string | null = null) => { setErrs(e); setError(rest ?? undefined); const first = Object.keys(e)[0]; if (first) focus(first) }
  /** A refusal of the box, placed by the part of the form its message starts with. */
  const place = (msg: string) => {
    const at = ([[/^Name:/, 'ca-name'], [/^Choose one of your connections/, 'ca-conn'], [/^(Action|Pick one of the write tools)/, 'ca-run'], [/^Rollback/, 'ca-rb'], [/^Read-back/, 'ca-vf'], [/^Check before/, 'ca-pc']] as const).find(([re]) => re.test(msg))?.[1]
    show(at ? { [at]: msg } : {}, at ? null : msg)
  }
  const ex = kindHint(kind ?? null)
  const submit = () => {
    if (!conn || !kind) { show({ 'ca-conn': t('catalog.noWritable') }); return }
    const pre = f.precheck ?? EMPTY_TPL, refuse = f.precheck_refuse ?? []
    const step = (k: 'run' | 'rollback') => { const what = t(k === 'run' ? 'catalog.runLegend' : 'catalog.rollbackLegend'); return kindProblem(kind, f[k], what) ?? (isMcp(kind) ? ((k === 'run' ? f.tool : f.rollback_tool) ? null : t('catalog.pickToolFirst')) : validateTpl(f[k], what)) }
    // every part of the form at once, each under its own field or group
    const e = Object.fromEntries(Object.entries({
      'ca-name': TEXT_RE.test(f.name) ? null : t('editor.nameBad'),
      'ca-run': step('run'),
      'ca-rb': step('rollback'),
      'ca-vf': isMcp(kind) || tplEmpty(f.verify) ? null : validateTpl(f.verify, t('catalog.verifyLegend')) ?? readBackProblem(f.verify),
      'ca-pc': validatePrecheck(pre, refuse, kind, f.precheck_expect ?? '') ?? (needsPrecheck(f.run, f.rollback, f.verify, pre, refuse, true) ? t('catalog.needsPrecheck') : null),
    }).filter((x): x is [string, string] => !!x[1]))
    const rest = (f.run.expect || f.rollback.expect || pre.expect ? t('catalog.expectOnlyReadBack') : null) ?? cliProblem(CLI_BAN, { run: f.run, rollback: f.rollback, verify: f.verify, pre }, true)
    if (Object.keys(e).length || rest) { show(e, rest); return }
    save.mutate({ id: action?.id, input: { ...f, tool: isMcp(kind) ? f.tool : null, rollback_tool: isMcp(kind) ? f.rollback_tool : null, verify: isMcp(kind) ? EMPTY_TPL : f.verify, precheck: isMcp(kind) ? EMPTY_TPL : pre, precheck_refuse: isMcp(kind) ? [] : refuse, precheck_expect: isMcp(kind) ? '' : f.precheck_expect ?? '' } }, { onSuccess: (a) => { toast.success(t('common:saved')); onSaved?.(a); onClose() }, onError: (er) => place(errText(er)) })
  }
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={action ? t('catalog.editTitle') : t('catalog.addTitle')} description={t('catalog.dialogHint')} wide>
        <form className="grid gap-4" noValidate onSubmit={(e) => { e.preventDefault(); submit() }}>
          <Field htmlFor="ca-name" label={t('catalog.name')} error={errs['ca-name']}><Input id="ca-name" {...(errs['ca-name'] ? { 'aria-invalid': true, 'aria-describedby': 'ca-name-error' } : {})} value={f.name} maxLength={80} onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field htmlFor="ca-desc" label={t('catalog.description')} hint={t('catalog.descriptionHint')}><Textarea id="ca-desc" className="min-h-16" maxLength={300} value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field htmlFor="ca-conn" label={t('catalog.connection')} hint={usable.length ? t(`catalog.kinds.${kind ?? 'none'}`) : t('catalog.noWritable')} error={errs['ca-conn']}>
              <Select id="ca-conn" value={f.connection_id} onChange={(e) => { const c = cat.connections.find((x) => x.id === e.target.value); setF({ ...f, ...start(c) }); setError(undefined); setErrs({}) }}>
                {!conn ? <option value="">{t('catalog.chooseConnection')}</option> : null}
                <ConnectionOptions connections={cat.connections} />
              </Select>
            </Field>
            <Field htmlFor="ca-risk" label={t('catalog.risk')}><Select id="ca-risk" value={f.risk} onChange={(e) => set({ risk: e.target.value as Risk })}>{(['low', 'medium', 'high'] as Risk[]).map((r) => <option key={r} value={r}>{t(`catalog.risks.${r}`)}</option>)}</Select></Field>
          </div>
          <p className="-mt-2 text-[13px] text-muted">{t('catalog.needConnection')} <Link className="text-accent underline underline-offset-4" to="/settings/connections">{t('catalog.toConnections')}</Link></p>
          {kind ? (
            <>
              <p className="text-[13px] text-muted">{t(action && !action.device ? 'catalog.placeholdersMessage' : 'catalog.placeholders')}</p>
              {ex.hint ? <p className="rounded-md border border-dashed border-rule px-3 py-2 text-[13px] text-muted">{ex.hint}</p> : null}
              <TplFields key={`run-${f.connection_id}`} id="ca-run" legend={t('catalog.runLegend')} kind={kind} value={f.run} onChange={(run) => set({ run })} tools={conn?.write_tools ?? []} tool={f.tool} onTool={(tool) => set({ tool })} error={errs['ca-run']} />
              <TplFields key={`rb-${f.connection_id}`} id="ca-rb" legend={t('catalog.rollbackLegend')} kind={kind} value={f.rollback} onChange={(rollback) => set({ rollback })} tools={conn?.write_tools ?? []} tool={f.rollback_tool} onTool={(rollback_tool) => set({ rollback_tool })} error={errs['ca-rb']} />
              {!isMcp(kind) ? <TplFields key={`vf-${f.connection_id}`} id="ca-vf" legend={t('catalog.verifyLegend')} kind={kind} value={f.verify} onChange={(verify) => set({ verify })} tools={[]} tool={null} onTool={() => undefined} hint={t('catalog.verifyHint')} expect error={errs['ca-vf']} /> : null}
              {isMcp(kind) ? <p className="text-[13px] text-muted">{t('catalog.precheckNoMcp')}</p> : (
                <TplFields key={`pc-${f.connection_id}`} id="ca-pc" legend={t('catalog.precheckLegend')} kind={kind} value={f.precheck ?? EMPTY_TPL} onChange={(precheck) => set({ precheck })} tools={[]} tool={null} onTool={() => undefined} hint={t('catalog.precheckHint')} readOnly error={errs['ca-pc']}>
                  <Field htmlFor="ca-pc-refuse" label={t('catalog.refuse')} hint={t('catalog.refuseHint', { max: MAX_REFUSE, len: MAX_REFUSE_LEN })}>
                    <RefuseText id="ca-pc-refuse" value={f.precheck_refuse ?? []} onChange={(precheck_refuse) => set({ precheck_refuse })} />
                  </Field>
                  <Field htmlFor="ca-pc-expect" label={t('catalog.precheckExpect')} hint={t('catalog.precheckExpectHint')}><Input id="ca-pc-expect" spellCheck={false} maxLength={MAX_REFUSE_LEN} value={f.precheck_expect ?? ''} onChange={(e) => set({ precheck_expect: e.target.value })} /></Field>
                </TplFields>
              )}
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

/** Settings, AI response: the action catalog by template pack. An action is allowed when it is enabled. */
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
    <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div><h3 className="text-sm font-medium">{t('catalog.title')}</h3><p className="text-[13px] text-muted">{t('catalog.hint')}</p></div>
        <Button onClick={() => setEdit('new')}><Plus className="size-4" aria-hidden />{t('catalog.add')}</Button>
      </div>
      {packsOf(cat.items).map((pack) => {
        const items = cat.items.filter((a) => a.pack === pack)
        if (!items.length) return null
        return (
          <section key={pack} className="grid grid-cols-[minmax(0,1fr)] gap-2" aria-label={t(`catalog.packs.${pack}`, { defaultValue: pack })}>
            <h4 className="mt-2 text-[13px] font-medium text-muted">{t(`catalog.packs.${pack}`, { defaultValue: pack })}</h4>
            {items.map((a) => (
              <Panel key={a.id} className="grid grid-cols-[minmax(0,1fr)] gap-2 p-4">
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
                {a.device && a.precheck_refuse.length ? <p className="text-[13px] text-muted">{t('catalog.checkedBefore', { texts: a.precheck_refuse.join(' · ') })}</p> : null}
                {a.device && a.precheck_expect ? <p className="text-[13px] text-muted">{t('catalog.mustContain', { text: a.precheck_expect })}</p> : null}
                {a.device && a.verify.expect ? <p className="text-[13px] text-muted">{t('catalog.readBackChecks', { text: a.verify.expect })}</p> : null}
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px]">
                  <div className="flex items-center gap-2">
                    <Switch id={`ai-${a.id}`} aria-label={t('catalog.aiMayFor', { name: a.name })} checked={a.ai_may_propose} disabled={save.isPending} onCheckedChange={(v) => save.mutate({ id: a.id, input: { ai_may_propose: v } }, { onError: fail })} />
                    <label htmlFor={`ai-${a.id}`} className="text-muted">{t('catalog.aiMay')}</label>
                  </div>
                  {a.device ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <label htmlFor={`cc-${a.id}`} className="text-muted">{t('catalog.connection')}:</label>
                      {a.builtin ? <Select id={`cc-${a.id}`} className="h-8 w-auto max-w-[14rem] sm:max-w-none" value={a.connection_id ?? ''} onChange={(e) => save.mutate({ id: a.id, input: { connection_id: e.target.value } }, { onError: fail })}>{a.connection_id ? null : <option value="">{t('catalog.chooseConnection')}</option>}<ConnectionOptions connections={cat.connections} /></Select> : <span>{a.connection}</span>}
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
