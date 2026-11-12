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
import { ApiError } from '@/lib/api'
import { useHooks, useRemoveHook, useSaveHook, useTestHook, useToggleBuiltinHook } from '../harness-api'
import { ActionError } from '../parts'
import type { CustomHook, HookAction, HookInput, HookTestResult, HookWhen } from '../types'
import { ConfirmDelete, List, Row, Toggle } from './shared'

const WHENS: HookWhen[] = ['before_ai', 'after_ai', 'before_tool']
const ACTIONS: HookAction[] = ['block', 'mask', 'approve']
const tone = (a: HookAction) => (a === 'block' ? 'danger' : a === 'mask' ? 'warn' : 'accent')

/** Hook: kiểm tra chạy trước và sau mỗi lần gọi AI (D-39). Có sẵn 3 hook; khách thêm hook theo từ khoá hoặc biểu thức. */
export default function HooksTab() {
  const { t } = useTranslation('ai')
  const hooks = useHooks()
  const toggle = useToggleBuiltinHook()
  const save = useSaveHook()
  const remove = useRemoveHook()
  const [edit, setEdit] = useState<CustomHook | 'new' | null>(null)
  const [del, setDel] = useState<CustomHook | null>(null)
  const fail = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  return (
    <QueryState query={hooks}>
      {(h) => (
        <>
          <Section title={t('harness.hooks.builtinTitle')} description={t('harness.hooks.body')} stories={['S-AI-7']}>
            <List label={t('harness.hooks.builtinTitle')}>
              {h.builtin.map((b) => (
                <Row key={b.id} dim={!b.enabled}
                  actions={<>{b.locked ? <Chip tone="ok">{t('harness.hooks.locked')}</Chip> : null}<Toggle checked={b.enabled} disabled={b.locked} title={b.locked ? t('harness.hooks.lockedWhy') : undefined} label={t('harness.hooks.enable', { name: b.name })} onChange={(enabled) => toggle.mutate({ id: b.id, enabled }, { onError: fail })} /></>}>
                  <p className="font-medium">{b.name}</p>
                  <p className="text-muted">{b.description}</p>
                  {b.locked ? <p className="text-[13px] text-muted">{t('harness.hooks.lockedWhy')}</p> : null}
                </Row>
              ))}
            </List>
          </Section>
          <Section title={t('harness.hooks.customTitle')} description={t('harness.hooks.customBody')} actions={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.hooks.add')}</Button>}>
            {h.custom.length === 0 ? <EmptyState title={t('harness.hooks.empty')} action={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.hooks.add')}</Button>}>{t('harness.hooks.emptyBody')}</EmptyState> : (
              <List label={t('harness.hooks.customTitle')}>
                {h.custom.map((x) => (
                  <Row key={x.id} dim={!x.enabled}
                    actions={<>
                      <Toggle checked={x.enabled} label={t('harness.hooks.enable', { name: x.name })} onChange={(enabled) => save.mutate({ ...x, enabled }, { onError: fail })} />
                      <Button size="sm" onClick={() => setEdit(x)} aria-label={t('harness.editNamed', { name: x.name })}>{t('harness.edit')}</Button>
                      <Button size="sm" onClick={() => setDel(x)} aria-label={t('harness.deleteNamed', { name: x.name })}>{t('harness.delete')}</Button>
                    </>}>
                    <p className="flex flex-wrap items-center gap-2 font-medium">{x.name} <Chip tone={tone(x.action)}>{t(`harness.hooks.action.${x.action}`)}</Chip></p>
                    <p className="text-[13px] text-muted">{t(`harness.hooks.when.${x.when}`)} · {t(`harness.hooks.matchType.${x.match.type}`)}: <code className="font-mono">{x.match.pattern}</code></p>
                    <p className="text-[13px] text-muted">{t('harness.hooks.shows', { message: x.message })}</p>
                  </Row>
                ))}
              </List>
            )}
          </Section>
          <Section title={t('harness.hooks.tryTitle')} description={t('harness.hooks.tryBody')}><TestBox idPrefix="try" /></Section>
          {edit ? <HookDialog hook={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
          {del ? <ConfirmDelete title={t('harness.hooks.deleteTitle', { name: del.name })} body={t('harness.hooks.deleteBody')} pending={remove.isPending} error={remove.error} onClose={() => setDel(null)} onConfirm={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('harness.hooks.deleted')) } })} /> : null}
        </>
      )}
    </QueryState>
  )
}

/** Ô thử: gõ một đoạn văn bản, xem hook nào chạy. Có `hook` thì chỉ thử hook nháp đó, không thì chạy mọi hook đang bật. */
function TestBox({ idPrefix, hook }: { idPrefix: string; hook?: HookInput }) {
  const { t } = useTranslation('ai')
  const test = useTestHook()
  const [text, setText] = useState('')
  const [when, setWhen] = useState<HookWhen>('before_ai')
  // A result holds for the draft it was run on: editing the hook (name, words, stage, action, message) hides it until Test runs again.
  const draft = JSON.stringify(hook ? [hook.name, hook.when, hook.match, hook.action, hook.message] : null)
  const [ran, setRan] = useState<{ r: HookTestResult; draft: string } | null>(null)
  const res = ran && ran.draft === draft ? ran.r : null
  const stage = hook ? hook.when : when
  function run() {
    setRan(null)
    test.mutate({ text: text.trim(), when: stage, hook }, { onSuccess: (r) => setRan({ r, draft }) })
  }
  return (
    <Panel className="grid gap-3 p-4">
      <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
        <Field label={t('harness.hooks.sample')} htmlFor={`${idPrefix}-text`} hint={t('harness.hooks.sampleHint')}><Textarea id={`${idPrefix}-text`} className="min-h-16" value={text} maxLength={1000} onChange={(e) => { setText(e.target.value); setRan(null) }} /></Field>
        {!hook ? <Field label={t('harness.hooks.stage')} htmlFor={`${idPrefix}-when`}><Select id={`${idPrefix}-when`} value={when} onChange={(e) => { setWhen(e.target.value as HookWhen); setRan(null) }}>{WHENS.map((w) => <option key={w} value={w}>{t(`harness.hooks.when.${w}`)}</option>)}</Select></Field> : null}
      </div>
      <div><Button onClick={run} disabled={!text.trim() || test.isPending || (!!hook && !hook.match.pattern)} title={hook && !hook.match.pattern ? t('harness.hooks.errPattern') : undefined}>{test.isPending ? t('harness.hooks.testing') : t('harness.hooks.test')}</Button></div>
      <ActionError error={test.error} />
      {res ? (
        <div role="status" className="grid gap-2 text-sm">
          <p className="flex flex-wrap items-center gap-2"><Chip tone={res.outcome === 'pass' ? 'ok' : res.outcome === 'masked' ? 'warn' : 'danger'}>{t(`harness.hooks.outcome.${res.outcome}`)}</Chip>{res.hits.map((x) => <span key={`${x.id}-${x.action}`} className="text-muted">{x.name}</span>)}</p>
          <p className="rounded-md border border-rule bg-sunken px-3 py-2">{res.output}</p>
        </div>
      ) : null}
    </Panel>
  )
}

function HookDialog({ hook, onClose }: { hook: CustomHook | null; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const save = useSaveHook()
  const [name, setName] = useState(hook?.name ?? '')
  const [when, setWhen] = useState<HookWhen>(hook?.when ?? 'before_ai')
  const [type, setType] = useState<'keywords' | 'regex'>(hook?.match.type ?? 'keywords')
  const [pattern, setPattern] = useState(hook?.match.pattern ?? '')
  const [action, setAction] = useState<HookAction>(hook?.action ?? 'block')
  const [message, setMessage] = useState(hook?.message ?? '')
  const [enabled, setEnabled] = useState(hook?.enabled ?? true)
  const [errs, setErrs] = useState<Partial<Record<'name' | 'pattern' | 'message', string>>>({})
  const draft: HookInput = { name: name.trim() || 'Draft', when, match: { type, pattern: pattern.trim() }, action, message: message.trim(), enabled }
  const clear = (k: keyof typeof errs) => setErrs((e) => ({ ...e, [k]: undefined }))
  // Lỗi do máy chủ chỉ ra ô nào sai (biểu thức hỏng, tên trùng…)
  const code = save.error instanceof ApiError ? save.error.code : ''
  const serverFor = (k: 'name' | 'pattern' | 'message') => ((code === 'invalid_match' && k === 'pattern') || ((code === 'invalid_name' || code === 'duplicate_name') && k === 'name') || (code === 'invalid_message' && k === 'message') ? (save.error as Error).message : undefined)
  const err = (k: 'name' | 'pattern' | 'message') => errs[k] ?? serverFor(k)
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const n: typeof errs = {}
    if (!name.trim()) n.name = t('harness.hooks.errName')
    if (!pattern.trim()) n.pattern = t('harness.hooks.errPattern')
    if (message.trim().length < 3) n.message = t('harness.hooks.errMessage')
    setErrs(n)
    if (Object.keys(n).length) return
    save.mutate({ id: hook?.id, ...draft, name: name.trim() }, { onSuccess: () => { toast.success(t('harness.hooks.saved')); onClose() } })
  }
  const aria = (k: 'name' | 'pattern' | 'message', hint?: boolean) => ({ 'aria-invalid': err(k) ? true : undefined, 'aria-describedby': err(k) ? `hk-${k}-error` : hint ? `hk-${k}-hint` : undefined })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={hook ? t('harness.hooks.editTitle', { name: hook.name }) : t('harness.hooks.addTitle')} description={t('harness.hooks.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={hook ? t('harness.hooks.editTitle', { name: hook.name }) : t('harness.hooks.addTitle')}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('harness.hooks.f.name')} htmlFor="hk-name" error={err('name')}><Input id="hk-name" value={name} maxLength={40} autoComplete="off" onChange={(e) => { setName(e.target.value); clear('name') }} {...aria('name')} /></Field>
            <Field label={t('harness.hooks.f.when')} htmlFor="hk-when"><Select id="hk-when" value={when} onChange={(e) => setWhen(e.target.value as HookWhen)}>{WHENS.map((w) => <option key={w} value={w}>{t(`harness.hooks.when.${w}`)}</option>)}</Select></Field>
            <Field label={t('harness.hooks.f.matchType')} htmlFor="hk-type"><Select id="hk-type" value={type} onChange={(e) => { setType(e.target.value as 'keywords' | 'regex'); setPattern(''); clear('pattern') }}>{(['keywords', 'regex'] as const).map((m) => <option key={m} value={m}>{t(`harness.hooks.matchType.${m}`)}</option>)}</Select></Field>
            <Field label={t('harness.hooks.f.action')} htmlFor="hk-action" hint={t(`harness.hooks.f.actionHint_${action}`)}><Select id="hk-action" value={action} onChange={(e) => setAction(e.target.value as HookAction)}>{ACTIONS.map((a) => <option key={a} value={a}>{t(`harness.hooks.action.${a}`)}</option>)}</Select></Field>
            <Field label={t(`harness.hooks.f.pattern_${type}`)} htmlFor="hk-pattern" hint={t(`harness.hooks.f.patternHint_${type}`)} error={err('pattern')} className="sm:col-span-2"><Input id="hk-pattern" className="font-mono text-[13px]" value={pattern} maxLength={200} autoComplete="off" onChange={(e) => { setPattern(e.target.value); clear('pattern') }} {...aria('pattern', true)} /></Field>
            <Field label={t('harness.hooks.f.message')} htmlFor="hk-message" hint={t('harness.hooks.f.messageHint')} error={err('message')} className="sm:col-span-2"><Input id="hk-message" value={message} maxLength={200} onChange={(e) => { setMessage(e.target.value); clear('message') }} {...aria('message', true)} /></Field>
          </div>
          <div className="flex items-center gap-3"><Switch id="hk-enabled" checked={enabled} onCheckedChange={setEnabled} /><Label htmlFor="hk-enabled" className="font-normal">{t('harness.enabled')}</Label></div>
          <div className="grid gap-1"><h3 className="text-sm font-medium">{t('harness.hooks.testTitle')}</h3><TestBox idPrefix="hk-test" hook={{ ...draft, message: draft.message || 'Test' }} /></div>
          {save.error && !serverFor('name') && !serverFor('pattern') && !serverFor('message') ? <ActionError error={save.error} /> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? t('harness.saving') : t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
