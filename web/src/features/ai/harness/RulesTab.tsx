import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useRemoveRule, useRules, useSaveRule } from '../harness-api'
import { ActionError } from '../parts'
import type { Rule } from '../types'
import { ConfirmDelete, JobPicker, jobNames, List, Row, Toggle } from './shared'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/input'

/** Quy tắc đưa vào mọi lần gọi AI (D-39). Quy tắc có sẵn chỉ đọc; quy tắc riêng thêm/sửa/xoá/tắt. */
export default function RulesTab() {
  const { t } = useTranslation('ai')
  const rules = useRules()
  const save = useSaveRule()
  const remove = useRemoveRule()
  const [edit, setEdit] = useState<Rule | 'new' | null>(null)
  const [del, setDel] = useState<Rule | null>(null)
  return (
    <QueryState query={rules}>
      {(r) => (
        <>
          <Section title={t('harness.rules.builtinTitle')} description={t('harness.rules.builtinBody')} stories={['S-AI-7']}>
            <List label={t('harness.rules.builtinTitle')}>
              {r.builtin.map((b) => <Row key={b.id} actions={<Chip tone="off">{t('harness.builtIn')}</Chip>}><p>{b.text}</p></Row>)}
            </List>
          </Section>
          <Section title={t('harness.rules.customTitle')} description={t('harness.rules.customBody')} actions={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.rules.add')}</Button>}>
            {r.custom.length === 0 ? <EmptyState title={t('harness.rules.empty')} action={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.rules.add')}</Button>}>{t('harness.rules.emptyBody')}</EmptyState> : (
              <List label={t('harness.rules.customTitle')}>
                {r.custom.map((x) => (
                  <Row key={x.id} dim={!x.enabled}
                    actions={<>
                      <Toggle checked={x.enabled} label={t('harness.rules.enable', { text: x.text.slice(0, 40) })} onChange={(enabled) => save.mutate({ ...x, enabled }, { onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })} />
                      <Button size="sm" onClick={() => setEdit(x)} aria-label={t('harness.editNamed', { name: x.text.slice(0, 40) })}>{t('harness.edit')}</Button>
                      <Button size="sm" onClick={() => setDel(x)} aria-label={t('harness.deleteNamed', { name: x.text.slice(0, 40) })}>{t('harness.delete')}</Button>
                    </>}>
                    <p>{x.text}</p>
                    <p className="text-[13px] text-muted">{t('harness.appliesTo', { jobs: jobNames(t, x.jobs) })}{x.enabled ? '' : ` · ${t('harness.off')}`}</p>
                  </Row>
                ))}
              </List>
            )}
          </Section>
          {edit ? <RuleDialog rule={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
          {del ? <ConfirmDelete title={t('harness.rules.deleteTitle')} body={del.text} pending={remove.isPending} error={remove.error} onClose={() => setDel(null)} onConfirm={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('harness.rules.deleted')) } })} /> : null}
        </>
      )}
    </QueryState>
  )
}

function RuleDialog({ rule, onClose }: { rule: Rule | null; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const save = useSaveRule()
  const [text, setText] = useState(rule?.text ?? '')
  const [jobs, setJobs] = useState(rule?.jobs ?? [])
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [err, setErr] = useState('')
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (text.trim().length < 3) { setErr(t('harness.rules.errText')); return }
    save.mutate({ id: rule?.id, text: text.trim(), jobs, enabled }, { onSuccess: () => { toast.success(t('harness.rules.saved')); onClose() } })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={rule ? t('harness.rules.editTitle') : t('harness.rules.addTitle')} description={t('harness.rules.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={rule ? t('harness.rules.editTitle') : t('harness.rules.addTitle')}>
          <Field label={t('harness.rules.text')} htmlFor="rule-text" hint={t('harness.rules.textHint')} error={err || undefined}>
            <Textarea id="rule-text" value={text} maxLength={300} onChange={(e) => { setText(e.target.value); setErr('') }} aria-invalid={err ? true : undefined} aria-describedby={err ? 'rule-text-error' : 'rule-text-hint'} />
          </Field>
          <JobPicker value={jobs} onChange={setJobs} idPrefix="rule-job" legend={t('harness.rules.jobs')} />
          <div className="flex items-center gap-3"><Switch id="rule-enabled" checked={enabled} onCheckedChange={setEnabled} /><Label htmlFor="rule-enabled" className="font-normal">{t('harness.enabled')}</Label></div>
          <ActionError error={save.error} />
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? t('harness.saving') : t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
