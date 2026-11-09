import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Label, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDate, fmtRelative } from '@/lib/format'
import { useAddMemory, useAnswerSuggestion, useMemory, useMemorySettings, usePatchMemory, useRemoveMemory } from '../harness-api'
import { ActionError } from '../parts'
import type { MemoryEntry } from '../types'
import { ConfirmDelete, List, Row, Toggle } from './shared'

/** Điều AI nhớ về hạ tầng này. Xem, sửa, tắt, xoá; AI chỉ đề xuất, người duyệt (D-39). */
export default function MemoryTab() {
  const { t } = useTranslation('ai')
  const mem = useMemory()
  const settings = useMemorySettings()
  const answer = useAnswerSuggestion()
  const patch = usePatchMemory()
  const remove = useRemoveMemory()
  const [edit, setEdit] = useState<MemoryEntry | 'new' | null>(null)
  const [del, setDel] = useState<MemoryEntry | null>(null)
  const fail = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  return (
    <QueryState query={mem}>
      {(m) => (
        <>
          <Section title={t('harness.memory.suggestTitle')} stories={['S-AI-7']}>
            <Panel className="flex items-start gap-3 p-4">
              <Switch id="mem-suggest" checked={m.suggest_enabled} onCheckedChange={(v) => settings.mutate(v, { onError: fail })} disabled={settings.isPending} />
              <div className="grid gap-0.5"><Label htmlFor="mem-suggest">{t('harness.memory.suggestSwitch')}</Label><p className="text-[13px] text-muted">{t('harness.memory.suggestHint')}</p></div>
            </Panel>
            {m.suggestions.length > 0 ? (
              <div className="mt-4">
                <h3 className="mb-2 text-sm font-medium">{t('harness.memory.queueTitle', { n: m.suggestions.length })}</h3>
                <List label={t('harness.memory.queueTitle', { n: m.suggestions.length })}>
                  {m.suggestions.map((s) => (
                    <Row key={s.id} actions={<>
                      <Button size="sm" variant="primary" disabled={answer.isPending} onClick={() => answer.mutate({ id: s.id, accept: true }, { onSuccess: () => toast.success(t('harness.memory.accepted')), onError: fail })} aria-label={t('harness.memory.acceptNamed', { text: s.text.slice(0, 40) })}>{t('harness.memory.accept')}</Button>
                      <Button size="sm" disabled={answer.isPending} onClick={() => answer.mutate({ id: s.id, accept: false }, { onError: fail })} aria-label={t('harness.memory.rejectNamed', { text: s.text.slice(0, 40) })}>{t('harness.memory.reject')}</Button>
                    </>}>
                      <p>{s.text}</p>
                      <p className="text-[13px] text-muted">{t('harness.memory.noticed', { evidence: s.evidence, when: fmtRelative(s.created_at) })}</p>
                    </Row>
                  ))}
                </List>
              </div>
            ) : m.suggest_enabled ? <p className="mt-3 text-sm text-muted">{t('harness.memory.queueEmpty')}</p> : null}
          </Section>
          <Section title={t('harness.memory.title')} description={t('harness.memory.body')} actions={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.memory.add')}</Button>}>
            {m.items.length === 0 ? <EmptyState title={t('harness.memory.empty')} action={<Button variant="primary" onClick={() => setEdit('new')}>{t('harness.memory.add')}</Button>}>{t('harness.memory.emptyBody')}</EmptyState> : (
              <List label={t('harness.memory.title')}>
                {m.items.map((x) => (
                  <Row key={x.id} dim={!x.enabled}
                    actions={<>
                      <Toggle checked={x.enabled} label={t('harness.memory.enable', { text: x.text.slice(0, 40) })} onChange={(enabled) => patch.mutate({ id: x.id, enabled }, { onError: fail })} />
                      <Button size="sm" onClick={() => setEdit(x)} aria-label={t('harness.editNamed', { name: x.text.slice(0, 40) })}>{t('harness.edit')}</Button>
                      <Button size="sm" onClick={() => setDel(x)} aria-label={t('harness.deleteNamed', { name: x.text.slice(0, 40) })}>{t('harness.delete')}</Button>
                    </>}>
                    <p>{x.text}</p>
                    <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
                      <Chip tone={x.source === 'ai' ? 'accent' : 'off'}>{t(`harness.memory.source.${x.source}`)}</Chip>
                      <span>{t('harness.memory.created', { date: fmtDate(x.created_at) })}</span>
                      <span>{x.last_used_at ? t('harness.memory.used', { when: fmtRelative(x.last_used_at) }) : t('harness.memory.neverUsed')}</span>
                      {!x.enabled ? <span>{t('harness.off')}</span> : null}
                    </p>
                  </Row>
                ))}
              </List>
            )}
          </Section>
          {edit ? <MemoryDialog entry={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
          {del ? <ConfirmDelete title={t('harness.memory.deleteTitle')} body={del.text} pending={remove.isPending} error={remove.error} onClose={() => setDel(null)} onConfirm={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('harness.memory.deleted')) } })} /> : null}
        </>
      )}
    </QueryState>
  )
}

function MemoryDialog({ entry, onClose }: { entry: MemoryEntry | null; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const add = useAddMemory()
  const patch = usePatchMemory()
  const [text, setText] = useState(entry?.text ?? '')
  const [err, setErr] = useState('')
  const q = entry ? patch : add
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (text.trim().length < 3) { setErr(t('harness.memory.errText')); return }
    const done = { onSuccess: () => { toast.success(t('harness.memory.saved')); onClose() } }
    if (entry) patch.mutate({ id: entry.id, text: text.trim() }, done); else add.mutate({ text: text.trim() }, done)
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={entry ? t('harness.memory.editTitle') : t('harness.memory.addTitle')} description={t('harness.memory.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={entry ? t('harness.memory.editTitle') : t('harness.memory.addTitle')}>
          <Field label={t('harness.memory.text')} htmlFor="mem-text" hint={t('harness.memory.textHint')} error={err || undefined}>
            <Textarea id="mem-text" value={text} maxLength={300} onChange={(e) => { setText(e.target.value); setErr('') }} aria-invalid={err ? true : undefined} aria-describedby={err ? 'mem-text-error' : 'mem-text-hint'} />
          </Field>
          <ActionError error={q.error} />
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={q.isPending}>{q.isPending ? t('harness.saving') : t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
