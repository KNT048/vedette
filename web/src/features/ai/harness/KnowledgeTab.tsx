import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { fmtNumber, fmtRelative } from '@/lib/format'
import { useProfiles } from '../api'
import { fileBase64, useAddDoc, useDocJobs, useIndexProfile, useKnowledge, useRemoveDoc } from '../harness-api'
import { ActionError } from '../parts'
import type { KnowledgeDoc } from '../types'
import { ConfirmDelete, JobPicker, jobNames, List, Row } from './shared'

const MAX = 10 * 1024 * 1024
const size = (n: number) => (n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)
const hostOf = (u: string) => { try { return new URL(u).host } catch { return u } }

/** Kho tri thức (RAG): tài liệu của khách, chỉ mục xây trên hộp bằng hồ sơ AI đã chọn (D-39). */
export default function KnowledgeTab() {
  const { t } = useTranslation('ai')
  const kb = useKnowledge()
  const profiles = useProfiles()
  const index = useIndexProfile()
  const add = useAddDoc()
  const remove = useRemoveDoc()
  const file = useRef<HTMLInputElement>(null)
  const [pickErr, setPickErr] = useState('')
  const [jobsFor, setJobsFor] = useState<KnowledgeDoc | null>(null)
  const [del, setDel] = useState<KnowledgeDoc | null>(null)
  const list = profiles.data?.items ?? []

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    setPickErr('')
    if (!/\.(pdf|md|txt|docx)$/i.test(f.name)) { setPickErr(t('harness.knowledge.errType', { name: f.name })); return }
    if (f.size > MAX) { setPickErr(t('harness.knowledge.errSize', { name: f.name })); return }
    if (f.size === 0) { setPickErr(t('harness.knowledge.errEmpty', { name: f.name })); return }
    let content: string
    try { content = await fileBase64(f) } catch { setPickErr(t('harness.knowledge.errRead', { name: f.name })); return }
    add.mutate({ name: f.name, size: f.size, content }, { onSuccess: () => toast.success(t('harness.knowledge.added', { name: f.name })) })
  }
  return (
    <QueryState query={kb}>
      {(k) => {
        const chosen = list.find((p) => p.id === k.index_profile)
        return (
          <>
            <Section title={t('harness.knowledge.indexTitle')} description={t('harness.knowledge.indexBody')} stories={['S-AI-7']}>
              <Panel className="grid gap-3 p-4">
                <Field label={t('harness.knowledge.indexLabel')} htmlFor="kb-index" hint={t('harness.knowledge.indexHint')}>
                  <Select id="kb-index" className="max-w-sm" value={k.index_profile ?? ''} disabled={index.isPending}
                    onChange={(e) => index.mutate(e.target.value || null, { onSuccess: () => toast.success(t('harness.knowledge.indexSaved')) })}>
                    <option value="">{t('harness.knowledge.indexNone')}</option>
                    {list.map((p) => <option key={p.id} value={p.id} disabled={!p.usable}>{p.name} ({t(`profiles.location.${p.location}`)}){!p.usable ? ` - ${t('assign.optNoKey')}` : ''}</option>)}
                  </Select>
                </Field>
                {chosen?.location === 'cloud' ? <p role="alert" className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-sm">{t('harness.knowledge.cloudWarn', { host: hostOf(chosen.base_url) })}</p> : null}
                {chosen?.location === 'internal' ? <p className="text-[13px] text-muted">{t('harness.knowledge.internalNote')}</p> : null}
                <ActionError error={index.error} />
              </Panel>
            </Section>
            <Section title={t('harness.knowledge.title')} description={t('harness.knowledge.body')}
              actions={<><Button variant="primary" onClick={() => file.current?.click()} disabled={add.isPending || !k.index_profile} title={!k.index_profile ? t('harness.knowledge.needIndex') : undefined}>{add.isPending ? t('harness.knowledge.uploading') : t('harness.knowledge.upload')}</Button>
                <input ref={file} type="file" hidden tabIndex={-1} aria-hidden="true" accept=".pdf,.md,.txt,.docx" onChange={(e) => { void onFile(e) }} data-testid="kb-file" /></>}>
              <div className="grid gap-3">
                {pickErr ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{pickErr}</p> : null}
                <ActionError error={add.error} />
                {k.items.length === 0 ? <EmptyState title={t('harness.knowledge.empty')}>{t('harness.knowledge.emptyBody')}</EmptyState> : (
                  <List label={t('harness.knowledge.title')}>
                    {k.items.map((d) => (
                      <Row key={d.id} actions={<>
                        <Button size="sm" onClick={() => setJobsFor(d)} aria-label={t('harness.knowledge.jobsNamed', { name: d.name })}>{t('harness.knowledge.jobs')}</Button>
                        <Button size="sm" onClick={() => setDel(d)} aria-label={t('harness.deleteNamed', { name: d.name })}>{t('harness.delete')}</Button>
                      </>}>
                        <p className="flex flex-wrap items-center gap-2 font-medium">{d.name} <Chip tone={d.status === 'ready' ? 'ok' : 'warn'}>{t(`harness.knowledge.status.${d.status}`)}</Chip></p>
                        <p className="text-[13px] text-muted">{size(d.size)} · {d.chunks === null ? t('harness.knowledge.noChunks') : t('harness.knowledge.chunks', { n: fmtNumber(d.chunks) })} · {fmtRelative(d.uploaded_at)}</p>
                        <p className="text-[13px] text-muted">{t('harness.knowledge.usedBy', { jobs: jobNames(t, d.jobs) })}</p>
                      </Row>
                    ))}
                  </List>
                )}
              </div>
            </Section>
            {jobsFor ? <DocJobsDialog doc={jobsFor} onClose={() => setJobsFor(null)} /> : null}
            {del ? <ConfirmDelete title={t('harness.knowledge.deleteTitle', { name: del.name })} body={t('harness.knowledge.deleteBody')} pending={remove.isPending} error={remove.error} onClose={() => setDel(null)} onConfirm={() => remove.mutate(del.id, { onSuccess: () => { setDel(null); toast.success(t('harness.knowledge.deleted')) } })} /> : null}
          </>
        )
      }}
    </QueryState>
  )
}

function DocJobsDialog({ doc, onClose }: { doc: KnowledgeDoc; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const save = useDocJobs()
  const [jobs, setJobs] = useState(doc.jobs)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('harness.knowledge.jobsTitle', { name: doc.name })} description={t('harness.knowledge.jobsBody')}>
        <form noValidate className="grid gap-4" aria-label={t('harness.knowledge.jobsTitle', { name: doc.name })} onSubmit={(e) => { e.preventDefault(); save.mutate({ id: doc.id, jobs }, { onSuccess: () => { toast.success(t('harness.knowledge.jobsSaved')); onClose() } }) }}>
          <JobPicker value={jobs} onChange={setJobs} idPrefix="kb-job" legend={t('harness.knowledge.jobsLegend')} allLabel={t('harness.knowledge.allJobs')} />
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
