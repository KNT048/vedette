import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Card } from '@/components/common/Card'
import { Notice, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { DependencyLink } from '@/components/common/DependencyLink'
import { ListRow } from '@/components/common/ListParts'
import { useCan } from '@/lib/session'
import { fmtNumber, fmtRelative } from '@/lib/format'
import { useProfiles } from '../api'
import { fileBase64, useAddDoc, useDocJobs, useIndexProfile, useKnowledge, useRemoveDoc } from '../harness-api'
import { ActionError } from '../parts'
import type { KnowledgeDoc } from '../types'
import { ConfirmDelete, JobPicker, jobNames, List } from './shared'

const MAX = 10 * 1024 * 1024
const size = (n: number) => (n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)
const hostOf = (u: string) => { try { return new URL(u).host } catch { return u } }

/** Knowledge base (RAG): the customer's documents, with an index built on the box using the chosen AI profile. */
export default function KnowledgeTab() {
  const { t } = useTranslation('ai')
  const kb = useKnowledge()
  const profiles = useProfiles()
  const admin = useCan('admin')
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
            <Section title={t('harness.knowledge.indexTitle')} description={t('harness.knowledge.indexBody')} info={t('harness.knowledge.indexInfo')} stories={['S-AI-7']}>
              <Card className="grid gap-3">
                <Field label={t('harness.knowledge.indexLabel')} htmlFor="kb-index" hint={t('harness.knowledge.indexHint')}>
                  <Select id="kb-index" className="max-w-sm" value={k.index_profile ?? ''} disabled={index.isPending}
                    onChange={(e) => index.mutate(e.target.value || null, { onSuccess: () => { add.reset(); toast.success(t('harness.knowledge.indexSaved')) } })}>
                    <option value="">{t('harness.knowledge.indexNone')}</option>
                    {list.map((p) => <option key={p.id} value={p.id} disabled={!p.usable}>{p.name} ({t(`profiles.location.${p.location}`)}){!p.usable ? ` - ${t('assign.optNoKey')}` : ''}</option>)}
                  </Select>
                </Field>
                {/* §0: no profile can index yet: the way to add one (the administrator's), not a select that offers only None */}
                {profiles.data && !list.some((p) => p.usable) ? (admin ? <DependencyLink reason={t('harness.knowledge.noProfile')} to="/settings/ai?tab=profiles#ai-profiles" label={t('harness.knowledge.toProfiles')} />
                  : <p className="text-meta text-muted">{t('harness.knowledge.noProfile')} {t('gate.askAdmin')}</p>) : null}
                {chosen?.location === 'cloud' ? <Notice tone="warn" role="alert" title={t('harness.knowledge.cloudWarn', { host: hostOf(chosen.base_url) })} info={t('harness.knowledge.cloudWarnInfo')} /> : null}
                {chosen?.location === 'internal' ? <p className="text-meta text-muted">{t('harness.knowledge.internalNote')}</p> : null}
                <ActionError error={index.error} />
              </Card>
            </Section>
            <Section title={t('harness.knowledge.title')} description={t('harness.knowledge.body')} info={t('harness.knowledge.bodyInfo')}
              actions={<><Button variant="primary" onClick={() => file.current?.click()} disabled={!k.index_profile} busy={add.isPending} busyLabel={t('harness.knowledge.uploading')} title={!k.index_profile ? t('harness.knowledge.needIndex') : undefined}>{t('harness.knowledge.upload')}</Button>
                <input ref={file} type="file" hidden tabIndex={-1} aria-hidden="true" accept=".pdf,.md,.txt,.docx" onChange={(e) => { void onFile(e) }} data-testid="kb-file" /></>}>
              <div className="grid gap-3">
                {pickErr ? <Notice tone="danger" role="alert" title={pickErr} /> : null}
                <ActionError error={add.error} />
                {k.items.length === 0 ? <EmptyState title={t('harness.knowledge.empty')} info={t('harness.knowledge.emptyBodyInfo')}>{t('harness.knowledge.emptyBody')}</EmptyState> : (
                  <List label={t('harness.knowledge.title')}>
                    {k.items.map((d) => (
                      <ListRow key={d.id} title={d.name} badges={<Chip tone={d.status === 'ready' ? 'ok' : 'warn'}>{t(`harness.knowledge.status.${d.status}`)}</Chip>}
                        meta={[
                          `${size(d.size)} · ${d.chunks === null ? t('harness.knowledge.noChunks') : t('harness.knowledge.chunks', { count: d.chunks, n: fmtNumber(d.chunks) })} · ${fmtRelative(d.uploaded_at)}`,
                          t('harness.knowledge.usedBy', { jobs: jobNames(t, d.jobs) }),
                        ]}
                        actions={<>
                        <Button size="sm" onClick={() => setJobsFor(d)} aria-label={t('harness.knowledge.jobsNamed', { name: d.name })}>{t('harness.knowledge.jobs')}</Button>
                        <Button size="sm" onClick={() => setDel(d)} aria-label={t('harness.deleteNamed', { name: d.name })}>{t('harness.delete')}</Button>
                      </>} />
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
            <Button type="submit" variant="primary" busy={save.isPending} busyLabel={t('common:busy.saving')}>{t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
