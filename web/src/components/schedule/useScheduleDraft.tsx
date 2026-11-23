import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ErrorState } from '@/components/common/States'
import { useSaveSchedule, useSchedule } from './api'
import { intervalProblem, intervalText, toDraft, toSave, type Draft } from './rule'
import { orgZoneOf, ScheduleFields } from './ScheduleFields'
import type { Schedule } from './types'

/**
 * A schedule's fields inside another item's dialog (a feed's settings), saved with that dialog's own Save: `fields` to draw,
 * `commit()` to save the schedule when it changed (it rejects with the box's answer, which `fields` then shows at its field).
 */
export function useScheduleDraft(ownerKey: string, { idPrefix, enabled = true, onOff = true }: { idPrefix: string; enabled?: boolean; onOff?: boolean }): { fields: ReactNode; commit: () => Promise<Schedule | undefined>; pending: boolean } {
  const { t } = useTranslation('schedule')
  const q = useSchedule(ownerKey, enabled)
  const save = useSaveSchedule(ownerKey)
  const [draft, setDraft] = useState<Draft | null>(null)
  const s = q.data
  const orgZone = s ? orgZoneOf(s) : ''
  if (s && draft === null) setDraft(toDraft(s, orgZone))
  const dirty = !!s && !!draft && JSON.stringify(toSave(draft, orgZone)) !== JSON.stringify(toSave(toDraft(s, orgZone), orgZone))
  const fields = !enabled ? null
    : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} />
    : s && draft ? <ScheduleFields schedule={s} draft={draft} onChange={(d) => { setDraft(d); save.reset() }} error={save.error} idPrefix={idPrefix} onOff={onOff} />
    : <p role="status" className="text-meta text-muted">{t('loading')}</p>
  const commit = () => {
    // an interval the owner does not allow: the field already says why in plain words; the dialog's save stops with the same words
    const p = s && draft && (draft.enabled || !onOff) ? intervalProblem(draft, s.limits) : null
    if (p && s) return Promise.reject(new Error(intervalText(p, s.limits, t)))
    return dirty && draft ? save.mutateAsync(toSave(draft, orgZone)) : Promise.resolve(s)
  }
  return { fields, commit, pending: save.isPending }
}
