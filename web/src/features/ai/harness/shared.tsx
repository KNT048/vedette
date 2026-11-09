import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { AiJob } from '../contract'
import { ActionError } from '../parts'
import type { AiJob as Job } from '../types'

export const ALL_JOBS = AiJob.options as Job[]

/** Một dòng trong danh sách quản lý: nội dung bên trái, công tắc và nút bên phải. */
export function Row({ children, actions, dim }: { children: React.ReactNode; actions?: React.ReactNode; dim?: boolean }) {
  return (
    <li className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-rule px-4 py-3 last:border-b-0">
      <div className={`grid min-w-0 flex-1 basis-72 gap-1 text-sm ${dim ? 'opacity-60' : ''}`}>{children}</div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </li>
  )
}
export const List = ({ label, children }: { label: string; children: React.ReactNode }) => <ul aria-label={label} className="rounded-md border border-rule bg-surface">{children}</ul>

export function Toggle({ checked, onChange, label, disabled, title }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; title?: string }) {
  return <Switch checked={checked} onCheckedChange={onChange} aria-label={label} disabled={disabled} title={title} />
}

export function jobNames(t: (k: string) => string, jobs: Job[]) { return jobs.length ? jobs.map((j) => t(`jobs.${j}.name`)).join(', ') : t('harness.allJobs') }

/** "Mọi việc" hoặc chọn từng việc. `value` rỗng = mọi việc. */
export function JobPicker({ value, onChange, idPrefix, legend, allLabel }: { value: Job[]; onChange: (v: Job[]) => void; idPrefix: string; legend: string; allLabel?: string }) {
  const { t } = useTranslation('ai')
  const all = value.length === 0
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      <RadioGroup value={all ? 'all' : 'some'} onValueChange={(v) => onChange(v === 'all' ? [] : [ALL_JOBS[0]!])} aria-label={legend}>
        <div className="flex items-center gap-2"><RadioItem id={`${idPrefix}-all`} value="all" /><Label htmlFor={`${idPrefix}-all`} className="font-normal">{allLabel ?? t('harness.allJobs')}</Label></div>
        <div className="flex items-center gap-2"><RadioItem id={`${idPrefix}-some`} value="some" /><Label htmlFor={`${idPrefix}-some`} className="font-normal">{t('harness.chosenJobs')}</Label></div>
      </RadioGroup>
      {!all ? (
        <div className="grid gap-1.5 rounded-md border border-rule p-3 sm:grid-cols-2">
          {ALL_JOBS.map((j) => (
            <div key={j} className="flex items-center gap-2">
              <Checkbox id={`${idPrefix}-${j}`} checked={value.includes(j)} onCheckedChange={(c) => { const next = c === true ? [...value, j] : value.filter((x) => x !== j); onChange(next.length ? next : value) }} />
              <Label htmlFor={`${idPrefix}-${j}`} className="font-normal">{t(`jobs.${j}.name`)}</Label>
            </div>
          ))}
          <p className="text-[13px] text-muted sm:col-span-2">{t('harness.atLeastOne')}</p>
        </div>
      ) : null}
    </fieldset>
  )
}

export function ConfirmDelete({ title, body, onConfirm, onClose, pending, error }: { title: string; body: string; onConfirm: () => void; onClose: () => void; pending: boolean; error: unknown }) {
  const { t } = useTranslation('ai')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={title} description={body}>
        <ActionError error={error} />
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" disabled={pending} onClick={onConfirm}>{t('harness.delete')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
