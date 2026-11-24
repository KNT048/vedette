import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { useSchedule } from '@/components/schedule/api'
import { ScheduleEditor } from '@/components/schedule/ScheduleEditor'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { useChannels } from '@/features/notify/api'
import { useNewChannel } from '@/features/notify/NewChannel'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { useDefinition, useSaveDefinition } from './api'
import { ActionError } from './parts'
import type { ReportDefinition, ReportDefinitionInput, ReportOptions } from './types'

// The box's rule for a recipient (modules/reports validate.go): a plain address of 120 characters at most, 20 addresses at most.
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/
const EMAIL_MAX = 120
const MAX_RECIPIENTS = 20
const PERIODS: ReportOptions['period'][] = ['last_7_days', 'last_30_days', 'calendar_month']
/** The period a report covers while its schedule sends it (modules/reports periodFollows): the time since the one before it. */
const FOLLOWS: Partial<Record<string, ReportOptions['period']>> = { weekly: 'last_7_days', monthly: 'calendar_month' }
const SECTIONS: (keyof ReportOptions['sections'])[] = ['summary', 'handled', 'open', 'new', 'exposure', 'detections', 'coverage']

const input = (d: ReportDefinition): ReportDefinitionInput => ({ name: d.name, options: structuredClone(d.options), recipients: [...d.recipients] })

/** The report's settings: what it covers (one template, its sections switched on or off) and when and to whom it goes. */
export default function SettingsTab() {
  const def = useDefinition()
  return <QueryState query={def}>{(d) => <SettingsForm key={d.updated_at} def={d} />}</QueryState>
}

function SettingsForm({ def }: { def: ReportDefinition }) {
  const { t } = useTranslation('reports')
  const admin = useCan('admin')
  const save = useSaveDefinition()
  const [f, setF] = useState<ReportDefinitionInput>(() => input(def))
  const sched = useSchedule(def.schedule_key)
  const follows = sched.data?.enabled ? FOLLOWS[sched.data.rule.freq] : undefined
  const [email, setEmail] = useState('')
  const [emailErr, setEmailErr] = useState('')
  const [nameErr, setNameErr] = useState('')
  const [secErr, setSecErr] = useState('')
  const newChannel = useNewChannel('email')
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const dirty = JSON.stringify(f) !== JSON.stringify(input(def))
  const opt = <K extends keyof ReportOptions>(k: K, v: ReportOptions[K]) => { setF((p) => ({ ...p, options: { ...p.options, [k]: v } })); save.reset() }
  const sec = (k: keyof ReportOptions['sections'], v: boolean) => { setSecErr(''); opt('sections', { ...f.options.sections, [k]: v }) }

  // A refusal the box names by field is said at that field, with the address when it is one of the list.
  const field = save.error instanceof ApiError ? String(save.error.details.field ?? '') : ''
  const badIndex = /^recipients\[(\d+)\]$/.exec(field)?.[1]
  const savedEmailErr = badIndex !== undefined && f.recipients[Number(badIndex)] !== undefined ? t('settings.badSaved', { email: f.recipients[Number(badIndex)] }) : ''
  const shownNameErr = nameErr || (field === 'name' ? (save.error as Error).message : '')
  const shownSecErr = secErr || (field === 'options.sections' ? (save.error as Error).message : '')
  const fieldShown = !!savedEmailErr || field === 'name' || field === 'options.sections'

  function add() {
    const e = email.trim().toLowerCase()
    if (e.length > EMAIL_MAX) { setEmailErr(t('settings.longEmail', { max: EMAIL_MAX, count: e.length })); return }
    if (!EMAIL_RE.test(e)) { setEmailErr(t('settings.badEmail')); return }
    if (f.recipients.includes(e)) { setEmailErr(t('settings.dupEmail')); return }
    if (f.recipients.length >= MAX_RECIPIENTS) { setEmailErr(t('settings.full')); return }
    setF((p) => ({ ...p, recipients: [...p.recipients, e] })); setEmail(''); setEmailErr(''); save.reset()
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (email.trim() !== '') { setEmailErr(t('settings.pending')); return }
    if (f.name.trim() === '') { setNameErr(t('settings.nameRequired')); return }
    if (!SECTIONS.some((k) => f.options.sections[k])) { setSecErr(t('settings.noSections')); return }
    save.mutate({ ...f, name: f.name.trim() }, { onSuccess: () => toast.success(t('settings.saved')) })
  }

  return (
    <>
      {!admin ? <p role="status" className="mb-4 text-meta text-muted">{t('settings.readOnly')}</p> : null}
      {/* outside the form: the schedule saves through its own dialog, whose submit must not bubble (through the portal) into this form */}
      <div className="max-w-3xl">
        <Section id="rep-schedule" title={t('settings.schedule')}>
          <ScheduleEditor ownerKey={def.schedule_key} name={t('settings.scheduleName')} runNow={false} />
        </Section>
      </div>
      <form noValidate onSubmit={submit} aria-label={t('page.settings')} className="grid max-w-3xl gap-2">
        <Section id="rep-content" title={t('settings.content')}>
          <div className="grid gap-5">
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label={t('settings.name')} htmlFor="rep-name" error={shownNameErr || undefined} className="sm:col-span-3">
                <Input id="rep-name" value={f.name} maxLength={80} disabled={!admin} aria-invalid={shownNameErr ? true : undefined}
                  onChange={(e) => { setF((p) => ({ ...p, name: e.target.value })); setNameErr(''); save.reset() }} />
              </Field>
              <Field label={t('settings.period')} htmlFor="rep-period" hint={follows ? t('settings.periodFollows') : undefined}>
                <Select id="rep-period" value={follows ?? f.options.period} disabled={!admin || !!follows} title={follows ? undefined : reason} onChange={(e) => opt('period', e.target.value as ReportOptions['period'])}>
                  {PERIODS.map((p) => <option key={p} value={p}>{t(`settings.periods.${p}`)}</option>)}
                </Select>
              </Field>
              <Field label={t('settings.grouping')} htmlFor="rep-grouping">
                <Select id="rep-grouping" value={f.options.grouping} disabled={!admin} title={reason} onChange={(e) => opt('grouping', e.target.value as ReportOptions['grouping'])}>
                  {(['device', 'cve'] as const).map((g) => <option key={g} value={g}>{t(`settings.groupings.${g}`)}</option>)}
                </Select>
              </Field>
            </div>
            <div className="grid gap-3">
              <Toggle id="rep-not-added" label={t('settings.notAdded')} info={t('settings.notAddedHint')} checked={f.options.include_not_added} disabled={!admin} onChange={(v) => opt('include_not_added', v)} />
              <Toggle id="rep-not-relevant" label={t('settings.notRelevant')} info={t('settings.notRelevantHint')} checked={f.options.include_not_relevant} disabled={!admin} onChange={(v) => opt('include_not_relevant', v)} />
              <Toggle id="rep-charts" label={t('settings.charts')} checked={f.options.charts} disabled={!admin} onChange={(v) => opt('charts', v)} />
            </div>
            <fieldset className="grid gap-2" aria-describedby={shownSecErr ? 'rep-sections-error' : undefined}>
              <legend className="mb-1 text-sm font-medium">{t('settings.sections')} <span className="font-normal text-muted">{t('settings.sectionsHint')}</span></legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {SECTIONS.map((k) => (
                  <div key={k} className="flex items-center gap-2">
                    <Checkbox id={`rep-sec-${k}`} checked={f.options.sections[k]} disabled={!admin} onCheckedChange={(v) => sec(k, v === true)} />
                    <Label htmlFor={`rep-sec-${k}`}>{t(`sr.section.${k}`)}</Label>
                  </div>
                ))}
              </div>
              {shownSecErr ? <p id="rep-sections-error" role="alert" className="text-meta text-danger">{shownSecErr}</p> : null}
            </fieldset>
          </div>
        </Section>

        <Section id="rep-recipients" title={t('settings.recipients')}>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Field label={t('settings.addRecipient')} htmlFor="rep-email" hint={t('settings.recipientsHint')} error={emailErr || savedEmailErr || undefined}>
                <div className="flex gap-2">
                  <Input id="rep-email" type="email" value={email} placeholder="name@company.com" disabled={!admin}
                    aria-invalid={emailErr || savedEmailErr ? true : undefined} aria-describedby={emailErr || savedEmailErr ? 'rep-email-error' : 'rep-email-hint'}
                    onChange={(e) => { setEmail(e.target.value); setEmailErr('') }} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
                  <Button onClick={add} disabled={!admin || email.trim() === ''} title={reason}>{t('settings.add')}</Button>
                </div>
              </Field>
              {f.recipients.length ? (
                <ul className="flex flex-wrap gap-2" aria-label={t('settings.list')}>
                  {f.recipients.map((e) => (
                    <li key={e} className="inline-flex items-center gap-1 rounded-sm border border-rule bg-surface py-0.5 pl-2 pr-1 text-sm">{e}
                      <button type="button" disabled={!admin} aria-label={t('settings.remove', { email: e })} className="rounded-sm p-1 text-muted hover:bg-sunken hover:text-ink disabled:opacity-50"
                        onClick={() => { setF((p) => ({ ...p, recipients: p.recipients.filter((x) => x !== e) })); save.reset() }}><X className="size-3.5" aria-hidden /></button>
                    </li>
                  ))}
                </ul>
              ) : <p className="text-sm text-muted">{t('settings.noRecipients')}</p>}
            </div>
            {admin ? <EmailChannelCheck button={newChannel.button(t('settings.setupChannel'))} /> : <p className="text-meta text-muted">{t('settings.channelByAdmin')}</p>}
          </div>
        </Section>

        {fieldShown ? null : <ActionError error={save.error} />}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={!admin || !dirty} busy={save.isPending} busyLabel={t('common:busy.saving')} title={reason}>{t('common:save')}</Button>
          {dirty ? <span role="status" className="text-meta text-warn">{t('settings.unsaved')}</span> : null}
        </div>
      </form>
      {/* outside the form: the channel form's submit must not bubble (through the portal) into this one */}
      {newChannel.dialogs}
    </>
  )
}

/** A switch and its label; what it means in detail is behind the label's info icon. */
function Toggle({ id, label, info, checked, disabled, onChange }: { id: string; label: string; info?: string; checked: boolean; disabled: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
      <span className="inline-flex items-center gap-1"><Label htmlFor={id}>{label}</Label>{info ? <InfoTip topic={label}>{info}</InfoTip> : null}</span>
    </div>
  )
}

/** Reports leave through the email channel: when none is set up, say so and set it up right here. */
function EmailChannelCheck({ button }: { button: React.ReactNode }) {
  const { t } = useTranslation('reports')
  const ch = useChannels({ retry: false })
  const none = !!ch.data && !ch.data.channels.some((c) => c.type === 'email' && c.configured && c.enabled)
  return none ? <Notice tone="warn" role="alert" className="mb-0" title={t('settings.noChannel')} actions={button} /> : null
}
