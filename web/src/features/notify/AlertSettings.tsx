import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, Section } from '@/components/common/PageHeader'
import { ScheduleEditor } from '@/components/schedule/ScheduleEditor'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { AlertTriggers } from './AlertTriggers'
import { useSaveRules } from './api'
import type { ChannelsResponse } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))

/** What the Settings tab reads from GET /notify/channels. */
type Rules = Pick<ChannelsResponse, 'quiet'>
type Settings = Pick<ChannelsResponse, 'quiet' | 'triggers' | 'vulnerability_trigger'>

/** Quiet hours: one form, for every channel. */
function RulesForm({ init }: { init: Rules }) {
  const { t } = useTranslation('notify')
  const isAdmin = useCan('admin')
  const save = useSaveRules()
  const [quiet, setQuiet] = useState(init.quiet)
  const [error, setError] = useState<string | null>(null)
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    save.mutate({ quiet }, { onSuccess: () => toast.success(t('rules.saved')), onError: (er) => setError(errMsg(er)) })
  }
  return (
    <form onSubmit={submit} className="grid max-w-2xl gap-8" noValidate>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {/* /settings/channels?tab=settings#quiet-hours (NotSentFix of a held incident) lands here */}
      <fieldset id="quiet-hours" disabled={!isAdmin} className="grid gap-3 border-0 p-0">
        <legend className="mb-1 flex items-center gap-1 text-base font-semibold">{t('rules.quiet.title')}<InfoTip topic={t('rules.quiet.title')}>{t('rules.quiet.descriptionInfo')}</InfoTip></legend>
        <p className="text-meta text-muted">{t('rules.quiet.description')}</p>
        <div className="flex items-center gap-3"><Switch id="q-on" checked={quiet.enabled} onCheckedChange={(v) => setQuiet({ ...quiet, enabled: v })} /><Label htmlFor="q-on">{t('rules.quiet.enabled')}</Label></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('rules.quiet.from')} htmlFor="q-from"><Input id="q-from" type="time" value={quiet.from} onChange={(e) => setQuiet({ ...quiet, from: e.target.value })} /></Field>
          <Field label={t('rules.quiet.to')} htmlFor="q-to"><Input id="q-to" type="time" value={quiet.to} onChange={(e) => setQuiet({ ...quiet, to: e.target.value })} /></Field>
        </div>
        {quiet.enabled && quiet.from && quiet.to && quiet.from !== quiet.to ? <p className="text-meta" role="status">{quiet.from > quiet.to ? t('rules.quiet.overnight', { from: quiet.from, to: quiet.to }) : t('rules.quiet.sameDay', { from: quiet.from, to: quiet.to })}</p> : null}
        <div className="flex items-center gap-2"><Checkbox id="q-crit" checked={quiet.allow_critical} onCheckedChange={(c) => setQuiet({ ...quiet, allow_critical: c === true })} /><Label htmlFor="q-crit" className="font-normal">{t('rules.quiet.allowCritical')}</Label></div>
      </fieldset>
      <div><Button type="submit" variant="primary" disabled={!isAdmin} busy={save.isPending} busyLabel={t('common:busy.saving')} title={isAdmin ? undefined : t('channels.needRole')}>{t('rules.save')}</Button></div>
    </form>
  )
}

/** The core/schedule owner key of the daily summary (notify ScheduleOwner): its switch and time. */
export const SUMMARY_SCHEDULE = 'notify.summary'

/** Settings › Alert channels › Settings: how alerts go out on every channel. Each block is a Section of its own: first what sends an
 *  alert at all (only findings exploited in the wild) and the daily summary of the rest, then quiet hours, then the triggers. */
export function AlertSettings({ quiet, triggers, vulnerability_trigger }: Settings) {
  const { t } = useTranslation('notify')
  return (
    <>
      {/* /settings/channels?tab=settings#daily-summary (NotSentFix of a finding that is not exploited) lands here */}
      <Section id="daily-summary" title={t('summary.title')} description={t('summary.description')} info={t('summary.descriptionInfo')}>
        <ScheduleEditor ownerKey={SUMMARY_SCHEDULE} name={t('summary.scheduleName')} runNow={false} />
      </Section>
      <Section id="alert-rules" title={t('alertSettings.rules.title')} description={t('alertSettings.rules.description')}>
        <RulesForm init={{ quiet }} />
      </Section>
      {/* /settings/channels?tab=settings#triggers (NotSentFix of an alert its trigger held back) lands here */}
      <Section id="triggers" title={t('triggers.title')} description={t('triggers.description')} info={t('triggers.descriptionInfo')}>
        <AlertTriggers init={triggers} vuln={vulnerability_trigger} />
      </Section>
    </>
  )
}
