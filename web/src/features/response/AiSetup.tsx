import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { CircleCheck, CircleDashed } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useProfiles, useSaveAssignments } from '@/features/ai/api'
import { errText, useAiAssignments, useBlocklist, useCatalog, usePlans, useSaveAction, useSaveSettings, useSettings, useTriggers } from './api'
import { EnableDialog } from './ResponseSettings'
import type { Blocklist, CatalogAction, PlannerStatus, SettingsView, TriggerInfo } from './types'

// "Let the AI propose actions" (item 20, S-RESP-2, D-513): one page of the five things the plan job needs before an AI proposal reaches the
// inbox, each with its status, what leaves the box (PRIVACY.md rows 3, 5, 12), and the same control the settings screens have. Nothing here
// lets the AI approve, enable or widen anything: every step is a person's setting, every action still needs a person to approve it.

/** The plan job proposes only actions whose every value is the device's address (aboutTheDevice, D-181). */
const aiOfferable = (a: CatalogAction) => a.params.length > 0 && a.params.every((p) => p === 'ip')
/** The only trigger the box asks the AI about today: the plan job of critical findings (modules/response/planner.go, D-310). */
const ASKED = ['finding']
const link = 'text-accent underline underline-offset-4'

function Step({ n, title, done, optional, children, leaves }: { n: number; title: string; done: boolean | undefined; optional?: boolean; children: ReactNode; leaves: string }) {
  const { t } = useTranslation('response')
  const Icon = done ? CircleCheck : CircleDashed
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 border-t border-rule py-4 first:border-t-0 first:pt-0">
      <Icon className={`mt-0.5 size-5 ${done ? 'text-ok' : 'text-muted'}`} aria-hidden />
      <div className="grid min-w-0 gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">{n}. {title}</h3>
          <Chip tone={done ? 'ok' : done === undefined ? 'off' : 'warn'}>{done ? t('setup.done') : done === undefined ? t('setup.unknown') : optional ? t('setup.optional') : t('setup.todo')}</Chip>
        </div>
        {children}
        <p className="text-[12px] text-muted"><span className="font-medium">{t('setup.leaves')}</span> {leaves}</p>
      </div>
    </li>
  )
}

function ProfileStep({ done, admin, ready }: { done: boolean; admin: boolean; ready: boolean }) {
  const { t } = useTranslation('response')
  const qc = useQueryClient()
  const aiOn = useModuleEnabled('ai')
  const ask = admin && aiOn === true
  const profiles = useProfiles(ask)
  const assign = useAiAssignments(ask)
  const save = useSaveAssignments()
  const slot = assign.data?.jobs['response-plan']
  const usable = (profiles.data?.items ?? []).filter((p) => p.usable)
  const allowed = (location: string) => !assign.data?.internal_only || location === 'internal' // the server checks it too (INV-3 of ai)
  const pick = (id: string) => {
    if (!assign.data) return
    const fallback = slot?.fallback && slot.fallback !== id ? slot.fallback : null
    save.mutate({ ...assign.data, jobs: { ...assign.data.jobs, 'response-plan': { primary: id || null, fallback: id ? fallback : null } } }, {
      onSuccess: () => { toast.success(t('setup.profile.saved')); void qc.invalidateQueries({ queryKey: ['response'] }) }, onError: (e) => toast.error(errText(e)),
    })
  }
  return (
    <Step n={5} title={t('setup.profile.title')} done={done} leaves={t('setup.profile.leaves')}>
      <p className="text-[13px]">{t('setup.profile.body')}</p>
      {aiOn === false ? <p className="text-[13px]">{t('setup.profile.aiOff')} {admin ? <Link className={link} to="/settings/modules">{t('setup.toModules')}</Link> : null}</p>
        : !admin ? <p className="text-[13px] text-muted">{t('setup.adminDoes')}</p>
        : profiles.data && !usable.length ? <p className="text-[13px]">{t('setup.profile.none')} <Link className={link} to="/settings/ai">{t('setup.profile.toAi')}</Link></p>
        : assign.data ? (
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="setup-profile" className="text-[13px] text-muted">{t('setup.profile.label')}</label>
            <Select id="setup-profile" className="h-8 w-full min-w-0 sm:w-auto sm:min-w-[13rem]" value={slot?.primary ?? ''} disabled={!ready || save.isPending} aria-describedby={ready ? undefined : 'setup-profile-wait'} onChange={(e) => pick(e.target.value)}>
              <option value="">{t('setup.profile.noneChosen')}</option>
              {usable.map((p) => <option key={p.id} value={p.id} disabled={!allowed(p.location)}>{p.name} ({p.model}){allowed(p.location) ? '' : ` · ${t('setup.profile.cloudBlocked')}`}</option>)}
            </Select>
            <Link className={`text-[13px] ${link}`} to="/settings/ai">{t('setup.profile.toAi')}</Link>
            {/* a plan written before steps 1, 2 and 4 is never sent (one plan per finding, D-314): the setup waits for them; the AI page still sets it */}
            {ready ? null : <p id="setup-profile-wait" className="basis-full text-[13px] text-warn">{t('setup.profile.wait')}</p>}
          </div>
        ) : null}
    </Step>
  )
}

function ConnectStep({ cat, pulled, done, admin }: { cat: CatalogAction[]; pulled: Blocklist['last_fetch'] | undefined; done: boolean | undefined; admin: boolean }) {
  const { t } = useTranslation('response')
  const ready = cat.filter((a) => a.device && aiOfferable(a) && a.available)
  return (
    <Step n={1} title={t('setup.connect.title')} done={done} leaves={t('setup.connect.leaves')}>
      <p className="text-[13px]">{t('setup.connect.body')}</p>
      <ul className="ml-5 list-disc text-[13px]">
        <li>{ready.length ? t('setup.connect.ready', { names: ready.map((a) => a.name).join(', ') }) : t('setup.connect.noneReady')}{' '}
          {admin ? <><Link className={link} to="/settings/connections">{t('setup.connect.toConnections')}</Link>{' · '}<Link className={link} to="/response?tab=actions">{t('setup.connect.toActions')}</Link></> : null}</li>
        <li>{pulled ? t('setup.connect.pulled', { time: fmtDateTime(pulled.at), from: pulled.from }) : t('setup.connect.blocklist')}{' '}
          {admin ? <Link className={link} to="/response?tab=actions">{t('setup.connect.toBlocklist')}</Link> : null}</li>
      </ul>
    </Step>
  )
}

function ChooseStep({ cat, s, triggers, done, admin }: { cat: CatalogAction[]; s: SettingsView | undefined; triggers: TriggerInfo[]; done: boolean; admin: boolean }) {
  const { t } = useTranslation('response')
  const save = useSaveSettings()
  const act = useSaveAction()
  const finding = triggers.find((x) => x.id === 'finding')
  const offer = cat.filter(aiOfferable)
  const setFinding = (on: boolean) => {
    if (!s) return
    const ai = { triggers: on ? [...new Set([...s.ai.triggers, 'finding' as const])] : s.ai.triggers.filter((x) => x !== 'finding'), budget_hour: s.ai.budget_hour, budget_day: s.ai.budget_day }
    save.mutate({ max_per_hour: s.max_per_hour, expiry_min: s.expiry_min, approval_channels: s.approval_channels, breaker_max_per_hour: s.breaker_max_per_hour, multi_target_max: s.multi_target_max, maintenance: s.maintenance, ai },
      { onSuccess: () => toast.success(t('common:saved')), onError: (e) => toast.error(errText(e)) })
  }
  return (
    <Step n={2} title={t('setup.choose.title')} done={done} leaves={t('setup.choose.leaves')}>
      <p className="text-[13px]">{t('setup.choose.body')}</p>
      <div className="flex items-start gap-2.5">
        <Checkbox id="setup-finding" checked={!!finding?.ai_allowed} disabled={!admin || !s || save.isPending} onCheckedChange={(v) => setFinding(v === true)} />
        <label htmlFor="setup-finding" className="text-sm">{t('setup.choose.finding')}</label>
      </div>
      {offer.length ? (
        <ul className="grid gap-2">
          {offer.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
              <Switch id={`setup-ai-${a.id}`} aria-label={t('catalog.aiMayFor', { name: a.name })} checked={a.ai_may_propose} disabled={!admin || act.isPending}
                onCheckedChange={(v) => act.mutate({ id: a.id, input: { ai_may_propose: v } }, { onError: (e) => toast.error(errText(e)) })} />
              <label htmlFor={`setup-ai-${a.id}`} className="font-medium">{a.name}</label>
              <span className="text-muted">{!a.enabled ? <>{t('setup.choose.off')} {admin ? <Link className={link} to="/response?tab=actions">{t('setup.choose.toActions')}</Link> : null}</>  : !a.available ? a.unavailable_reason : a.device ? t('setup.choose.via', { connection: a.connection }) : t('setup.choose.publicOnly')}</span>
            </li>
          ))}
        </ul>
      ) : <p className="text-[13px] text-muted">{t('setup.choose.noAction')}</p>}
      {!admin ? <p className="text-[13px] text-muted">{t('setup.adminDoes')}</p> : null}
    </Step>
  )
}

function ApproverStep({ s }: { s: SettingsView | undefined }) {
  const { t } = useTranslation('response')
  const chosen = s ? s.channels.filter((c) => c.ready && s.approval_channels.includes(c.type)) : []
  const done = s ? chosen.some((c) => c.linked > 0) : undefined
  return (
    <Step n={3} title={t('setup.approvers.title')} done={done} optional leaves={t('setup.approvers.leaves')}>
      <p className="text-[13px]">{t('setup.approvers.body')}</p>
      {!s ? <p className="text-[13px] text-muted">{t('setup.adminDoes')}</p> : (
        <p className="text-[13px]">
          {chosen.length ? t('setup.approvers.chosen', { channels: chosen.map((c) => `${c.label} (${t('form.linkedCount', { linked: c.linked, count: c.approvers })})`).join(', ') }) : t('setup.approvers.none')}{' '}
          <Link className={link} to="/response?tab=settings">{t('setup.approvers.toSettings')}</Link>{' · '}<Link className={link} to="/settings/channels">{t('form.toChannels')}</Link>
        </p>
      )}
    </Step>
  )
}

function ExecutionStep({ on, admin }: { on: boolean; admin: boolean }) {
  const { t } = useTranslation('response')
  const [open, setOpen] = useState(false)
  return (
    <Step n={4} title={t('setup.execution.title')} done={on} leaves={t('setup.execution.leaves')}>
      <p className="text-[13px]">{t('setup.execution.body')}</p>
      {on ? null : admin ? <div><Button variant="danger" size="sm" onClick={() => setOpen(true)}>{t('setup.execution.button')}</Button></div> : <p className="text-[13px] text-muted">{t('setup.adminDoes')}</p>}
      {admin ? <EnableDialog open={open} onOpenChange={setOpen} /> : null}
    </Step>
  )
}

/** What the setup needs, read once for the steps and for the inbox (which folds the steps away when the required ones are done). */
function useSetup() {
  const admin = useCan('admin')
  const plans = usePlans()
  const settings = useSettings(admin)
  const triggers = useTriggers()
  const catalog = useCatalog()
  const blocklist = useBlocklist(admin)
  if (!plans.data || !triggers.data || !catalog.data) return null
  const cat = catalog.data.items
  const ready = (a: CatalogAction) => aiOfferable(a) && a.enabled && a.available
  const pulled = blocklist.data?.last_fetch
  // Only a device action counts: the block list never publishes a LAN address, so the plan job never offers it for a device on your
  // network (offeredFor, D-469), and a critical finding there would get a plan with no action for good. Switching the action on is step 2.
  const device = cat.some((a) => a.device && aiOfferable(a) && a.available)
  const connected = device ? true : admin ? false : undefined // the block list read is admin-only: a non-admin cannot tell more
  const chosen = !!triggers.data.items.find((x) => x.id === 'finding')?.ai_allowed && cat.some((a) => a.device && ready(a) && a.ai_may_propose)
  const required = [plans.data.ai_available, connected === true, chosen, plans.data.execution]
  return { admin, plans: plans.data, s: settings.data, triggers: triggers.data.items, cat, pulled, connected, chosen, n: required.filter(Boolean).length, of: required.length }
}

/** Required steps done (undefined while loading). */
export function useSetupDone(): boolean | undefined {
  const x = useSetup()
  return x ? x.n === x.of : undefined
}

/** The five steps and how many are done; `compact` folds them under one line (the inbox has requests). */
export function AiSetup({ compact = false }: { compact?: boolean }) {
  const { t } = useTranslation('response')
  const x = useSetup()
  if (!x) return null
  const steps = (
    <ol className="grid">
      {/* The profile is last: it starts the AI, which writes one plan per finding and sends its actions only if steps 1, 2 and 4 are done at
          that moment (D-314), so the setup offers it only after steps 1, 2 and 4; a plan written earlier stays in the plan list, where a person asks for approval (D-513). */}
      <ConnectStep cat={x.cat} pulled={x.pulled} done={x.connected} admin={x.admin} />
      <ChooseStep cat={x.cat} s={x.s} triggers={x.triggers} done={x.chosen} admin={x.admin} />
      <ApproverStep s={x.s} />
      <ExecutionStep on={x.plans.execution} admin={x.admin} />
      <ProfileStep done={x.plans.ai_available} admin={x.admin} ready={x.connected === true && x.chosen && x.plans.execution} />
    </ol>
  )
  const title = t('setup.title')
  const count = t('setup.count', { n: x.n, of: x.of })
  if (compact) {
    return (
      <details className="mb-6 rounded-md border border-rule bg-surface px-4 py-3">
        <summary className="cursor-pointer text-sm font-medium">{title} <span className="font-normal text-muted">· {count}</span></summary>
        <div className="mt-4">{steps}</div>
      </details>
    )
  }
  return (
    <Section id="ai-setup" title={title} description={<>{t('setup.description')} <span className="font-medium">{count}</span></>} stories={['S-RESP-2']}>
      <Panel className="p-4">{steps}</Panel>
    </Section>
  )
}

const OUTCOME_TONE: Record<PlannerStatus['findings'][number]['outcome'], Tone> = {
  proposed: 'ok', noted: 'accent', refused: 'warn', not_sent: 'warn', no_action: 'warn', plan_refused: 'warn', ai_failed: 'danger', ai_unavailable: 'danger', has_plan: 'off', backed_off: 'off', later: 'off',
}

/** Why the inbox is empty: what the plan job did on its last run, and which triggers the AI may use (D-119). */
export function InboxWhy() {
  const { t } = useTranslation('response')
  const plans = usePlans()
  const triggers = useTriggers()
  if (!plans.data || !triggers.data) return null
  const p = plans.data.planner
  const time = p.ran_at ? fmtDateTime(p.ran_at) : ''
  const look = !p.ran_at ? t('why.notYet') : p.blocked ? t(`why.blocked.${p.blocked}`, { time }) : t('why.looked', { time, count: p.considered, asked: p.asked, proposed: p.proposed })
  const trig = (x: TriggerInfo) => !x.ai_evidence.length ? t('why.trigger.never') : !x.ai_allowed ? t('why.trigger.notAllowed') : ASKED.includes(x.id) ? t('why.trigger.asked') : t('why.trigger.nobodyAsks')
  return (
    <Section id="inbox-why" title={t('why.title')} stories={['S-RESP-2']}>
      <Panel className="grid gap-4 p-4 text-sm">
        <div className="grid gap-2">
          <p>{look}</p>
          {p.findings.length ? (
            <ul className="grid gap-2">
              {p.findings.map((f) => (
                <li key={f.finding_id} className="grid gap-0.5">
                  <p className="flex flex-wrap items-center gap-2"><Link className={link} to={`/findings/${f.finding_id}`}>{f.cve}</Link><span>{t('why.on', { device: f.asset_name })}</span><Chip tone={OUTCOME_TONE[f.outcome]}>{t(`why.outcome.${f.outcome}`)}</Chip></p>
                  <p className="text-[13px] text-muted">{f.reason}</p>
                </li>
              ))}
            </ul>
          ) : null}
          {p.ran_at && !p.blocked && !p.considered ? <p className="text-[13px] text-muted">{t('why.noFindings')}</p> : null}
        </div>
        <div className="grid gap-1">
          <h3 className="text-sm font-semibold">{t('why.triggers')}</h3>
          <p className="text-[13px] text-muted">{t('why.triggersBody')}</p>
          <ul className="grid gap-1 text-[13px]">
            {triggers.data.items.map((x) => <li key={x.id}><span className="font-medium">{x.name}</span>: {trig(x)}</li>)}
          </ul>
          <p className="text-[13px] text-muted">{t('why.rules')} <Link className={link} to="/response?tab=rules">{t('why.toRules')}</Link></p>
        </div>
      </Panel>
    </Section>
  )
}
