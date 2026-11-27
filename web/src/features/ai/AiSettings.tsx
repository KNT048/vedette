import { lazy, Suspense, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Card } from '@/components/common/Card'
import { CreatableSelect, type CreateDialogProps, type SelectOption } from '@/components/common/CreatableSelect'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { DataTable } from '@/components/common/DataTable'
import { EmptyState, Loading, QueryState } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDate, fmtDateTime, fmtNumber } from '@/lib/format'
import { useInstallKind } from '@/lib/modules'
import { notOffered } from '@/lib/v1'
import { useCan } from '@/lib/session'
import { fetchSuggestion, useActivitySettings, useAiConfig, useAssignments, useProfiles, useRemoveProfile, useSaveActivitySettings, useSaveAssignments, useSaveConfig, useListModels, useSaveProfile, useTestProfile } from './api'
import { ActionError } from './parts'
import { BudgetUse, budgetPct } from './Budget'
import type { AiConfigView, AiJob, AiProfile, AiTier, ApiStyle, Assignments, ProfileInput, ProfileKind, TestResult } from './types'

const RulesTab = lazy(() => import('./harness/RulesTab'))
const MemoryTab = lazy(() => import('./harness/MemoryTab'))
const SkillsTab = lazy(() => import('./harness/SkillsTab'))
const KnowledgeTab = lazy(() => import('./harness/KnowledgeTab'))
const ConnectionsMoved = lazy(() => import('./harness/ConnectionsMoved'))
const HooksTab = lazy(() => import('./harness/HooksTab'))
// docs/UI.md §4: at most 6 tabs. Connections moved to core: an old ?tab=connections link shows where they are now.
const TABS = ['profiles', 'rules', 'memory', 'skills', 'knowledge', 'hooks'] as const
type Tab = (typeof TABS)[number]
const HARNESS: Record<Exclude<Tab, 'profiles'>, React.LazyExoticComponent<() => React.JSX.Element>> = { rules: RulesTab, memory: MemoryTab, skills: SkillsTab, knowledge: KnowledgeTab, hooks: HooksTab }

// Suggested addresses and models, checked against the official documentation on 2026-11-06. Model names change over time, so the user can edit them.
//  Anthropic: platform.claude.com/docs/en/about-claude/models/overview (claude-haiku-5-5, API https://api.anthropic.com)
//  OpenAI:    developers.openai.com/api/docs/models (gpt-6-luna is the small model), API https://api.openai.com/v1
//  Gemini:    aistudio.google.com/docs/models (gemini-3.6-flash), REST https://generativelanguage.googleapis.com (the client adds /v1beta)
//  OpenCode:  opencode.ai/docs/zen: Chat Completions at https://opencode.ai/inference/openai/v1, model glm-5.3-flash (cheap, tools); a preset on kind custom
//  Ollama:    docs.ollama.com/api/openai-compatibility (port 11434, example model qwen3:8b); vLLM port 8000. Core always runs in a container (also the install.sh install,
//             rootful Podman): Ollama on the same machine is host.containers.internal, not localhost. A container-only install
//             (the customer's Docker or Podman) cannot be sure to have that name: it is not pre-filled, and the hint says to use the machine's LAN IP
// The provider choice of the dialog: the five kinds and the OpenCode preset, which is a Custom profile (no new kind).
type Preset = ProfileKind | 'opencode'
const PRESETS: Preset[] = ['anthropic', 'openai', 'gemini', 'opencode', 'openai-compatible', 'custom']
const OPENCODE_URL = 'https://opencode.ai/inference/openai/v1'
const kindOf = (p: Preset): ProfileKind => (p === 'opencode' ? 'custom' : p)
const presetOf = (p: AiProfile | null): Preset => (!p ? 'anthropic' : p.kind === 'custom' && p.base_url === OPENCODE_URL ? 'opencode' : p.kind)
const DEFAULTS: Record<Preset, { base_url: string; model: string; api_style: ApiStyle; location: 'internal' | 'cloud'; name: string }> = {
  anthropic: { base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', api_style: 'anthropic', location: 'cloud', name: 'Claude' },
  openai: { base_url: 'https://api.openai.com/v1', model: 'gpt-6-luna', api_style: 'openai', location: 'cloud', name: 'OpenAI' },
  gemini: { base_url: 'https://generativelanguage.googleapis.com', model: 'gemini-3.6-flash', api_style: 'gemini', location: 'cloud', name: 'Gemini' },
  opencode: { base_url: OPENCODE_URL, model: 'glm-5.3-flash', api_style: 'openai', location: 'cloud', name: 'OpenCode' },
  'openai-compatible': { base_url: 'http://host.containers.internal:11434/v1', model: 'qwen3:8b', api_style: 'openai', location: 'internal', name: 'Local model' },
  custom: { base_url: '', model: '', api_style: 'openai', location: 'cloud', name: '' },
}
const TIERS: AiTier[] = ['min', 'med', 'max']
const JOBS: { id: AiJob; data: 'internal' | 'public' }[] = [
  { id: 'explain-finding', data: 'internal' }, { id: 'mitigation-config', data: 'internal' }, { id: 'ask-my-data', data: 'internal' }, { id: 'log-digest', data: 'internal' }, { id: 'log-investigate', data: 'internal' },
  { id: 'weekly-report', data: 'internal' }, { id: 'pdpl-assessment', data: 'internal' }, { id: 'cve-news', data: 'public' }, { id: 'translate-advisory', data: 'public' }, { id: 'response-plan', data: 'internal' },
]
// The response plan is set on the response module's own page; no row for it while this build does not offer that module
const shownJobs = () => (notOffered('response') ? JOBS.filter((j) => j.id !== 'response-plan') : JOBS)
const hostOf = (u: string) => { try { return new URL(u).host } catch { return u || '…' } }
const usable = (p: AiProfile) => p.usable

/** Settings, AI assistant (S-AI-1, S-AI-4, S-AI-7): tabs for profiles and routing, then the AI harness (rules, memory, skills, knowledge, connections, hooks). The key is entered one way only: after saving, only its last 4 characters remain (SYS-4). */
export default function AiSettings() {
  const { t } = useTranslation('ai')
  const cfg = useAiConfig()
  const [params] = useSearchParams()
  const moved = params.get('tab') === 'connections'
  const profiles = useProfiles()
  // "set up" is not the whole truth when no saved profile passed its last test (S-AI-1)
  const allFailed = (c: AiConfigView) => c.configured && !!profiles.data?.items.length && profiles.data.items.every((p) => p.last_test && !p.last_test.ok)
  return (
    <div className="grid max-w-4xl grid-cols-[minmax(0,1fr)] gap-2">
      <QueryState query={cfg}>
        {(c) => (
          <>
            <PageHeader title={t('common:shell.aiSettings')} meta={allFailed(c) ? t('settings.statusAllFailed') : c.configured ? t('settings.statusOn') : t('settings.statusOff')} info={allFailed(c) ? t('settings.statusAllFailedInfo') : undefined} />
            {moved ? <Suspense fallback={null}><ConnectionsMoved /></Suspense> : null}
            {/* each lazy panel has its own Suspense (FRONTEND §3) */}
            <PageTabs label={t('harness.tabs.label')} tabs={TABS.map((id) => {
              const Harness = id === 'profiles' ? null : HARNESS[id]
              return { id, label: t(`harness.tabs.${id}`), panel: Harness ? <Suspense fallback={<Loading />}><Harness /></Suspense> : <ProfilesTab cfg={c} /> }
            })} />
          </>
        )}
      </QueryState>
    </div>
  )
}

function ProfilesTab({ cfg }: { cfg: AiConfigView }) {
  const profiles = useProfiles()
  const assign = useAssignments()
  return (
    <>
      <Flow profiles={profiles.data?.items ?? []} />
      <QueryState query={profiles}>{(p) => <ProfilesSection profiles={p.items} assign={assign.data} />}</QueryState>
      <QueryState query={assign}>{(a) => <AssignSection profiles={profiles.data?.items ?? []} assign={a} />}</QueryState>
      <TierForm key={`${cfg.tier}|${cfg.monthly_budget}|${cfg.redact_pii}`} cfg={cfg} />
      <RetentionForm />
    </>
  )
}

function Flow({ profiles }: { profiles: AiProfile[] }) {
  const { t } = useTranslation('ai')
  const cloud = [...new Set(profiles.filter((p) => p.location === 'cloud').map((p) => hostOf(p.base_url)))]
  return (
    <Section title={t('settings.flow.title')} stories={['S-AI-1']} info={<><p>{cloud.length ? t('settings.flow.remoteInfo') : t('settings.flow.noneRemoteInfo')}</p><p>{t('settings.flow.rules')}</p></>}>
      <Card className="grid gap-2 text-sm">
        <p>{cloud.length ? t('settings.flow.remote', { hosts: cloud.join(', ') }) : t('settings.flow.noneRemote')}</p>
        {/* Legal risk (Vietnam PDPL cross-border transfer): one visible line, the law and what to do behind the ⓘ (#824) */}
        {cloud.length ? <div className="flex items-center gap-1"><p>{t('settings.flow.abroad')}</p><InfoTip topic={t('settings.flow.abroadTopic')}>{t('settings.flow.abroadInfo')}</InfoTip></div> : null}
      </Card>
    </Section>
  )
}

// ---------- AI profiles
function ProfilesSection({ profiles, assign }: { profiles: AiProfile[]; assign: Assignments | undefined }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const test = useTestProfile()
  const [edit, setEdit] = useState<AiProfile | 'new' | null>(null)
  const [del, setDel] = useState<AiProfile | null>(null)
  const [result, setResult] = useState<{ name: string; ok?: TestResult; error?: string } | null>(null)
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })

  function runTest(p: AiProfile) {
    setResult(null)
    test.mutate({ id: p.id, name: p.name, kind: p.kind, api_style: p.api_style, base_url: p.base_url, model: p.model, location: p.location }, {
      onSuccess: (r) => setResult({ name: p.name, ok: r }),
      onError: (e) => {
        setResult({ name: p.name, error: e instanceof Error ? e.message : String(e) })
        // #847: the saved key was not restored; the key is entered again right here, in Edit, which opens on the key field
        if (e instanceof ApiError && e.code === 'secret_lost') setEdit(p)
      },
    })
  }
  const Actions = (p: AiProfile) => (
    <span className="flex flex-wrap gap-2">
      <Button size="sm" onClick={() => runTest(p)} disabled={!admin || test.isPending} busy={test.isPending && test.variables?.id === p.id} busyLabel={t('common:busy.testing')} title={reason} aria-label={t('profiles.testNamed', { name: p.name })}>{t('profiles.test')}</Button>
      <Button size="sm" onClick={() => setEdit(p)} disabled={!admin} title={reason} aria-label={t('profiles.editNamed', { name: p.name })}>{t('profiles.edit')}</Button>
      <Button size="sm" onClick={() => setDel(p)} disabled={!admin} title={reason} aria-label={t('profiles.removeNamed', { name: p.name })}>{t('profiles.remove')}</Button>
    </span>
  )
  const keyText = (p: AiProfile) => p.key_lost ? t('profiles.keyLost') : p.key_last4 ? t('profiles.keyEnds', { last4: p.key_last4 }) : p.location === 'internal' ? t('profiles.noKeyNeeded') : t('profiles.keyMissing')
  const lost = profiles.filter((p) => p.key_lost)
  const loc = (p: AiProfile) => <Chip tone={p.location === 'internal' ? 'ok' : 'off'}>{t(`profiles.location.${p.location}`)}</Chip>
  const lastTest = (p: AiProfile) => !p.last_test ? <span className="text-muted">{t('profiles.lastNever')}</span>
    : p.last_test.ok ? <span className="text-ok">{t('profiles.lastOk', { time: fmtDateTime(p.last_test.at) })}</span>
      : <span className="font-medium text-danger">{t('profiles.lastFail', { time: fmtDateTime(p.last_test.at), reason: p.last_test.detail })}</span>
  return (
    <Section id="ai-profiles" title={t('profiles.title')} description={t('profiles.description')} info={t('profiles.descriptionInfo')} stories={['S-AI-1']}
      actions={<Button variant="primary" onClick={() => setEdit('new')} disabled={!admin} title={reason}>{t('profiles.add')}</Button>}>
      {/* #847: a key that was not restored with the backup. Nothing is sent to the profile until the key is entered again, right here. */}
      {lost.map((p) => (
        <Notice key={p.id} tone="danger" role="status" title={t('profiles.lostTitle', { name: p.name })}
          actions={<Button size="sm" onClick={() => setEdit(p)} disabled={!admin} title={reason}>{t('profiles.lostAction')}</Button>}>
          {t('profiles.lostBody')}
        </Notice>
      ))}
      {profiles.length === 0 ? (
        <EmptyState title={t('profiles.empty')} info={t('profiles.emptyBodyInfo')} action={<Button variant="primary" onClick={() => setEdit('new')} disabled={!admin} title={reason}>{t('profiles.add')}</Button>}>{t('profiles.emptyBody')}</EmptyState>
      ) : (
        <DataTable<AiProfile> urlKey="ai-profiles" caption={t('profiles.caption')} data={profiles}
          mobileRow={(p) => (
            <div className="grid gap-1.5 text-sm">
              <p className="flex flex-wrap items-center gap-2 font-medium">{p.name} {loc(p)}</p>
              <p className="text-muted">{t(`profiles.kind.${p.kind}`)}, {p.model}</p>
              <p className="text-muted">{keyText(p)}. {t('profiles.col.usage')}: <BudgetUse used={p.used_month} budget={p.monthly_budget} /></p>
              <p>{lastTest(p)}</p>
              {Actions(p)}
            </div>
          )}
          columns={[
            { id: 'name', header: t('profiles.col.name'), accessorKey: 'name', cell: ({ row }: { row: { original: AiProfile } }) => <span className="grid justify-items-start gap-1"><span className="font-medium">{row.original.name}</span><span className="text-caption text-muted">{t(`profiles.kind.${row.original.kind}`)}</span>{loc(row.original)}</span> },
            { id: 'model', header: t('profiles.col.model'), accessorKey: 'model', cell: ({ row }: { row: { original: AiProfile } }) => <span className="whitespace-nowrap">{row.original.model}</span> },
            { id: 'key', header: t('profiles.col.key'), accessorFn: keyText },
            { id: 'lastTest', header: t('profiles.col.lastTest'), enableSorting: false, cell: ({ row }: { row: { original: AiProfile } }) => lastTest(row.original) },
            { id: 'cap', header: t('profiles.col.usage'), accessorKey: 'used_month', cell: ({ row }: { row: { original: AiProfile } }) => <BudgetUse used={row.original.used_month} budget={row.original.monthly_budget} /> },
            { id: 'actions', header: t('profiles.col.actions'), enableSorting: false, cell: ({ row }: { row: { original: AiProfile } }) => Actions(row.original) },
          ]} />
      )}
      {/* A test asks the provider (up to 60 s, modules/ai probeTimeout); say so while it runs */}
      <BusyNote busy={test.isPending} className="mt-3">{t('profiles.testWaiting', { name: test.variables?.name ?? '' })}</BusyNote>
      {result ? (
        result.ok ? (
          <p role="status" className="mt-3 flex flex-wrap items-center gap-2 text-sm">
            <Chip tone="ok">{t('profiles.testOk')}</Chip>{t('profiles.testDetail', { name: result.name, ms: result.ok.latency_ms, input: result.ok.tokens_in, output: result.ok.tokens_out })} {t(result.ok.capabilities.tools ? 'profiles.capTools' : 'profiles.capNoTools')}
          </p>
        ) : <Notice tone="danger" role="alert" title={`${result.name}: ${result.error}`} className="mt-3 mb-0" />
      ) : null}
      {edit ? <ProfileDialog key={typeof edit === 'string' ? 'new' : edit.id} profile={edit === 'new' ? null : edit} existing={profiles} onClose={() => setEdit(null)}
        onSaved={() => { if (typeof edit !== 'string') setResult((r) => (r?.error && r.name === edit.name ? null : r)) }} /> : null}
      {del ? <RemoveDialog profile={del} assign={assign} onClose={() => setDel(null)} /> : null}
    </Section>
  )
}

const FIELD_OF: Record<string, 'name' | 'base_url' | 'model' | 'key' | 'cap' | 'style' | 'location'> = { invalid_name: 'name', duplicate_name: 'name', invalid_base_url: 'base_url', invalid_model: 'model', invalid_key: 'key', key_required: 'key', secret_lost: 'key', invalid_cap: 'cap', invalid_style: 'style', invalid_location: 'location' }
type Errs = Partial<Record<'name' | 'base_url' | 'model' | 'key' | 'cap' | 'style' | 'location', string>>

const sameOrigin = (a: string, b: string) => { try { return new URL(a).origin === new URL(b.trim()).origin } catch { return false } }

/** Add or edit an AI profile. Also opened where a profile is missing (docs/UI.md §0): "+ New AI profile" of the routing table, the
 *  Assistant and the AI panels of other pages; `onSaved` gets the saved profile so the caller can select it; after an edit a failed Test shown
 *  for it is out of date (review r1 L5). */
export function ProfileDialog({ profile, existing, onClose, onSaved }: { profile: AiProfile | null; existing: AiProfile[]; onClose: () => void; onSaved?: (p: AiProfile) => void }) {
  const { t } = useTranslation('ai')
  const save = useSaveProfile()
  const test = useTestProfile()
  const models = useListModels()
  const first = presetOf(profile)
  const [preset, setPreset] = useState<Preset>(first)
  const kind = kindOf(preset)
  const [name, setName] = useState(profile?.name ?? (existing.some((p) => p.name === DEFAULTS[first].name) ? '' : DEFAULTS[first].name))
  const [adv, setAdv] = useState(first === 'custom')
  const [style, setStyle] = useState<ApiStyle>(profile?.api_style ?? DEFAULTS[first].api_style)
  const [baseUrl, setBaseUrl] = useState(profile?.base_url ?? DEFAULTS[first].base_url)
  const [model, setModel] = useState(profile?.model ?? DEFAULTS[first].model)
  const [key, setKey] = useState('')
  const [location, setLocation] = useState<'internal' | 'cloud'>(profile?.location ?? DEFAULTS[first].location)
  const [cap, setCap] = useState(String(profile?.monthly_budget ?? 6_000_000))
  const [ack, setAck] = useState(false)
  const [errs, setErrs] = useState<Errs>({})
  const cloudOnly = preset !== 'openai-compatible' && preset !== 'custom'
  // The consent names the host only for an address that is one; a half-typed or wrong address reads as a neutral phrase.
  const host = (() => { try { const u = new URL(baseUrl.trim()); return /^https?:$/.test(u.protocol) && u.host ? u.host : null } catch { return null } })()
  const needAck = location === 'cloud' && (!profile || key !== '' || baseUrl !== profile.base_url || profile.location !== 'cloud')
  const serverField = (e: unknown) => (e instanceof ApiError ? FIELD_OF[e.code] : undefined)
  const err = (k: keyof Errs) => errs[k] ?? (serverField(save.error) === k ? (save.error as Error).message : serverField(testErr) === k ? (testErr as Error).message : serverField(models.error) === k ? (models.error as Error).message : undefined)
  const upd = (k: keyof Errs) => setErrs((x) => ({ ...x, [k]: undefined }))
  // The stored key is offered only for the provider and address it was saved for; another provider or origin needs the key again (validate, server).
  // #847: a key that was not restored is not kept: it has to be entered again (the dialog opens on the field).
  const lostKey = !!profile?.key_lost
  const keptKey = !lostKey && profile?.key_last4 && profile.kind === kind && sameOrigin(profile.base_url, baseUrl) ? profile.key_last4 : null
  // host.containers.internal is known only on the appliance (rootful Podman); a container-only install may be Docker, which does not
  // resolve it, so the address of a local model starts empty there and the hint says to use the machine's LAN IP.
  const container = useInstallKind() === 'container'
  const defaultsOf = (k: Preset) => (container && k === 'openai-compatible' ? { ...DEFAULTS[k], base_url: '' } : DEFAULTS[k])

  function pickKind(k: Preset) {
    save.reset(); test.reset(); models.reset(); setErrs({})
    const d = defaultsOf(k)
    // changing the kind refills the defaults; the name changes only when the user has not set it themselves
    if (!profile && (name === '' || Object.values(DEFAULTS).some((x) => x.name === name))) setName(d.name && !existing.some((p) => p.name === d.name) ? d.name : '')
    // A key belongs to one provider: never carry it to another one. An address or model the person typed stays; one that is still
    // the previous type's default (or empty) takes the new type's default.
    const prev = defaultsOf(preset)
    const typed = (v: string, dflt: string) => v.trim() !== '' && v !== dflt
    setPreset(k); setAdv(k === 'custom'); setStyle(d.api_style); setLocation(d.location); setKey(''); setAck(false)
    if (!typed(baseUrl, prev.base_url)) setBaseUrl(d.base_url)
    if (!typed(model, prev.model)) setModel(d.model)
  }
  // A new profile moved off the network keeps no trace of the local defaults: not the name "Local model", not the http://localhost address.
  function clearLocalDefaults(loc: 'internal' | 'cloud') {
    if (profile || loc !== 'cloud') return
    const d = defaultsOf(preset)
    if (d.location === 'internal' && name === d.name) setName('')
    if (d.location === 'internal' && baseUrl === d.base_url) setBaseUrl('')
  }
  const input = (): ProfileInput => ({ id: profile?.id, name: name.trim(), kind, api_style: style, base_url: baseUrl.trim(), model: model.trim(), api_key: key || undefined, location, monthly_budget: Number(cap) })

  function validate(forTest: boolean): boolean {
    const n: Errs = {}
    if (!forTest && !name.trim()) n.name = t('profiles.err.name')
    if (!forTest && existing.some((p) => p.id !== profile?.id && p.name.toLowerCase() === name.trim().toLowerCase())) n.name = t('profiles.err.duplicate')
    if (kind === 'custom' && !style) n.style = t('profiles.err.style')
    try { const u = new URL(baseUrl.trim()); if (u.protocol !== 'https:' && !(u.protocol === 'http:' && location === 'internal')) n.base_url = t('profiles.err.https') } catch { n.base_url = t('profiles.err.url') }
    if (!model.trim()) n.model = t('profiles.err.model')
    const hadKey = !!profile?.key_last4 && profile.kind === kind
    // The stored key follows only its own address: another origin needs the key again (the server enforces it too).
    const moved = hadKey && (() => { try { return new URL(profile!.base_url).origin !== new URL(baseUrl.trim()).origin } catch { return false } })()
    if (key === '' && lostKey) n.key = t('profiles.err.keyLost')
    else if (key === '' && location === 'cloud' && moved) n.key = t('profiles.err.keyMoved')
    else if (key === '' && location === 'cloud' && !hadKey) n.key = t('profiles.err.keyRequired')
    else if (key !== '' && (key.length < 8 || /\s/.test(key))) n.key = t('profiles.err.keyShape')
    if (!forTest) { const c = Number(cap); if (!Number.isInteger(c) || c < 1000 || c > 150_000_000) n.cap = t('profiles.err.cap') }
    setErrs(n)
    if (n.base_url || n.cap || n.style) setAdv(true)
    return Object.keys(n).length === 0
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    test.reset()
    if (!validate(false)) return
    save.mutate(input(), { onSuccess: (saved) => { toast.success(profile ? t('profiles.saved') : t('profiles.added')); onSaved?.(saved); onClose() } })
  }
  function runTest() { save.reset(); if (validate(true)) test.mutate(input()) }
  // The box asks the provider which models it offers. Only what the call needs is checked here; the box checks the rest.
  function listModels() {
    save.reset(); test.reset()
    const n: Errs = {}
    try { const u = new URL(baseUrl.trim()); if (u.protocol !== 'https:' && !(u.protocol === 'http:' && location === 'internal')) n.base_url = t('profiles.err.https') } catch { n.base_url = t('profiles.err.url') }
    if (key === '' && location === 'cloud' && !keptKey) n.key = t('profiles.err.keyRequired')
    setErrs(n)
    if (n.base_url) setAdv(true)
    if (Object.keys(n).length === 0) models.mutate({ id: profile?.id, kind, api_style: style, base_url: baseUrl.trim(), api_key: key || undefined, location })
  }
  const notEncrypted = location === 'internal' && /^http:/i.test(baseUrl.trim())
  const aria = (k: keyof Errs, hint?: boolean) => ({ 'aria-invalid': err(k) ? true : undefined, 'aria-describedby': err(k) ? `pf-${k}-error` : hint ? `pf-${k}-hint` : undefined })
  // "Connected" holds only for what was tested: a changed provider, address, model, key or location hides it until Test runs again.
  const conn = (i: Pick<ProfileInput, 'kind' | 'api_style' | 'base_url' | 'model' | 'api_key' | 'location'>) => JSON.stringify([i.kind, i.api_style, i.base_url, i.model, i.api_key, i.location])
  const tested = test.data && test.variables && conn(test.variables) === conn(input()) ? test.data : undefined
  // A Test failure holds for the connection it was run on, like a success (tested): change the address, location, model or key and it goes.
  const testErr = test.error && test.variables && conn(test.variables) === conn(input()) ? test.error : null

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={profile ? t('profiles.editTitle', { name: profile.name }) : t('profiles.addTitle')} description={t('profiles.dialogBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={profile ? t('profiles.editTitle', { name: profile.name }) : t('profiles.addTitle')}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('profiles.f.kind')} htmlFor="pf-kind" hint={preset === 'opencode' ? t('profiles.f.opencodeHint') : undefined} info={preset === 'opencode' ? t('profiles.f.opencodeInfo') : undefined} className="sm:col-span-2">
              <Select id="pf-kind" value={preset} onChange={(e) => pickKind(e.target.value as Preset)}>{PRESETS.map((k) => <option key={k} value={k}>{t(`profiles.kind.${k}`)}</option>)}</Select>
            </Field>
            <div className="grid gap-1.5 sm:col-span-2">
              <div className="flex items-center gap-1">
                <Label id="pf-location-label">{t('profiles.f.location')}</Label>
                <InfoTip topic={t('profiles.f.location')}><p>{t('profiles.f.locationInfo')}</p>{cloudOnly ? <p>{t('profiles.f.cloudOnlyInfo')}</p> : null}</InfoTip>
              </div>
              <RadioGroup value={location} onValueChange={(v) => { setLocation(v as 'internal' | 'cloud'); models.reset(); setErrs((x) => ({ ...x, base_url: undefined, key: undefined })); clearLocalDefaults(v as 'internal' | 'cloud') }} aria-labelledby="pf-location-label" disabled={cloudOnly}>
                {(['internal', 'cloud'] as const).map((l) => (
                  <div key={l} className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
                    <RadioItem id={`pf-loc-${l}`} value={l} className="mt-0.5" disabled={cloudOnly && l === 'internal'} />
                    <div className="grid gap-0.5"><Label htmlFor={`pf-loc-${l}`}>{t(`profiles.location.${l}`)}</Label><p className="text-meta text-muted">{t(`profiles.f.location_${l}`)}</p></div>
                  </div>
                ))}
              </RadioGroup>
              {cloudOnly ? <p className="text-meta text-muted">{t('profiles.f.cloudOnly')}</p> : null}
              {notEncrypted ? <div role="note" className="flex items-center gap-1 text-meta text-warn"><p>{t('profiles.f.notEncrypted')}</p><InfoTip topic={t('profiles.f.baseUrl')}>{t('profiles.f.notEncryptedInfo')}</InfoTip></div> : null}
            </div>
            <Field label={t('profiles.f.key')} htmlFor="pf-key" error={err('key')} hint={lostKey ? t('profiles.f.keyLost') : keptKey ? t('profiles.f.keySaved', { last4: keptKey }) : location === 'internal' ? t('profiles.f.keyOptional') : t('profiles.f.keyHint')} className="sm:col-span-2">
              <Input id="pf-key" type="password" value={key} onChange={(e) => { setKey(e.target.value); upd('key'); models.reset() }} autoComplete="off" autoFocus={lostKey} placeholder={keptKey ? `••••${keptKey}` : ''} {...aria('key', true)} />
            </Field>
            <Field label={t('profiles.f.model')} htmlFor="pf-model" hint={models.data ? t('profiles.f.modelsFound', { count: models.data.models.length }) : t('profiles.f.modelHint')} info={t('profiles.f.modelInfo')} error={err('model')} className="sm:col-span-2">
              <div className="flex gap-2">
                <Input id="pf-model" list="pf-models" value={model} onChange={(e) => { setModel(e.target.value); upd('model') }} autoComplete="off" className="min-w-0 flex-1" {...aria('model', true)} />
                <Button type="button" onClick={listModels} busy={models.isPending} busyLabel={t('profiles.f.listing')}>{t('profiles.f.listModels')}</Button>
              </div>
              <BusyNote busy={models.isPending}>{t('profiles.f.listingWaiting')}</BusyNote>
              <datalist id="pf-models">{models.data?.models.map((m) => <option key={m} value={m} />)}</datalist>
            </Field>
            {models.error && !serverField(models.error) ? <div className="sm:col-span-2"><ActionError error={models.error} /></div> : null}
            <Field label={t('profiles.f.name')} htmlFor="pf-name" hint={t('profiles.f.nameHint')} info={t('profiles.f.nameInfo')} error={err('name')} className="sm:col-span-2">
              <Input id="pf-name" value={name} maxLength={40} onChange={(e) => { setName(e.target.value); upd('name') }} autoComplete="off" {...aria('name', true)} />
            </Field>
            <details className="grid gap-4 sm:col-span-2" open={adv} onToggle={(e) => setAdv((e.currentTarget as HTMLDetailsElement).open)}>
              <summary className="cursor-pointer text-sm font-medium">{t('profiles.f.advanced')}</summary>
              <div className="mt-3 grid gap-4">
                <p className="text-meta text-muted">{t(preset === 'custom' ? 'profiles.f.advancedCustom' : 'profiles.f.advancedHint')}</p>
                {preset === 'custom' ? (
                  <Field label={t('profiles.f.style')} htmlFor="pf-style" hint={t('profiles.f.styleHint')} error={err('style')}>
                    <Select id="pf-style" value={style} onChange={(e) => setStyle(e.target.value as ApiStyle)}>{(['openai', 'anthropic', 'gemini'] as const).map((st) => <option key={st} value={st}>{t(`profiles.style.${st}`)}</option>)}</Select>
                  </Field>
                ) : null}
                <Field label={t('profiles.f.baseUrl')} htmlFor="pf-base_url" hint={location === 'internal' ? t(container ? 'profiles.f.baseUrlInternalContainer' : 'profiles.f.baseUrlInternal') : t('profiles.f.baseUrlCloud')} info={location === 'internal' ? t(container ? 'profiles.f.baseUrlInternalContainerInfo' : 'profiles.f.baseUrlInternalInfo') : undefined} error={err('base_url')}>
                  <Input id="pf-base_url" value={baseUrl} onChange={(e) => { setBaseUrl(e.target.value); upd('base_url'); models.reset() }} autoComplete="off" inputMode="url" placeholder={container && preset === 'openai-compatible' && location === 'internal' ? t('profiles.f.baseUrlLanPlaceholder') : undefined} {...aria('base_url', true)} />
                </Field>
                <Field label={t('profiles.f.cap')} htmlFor="pf-cap" hint={t('profiles.f.capHint')} info={t('profiles.f.capInfo')} error={err('cap')}>
                  <Input id="pf-cap" type="number" min={1000} max={150000000} step={1000} value={cap} onChange={(e) => { setCap(e.target.value); upd('cap') }} {...aria('cap', true)} />
                </Field>
              </div>
            </details>
          </div>
          {needAck ? (
            <div className="flex items-start gap-3">
              <Checkbox id="pf-ack" checked={ack} onCheckedChange={(v) => setAck(v === true)} className="mt-0.5" />
              <Label htmlFor="pf-ack" className="font-normal">{host ? t('profiles.f.ack', { host }) : t('profiles.f.ackNoHost')}</Label>
            </div>
          ) : null}
          {needAck && !ack ? <p id="pf-ack-why" className="text-meta text-muted">{t('profiles.f.ackNeeded', { button: profile ? t('common:save') : t('profiles.addConfirm') })}</p> : null}
          {/* The test asks the provider (up to 60 s, modules/ai probeTimeout); say so while it runs */}
          <BusyNote busy={test.isPending}>{t('profiles.testWaitingDraft')}</BusyNote>
          {tested ? <p role="status" className="flex flex-wrap items-center gap-2 text-sm"><Chip tone="ok">{t('profiles.testOk')}</Chip>{t('profiles.testDetail', { name: name.trim() || t('profiles.thisProfile'), ms: tested.latency_ms, input: tested.tokens_in, output: tested.tokens_out })} {t(tested.capabilities.tools ? 'profiles.capTools' : 'profiles.capNoTools')}</p> : null}
          {testErr && !serverField(testErr) ? <ActionError error={testErr} /> : null}
          {save.error && !serverField(save.error) ? <ActionError error={save.error} /> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="button" onClick={runTest} disabled={save.isPending} busy={test.isPending} busyLabel={t('common:busy.testing')}>{t('profiles.test')}</Button>
            <Button type="submit" variant="primary" disabled={needAck && !ack} busy={save.isPending} busyLabel={t('common:busy.saving')} aria-describedby={needAck && !ack ? 'pf-ack-why' : undefined}>{profile ? t('common:save') : t('profiles.addConfirm')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function RemoveDialog({ profile, assign, onClose }: { profile: AiProfile; assign: Assignments | undefined; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const remove = useRemoveProfile()
  const used = JOBS.filter((j) => assign?.jobs[j.id]?.primary === profile.id || assign?.jobs[j.id]?.fallback === profile.id)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('profiles.removeTitle', { name: profile.name })} description={used.length ? t('profiles.removeBodyUsed', { jobs: used.map((j) => t(`jobs.${j.id}.name`)).join(', ') }) : t('profiles.removeBody')} info={used.length ? t('profiles.removeBodyUsedInfo') : undefined}>
        <ActionError error={remove.error} />
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" busy={remove.isPending} busyLabel={t('common:busy.removing')} onClick={() => remove.mutate(profile.id, { onSuccess: () => { onClose(); toast.success(t('profiles.removed', { name: profile.name })) } })}>{t('profiles.removeConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------- Job assignments
/** A refetch of the assignments (a profile added from "+ New AI profile" takes every job without a primary; a save) keeps what the
 *  customer changed: a row they edited stays theirs, an untouched row takes the server's value. With the privacy rule changed in the
 *  draft, the draft stays whole (the server's rows follow the saved rule, not the draft's). Never a remount: focus and the "added
 *  and selected" status stay on the select (#875 r1). */
function mergeAssignments(draft: Assignments, was: Assignments, now: Assignments): Assignments {
  const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
  if (same(draft, was)) return now
  if (draft.internal_only !== was.internal_only) return draft
  const jobs = { ...draft.jobs }
  for (const j of Object.keys(now.jobs) as AiJob[]) if (same(draft.jobs[j], was.jobs[j])) jobs[j] = now.jobs[j]
  return { ...draft, jobs }
}

function AssignSection({ profiles, assign }: { profiles: AiProfile[]; assign: Assignments }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const save = useSaveAssignments()
  const [draft, setDraft] = useState<Assignments>(assign)
  const [base, setBase] = useState<Assignments>(assign)
  if (JSON.stringify(assign) !== JSON.stringify(base)) { // adjust state to a new prop during render (react.dev, "You might not need an effect")
    setBase(assign)
    setDraft((d) => mergeAssignments(d, base, assign))
  }
  const [note, setNote] = useState('')
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const dirty = JSON.stringify(draft) !== JSON.stringify(assign)
  const byId = new Map(profiles.map((p) => [p.id, p]))
  const blocked = (p: AiProfile, data: 'internal' | 'public', internalOnly = draft.internal_only) => internalOnly && data === 'internal' && p.location !== 'internal'

  function setSlot(job: AiJob, slot: 'primary' | 'fallback', id: string) {
    setNote('')
    setDraft((d) => {
      const cur = d.jobs[job]
      const next = { ...cur, [slot]: id || null }
      if (!next.primary) next.fallback = null
      if (next.primary && next.primary === next.fallback) next.fallback = null
      return { ...d, jobs: { ...d.jobs, [job]: next } }
    })
  }
  function toggleRule(on: boolean) {
    setNote('')
    setDraft((d) => {
      if (!on) return { ...d, internal_only: false }
      let cleared = 0
      const jobs = { ...d.jobs }
      for (const j of JOBS) {
        const s = { ...jobs[j.id] }
        for (const slot of ['primary', 'fallback'] as const) { const p = s[slot] ? byId.get(s[slot]!) : undefined; if (p && blocked(p, j.data, true)) { s[slot] = null; cleared += 1 } }
        if (!s.primary && s.fallback) { s.primary = s.fallback; s.fallback = null }
        jobs[j.id] = s
      }
      if (cleared) setNote(t('assign.cleared', { count: cleared }))
      return { internal_only: true, jobs }
    })
  }
  async function suggest() {
    try {
      const s = await fetchSuggestion(draft.internal_only)
      setDraft(s)
      setNote(JSON.stringify(s) === JSON.stringify(assign) ? t('assign.suggestedSame') : t('assign.suggested'))
    } catch (e) { toast.error(e instanceof Error ? e.message : String(e)) }
  }
  // #847: every profile's key was not restored. The table stays (its jobs keep their profiles) with its own line, not "add a profile".
  const allLost = profiles.filter(usable).length === 0 && profiles.some((p) => p.key_lost)
  const noProfiles = profiles.filter(usable).length === 0 && !allLost
  const [adding, setAdding] = useState(false)
  // §0: the new profile is selected in the row it was made from only when that row may use it; otherwise the row keeps its value
  // and says why, so Save never fails on a profile the privacy rule or a missing key forbids (#875 r1).
  const newProfile = (data: 'internal' | 'public') => ({ open, onOpenChange, onCreated }: CreateDialogProps) => (open ? <ProfileDialog profile={null} existing={profiles} onClose={() => onOpenChange(false)} onSaved={(p) => {
    if (p.usable && !blocked(p, data)) { onCreated({ value: p.id, label: p.name }); return }
    setNote(t('assign.addedNotSelected', { name: p.name, why: blocked(p, data) ? t('assign.notSelectedCloud') : t('assign.notSelectedUnusable') }))
  }} /> : null)
  return (
    <Section id="ai-routing" title={t('assign.title')} description={t('assign.description')} info={<><p>{t('assign.descriptionInfo')}</p><p>{t('assign.fallbackNote')}</p></>} stories={['S-AI-4']}
      actions={<Button onClick={() => void suggest()} disabled={!admin || noProfiles || allLost} title={reason ?? (noProfiles || allLost ? t('assign.needProfile') : undefined)}>{t('assign.suggest')}</Button>}>
      <div className="grid gap-4">
        <Card className="flex items-start gap-3">
          <Switch id="ai-internal-only" checked={draft.internal_only} onCheckedChange={toggleRule} disabled={!admin} title={reason} className="mt-0.5" />
          <div className="grid gap-0.5">
            <div className="flex items-center gap-1">
              <Label htmlFor="ai-internal-only">{t('assign.rule')}</Label>
              <InfoTip topic={t('assign.rule')}>{t('assign.ruleInfo')}</InfoTip>
            </div>
            <p className="text-meta text-muted">{t('assign.ruleBody')}</p>
          </div>
        </Card>
        {note ? <p role="status" className="text-sm">{note}</p> : null}
        {allLost ? <p role="status" className="text-sm text-danger">{t('assign.allLost')}</p> : null}
        {noProfiles ? <EmptyState title={t('assign.noProfiles')} info={t('assign.noProfilesInfo')} action={<Button variant="primary" onClick={() => setAdding(true)} disabled={!admin} title={reason}>{t('profiles.add')}</Button>}>{t('assign.noProfilesBody')}</EmptyState> : (
          <div className="overflow-x-auto rounded-md border border-rule bg-surface">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <caption className="sr-only">{t('assign.caption')}</caption>
              <thead><tr className="border-b border-rule bg-sunken text-left text-caption text-muted">
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.job')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.data')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.primary')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.fallback')}</th>
              </tr></thead>
              <tbody>
                {shownJobs().map((j) => {
                  const s = draft.jobs[j.id]
                  const opts = (slot: 'primary' | 'fallback'): SelectOption[] => [{ value: '', label: t('assign.none') }, ...profiles.map((p) => {
                    const off = !p.usable || blocked(p, j.data) || (slot === 'fallback' && s.primary === p.id)
                    const why = p.key_lost ? t('assign.optKeyLost') : !p.usable ? t('assign.optNoKey') : blocked(p, j.data) ? t('assign.optCloud') : ''
                    return { value: p.id, label: `${p.name}${why ? ` (${why})` : ''}`, disabled: off }
                  })]
                  return (
                    <tr key={j.id} className="border-b border-rule align-top last:border-b-0">
                      <th scope="row" className="px-3 py-2 text-left font-normal"><span className="font-medium">{t(`jobs.${j.id}.name`)}</span><span className="block text-caption text-muted">{t(`jobs.${j.id}.what`)}</span></th>
                      <td className="px-3 py-2"><Chip tone={j.data === 'internal' ? 'warn' : 'off'}>{t(`assign.data.${j.data}`)}</Chip></td>
                      <td className="px-3 py-2">
                        {/* §0: the profile a task needs is created right here and selected */}
                        <CreatableSelect id={`ai-job-${j.id}`} className="min-w-[11rem]" aria-label={t('assign.primaryFor', { job: t(`jobs.${j.id}.name`) })} value={s.primary ?? ''} onChange={(v) => setSlot(j.id, 'primary', v)} disabled={!admin} title={reason}
                          options={opts('primary')} newLabel={t('assign.newProfile')} canCreate={admin} renderCreate={newProfile(j.data)} />
                      </td>
                      <td className="px-3 py-2">
                        <Select className="min-w-[11rem]" aria-label={t('assign.fallbackFor', { job: t(`jobs.${j.id}.name`) })} value={s.fallback ?? ''} onChange={(e) => setSlot(j.id, 'fallback', e.target.value)} disabled={!admin || !s.primary} title={reason ?? (!s.primary ? t('assign.fallbackNeedsPrimary') : undefined)}>
                          {opts('fallback').map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
                        </Select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {adding ? <ProfileDialog profile={null} existing={profiles} onClose={() => setAdding(false)} /> : null}
        <ActionError error={save.error} />
        <div className="flex flex-wrap gap-3">
          <Button variant="primary" disabled={!admin || !dirty} busy={save.isPending} busyLabel={t('common:busy.saving')} title={reason ?? (!dirty ? t('assign.nothingToSave') : undefined)}
            onClick={() => save.mutate(draft, { onSuccess: () => { setNote(''); toast.success(t('assign.saved')) } })}>{t('assign.save')}</Button>
          {dirty ? <Button onClick={() => { setDraft(assign); setNote('') }}>{t('assign.discard')}</Button> : null}
        </div>
      </div>
    </Section>
  )
}

// ---------- Token usage, the shared monthly budget, masking personal information
function TierForm({ cfg }: { cfg: AiConfigView }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const save = useSaveConfig()
  const [tier, setTier] = useState<AiTier>(cfg.tier)
  const [cap, setCap] = useState(String(cfg.monthly_budget))
  const [redact, setRedact] = useState(cfg.redact_pii)
  const [capErr, setCapErr] = useState('')
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const serverCap = save.error instanceof ApiError && save.error.code === 'invalid_cap' ? save.error.message : ''
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const c = Number(cap)
    if (!Number.isInteger(c) || c < 1000 || c > 150_000_000) { setCapErr(t('settings.err.cap')); return }
    setCapErr('')
    save.mutate({ tier, monthly_budget: c, redact_pii: redact }, { onSuccess: () => toast.success(t('settings.saved')) })
  }
  const err = capErr || serverCap
  const pct = budgetPct(cfg.month_used, cfg.monthly_budget)
  return (
    <form onSubmit={submit} noValidate aria-label={t('settings.tier.title')}>
      <Section title={t('settings.tier.title')} description={t('settings.tier.intro')} info={<><p>{t('settings.tier.introInfo')}</p><p>{t('settings.tier.maxInfo')}</p></>} stories={['S-AI-4']}>
        <RadioGroup value={tier} onValueChange={(v) => setTier(v as AiTier)} aria-label={t('settings.tier.title')} disabled={!admin}>
          {TIERS.map((k) => (
            <div key={k} className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
              <RadioItem id={`ai-tier-${k}`} value={k} className="mt-0.5" />
              <div className="grid gap-0.5">
                <Label htmlFor={`ai-tier-${k}`}>{t(`settings.tier.${k}.name`)}</Label>
                <p className="text-meta text-muted">{t(`settings.tier.${k}.sends`)}</p>
                <p className="text-meta text-muted">{cfg.tier_estimates[k] ? t('settings.tier.estimate', { n: fmtNumber(cfg.tier_estimates[k]), month: fmtNumber(cfg.tier_estimates[k]! * 30) }) : t('settings.tier.estimateMax')}</p>
              </div>
            </div>
          ))}
        </RadioGroup>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label={t('settings.cap')} htmlFor="ai-cap" hint={t('settings.capHint')} info={t('settings.capInfo')} error={err || undefined}>
            <Input id="ai-cap" type="number" min={1000} max={150000000} step={1000} value={cap} onChange={(e) => { setCap(e.target.value); setCapErr('') }} disabled={!admin} aria-invalid={err ? true : undefined} aria-describedby={err ? 'ai-cap-error' : 'ai-cap-hint'} />
            <p className="text-meta">{t('settings.budgetNow')}{' '}
              <BudgetUse used={cfg.month_used} budget={cfg.monthly_budget} />{' '}<span className="text-muted">{t('settings.budgetRenews', { date: fmtDate(cfg.renews_on) })}</span>
            </p>
            {pct >= 100 ? <p role="status" className="text-meta text-danger">{t('settings.budgetStop', { date: fmtDate(cfg.renews_on) })}</p>
              : pct >= 80 ? <div role="status" className="flex items-center gap-1 text-meta text-warn"><p>{t('settings.budgetWarn')}</p><InfoTip topic={t('settings.cap')}>{t('settings.budgetWarnInfo')}</InfoTip></div> : null}
          </Field>
          <div className="flex items-start gap-3 pt-6">
            <Switch id="ai-redact" checked={redact} onCheckedChange={setRedact} disabled={!admin} />
            <div className="grid gap-0.5">
              <div className="flex items-center gap-1">
                <Label htmlFor="ai-redact">{t('settings.redact')}</Label>
                <InfoTip topic={t('settings.redact')}>{t('settings.redactInfo')}</InfoTip>
              </div>
              <p className="text-meta text-muted">{t('settings.redactHint')}</p>
            </div>
          </div>
        </div>
        {save.error && !serverCap ? <div className="mt-3"><ActionError error={save.error} /></div> : null}
        <div className="mt-4"><Button type="submit" variant="primary" disabled={!admin} busy={save.isPending} busyLabel={t('common:busy.saving')} title={reason}>{t('common:save')}</Button></div>
      </Section>
    </form>
  )
}

/** S-AI-8: how long the activity log is kept. Minimum 90 days; entries can never be edited or deleted from here. */
function RetentionForm() {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const cur = useActivitySettings()
  const save = useSaveActivitySettings()
  const [days, setDays] = useState<string | null>(null)
  const value = days ?? String(cur.data?.retention_days ?? 365)
  const n = Number(value)
  const err = !Number.isInteger(n) || n < 90 ? t('settings.retention.err') : ''
  return (
    <form noValidate aria-label={t('settings.retention.title')} onSubmit={(e) => { e.preventDefault(); if (!err) save.mutate({ retention_days: n }, { onSuccess: () => { setDays(null); toast.success(t('settings.saved')) } }) }}>
      <Section title={t('settings.retention.title')} description={t('settings.retention.intro')} info={t('settings.retention.introInfo')} stories={['S-AI-8']}>
        <Card className="grid gap-4 sm:grid-cols-2">
          <Field label={t('settings.retention.label')} htmlFor="ai-retention" hint={t('settings.retention.hint')} error={err || undefined}>
            <Input id="ai-retention" type="number" min={90} max={3650} value={value} onChange={(e) => setDays(e.target.value)} disabled={!admin} aria-invalid={err ? true : undefined} />
          </Field>
        </Card>
        {save.error ? <div className="mt-3"><ActionError error={save.error} /></div> : null}
        <div className="mt-4"><Button type="submit" variant="primary" disabled={!admin || !!err || cur.isPending} busy={save.isPending} busyLabel={t('common:busy.saving')} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })}>{t('common:save')}</Button></div>
      </Section>
    </form>
  )
}
