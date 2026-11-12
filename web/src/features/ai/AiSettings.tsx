import { lazy, Suspense, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section, Panel } from '@/components/common/PageHeader'
import { DataTable } from '@/components/common/DataTable'
import { EmptyState, Loading, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtNumber } from '@/lib/format'
import { useCan } from '@/lib/session'
import { fetchSuggestion, useActivitySettings, useAiConfig, useAssignments, useProfiles, useRemoveProfile, useSaveActivitySettings, useSaveAssignments, useSaveConfig, useSaveProfile, useTestProfile } from './api'
import { ActionError } from './parts'
import type { AiConfigView, AiJob, AiProfile, AiTier, ApiStyle, Assignments, ProfileInput, ProfileKind, TestResult } from './types'

const RulesTab = lazy(() => import('./harness/RulesTab'))
const MemoryTab = lazy(() => import('./harness/MemoryTab'))
const SkillsTab = lazy(() => import('./harness/SkillsTab'))
const KnowledgeTab = lazy(() => import('./harness/KnowledgeTab'))
const ConnectionsMoved = lazy(() => import('./harness/ConnectionsMoved'))
const HooksTab = lazy(() => import('./harness/HooksTab'))
const TABS = ['profiles', 'rules', 'memory', 'skills', 'knowledge', 'connections', 'hooks'] as const
type Tab = (typeof TABS)[number]
const HARNESS: Record<Exclude<Tab, 'profiles'>, React.LazyExoticComponent<() => React.JSX.Element>> = { rules: RulesTab, memory: MemoryTab, skills: SkillsTab, knowledge: KnowledgeTab, connections: ConnectionsMoved, hooks: HooksTab }

// Địa chỉ và model gợi ý, đối chiếu tài liệu chính thức ngày 2026-11-06. Tên model đổi theo thời gian nên người dùng sửa được.
//  Anthropic: platform.claude.com/docs/en/about-claude/models/overview (claude-haiku-5-5, API https://api.anthropic.com)
//  OpenAI:    developers.openai.com/api/docs/models (gpt-6-luna là model gọn nhẹ), API https://api.openai.com/v1
//  Gemini:    aistudio.google.com/docs/models (gemini-3.6-flash), REST https://generativelanguage.googleapis.com/v1beta
//  Ollama:    docs.ollama.com/api/openai-compatibility (http://localhost:11434/v1, ví dụ model qwen3:8b); vLLM mặc định http://localhost:8000/v1
const KINDS: ProfileKind[] = ['anthropic', 'openai', 'gemini', 'openai-compatible', 'custom']
const DEFAULTS: Record<ProfileKind, { base_url: string; model: string; api_style: ApiStyle; location: 'internal' | 'cloud'; name: string }> = {
  anthropic: { base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', api_style: 'anthropic', location: 'cloud', name: 'Claude' },
  openai: { base_url: 'https://api.openai.com/v1', model: 'gpt-6-luna', api_style: 'openai', location: 'cloud', name: 'OpenAI' },
  gemini: { base_url: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-3.6-flash', api_style: 'gemini', location: 'cloud', name: 'Gemini' },
  'openai-compatible': { base_url: 'http://localhost:11434/v1', model: 'qwen3:8b', api_style: 'openai', location: 'internal', name: 'Local model' },
  custom: { base_url: '', model: '', api_style: 'openai', location: 'cloud', name: '' },
}
const TIERS: AiTier[] = ['min', 'med', 'max']
const JOBS: { id: AiJob; data: 'internal' | 'public' }[] = [
  { id: 'explain-finding', data: 'internal' }, { id: 'mitigation-config', data: 'internal' }, { id: 'ask-my-data', data: 'internal' }, { id: 'log-digest', data: 'internal' }, { id: 'log-investigate', data: 'internal' },
  { id: 'weekly-report', data: 'internal' }, { id: 'pdpl-assessment', data: 'internal' }, { id: 'cve-news', data: 'public' }, { id: 'translate-advisory', data: 'public' }, { id: 'response-plan', data: 'internal' },
]
const hostOf = (u: string) => { try { return new URL(u).host } catch { return u || '…' } }
const usable = (p: AiProfile) => p.usable

/** Settings, AI assistant (S-AI-1, S-AI-4, S-AI-7): tabs for profiles and routing, then the AI harness (rules, memory, skills, knowledge, connections, hooks). Khoá chỉ nhập một chiều: sau khi lưu chỉ còn 4 ký tự cuối (SYS-4). */
export default function AiSettings() {
  const { t } = useTranslation('ai')
  const cfg = useAiConfig()
  const [params, setParams] = useSearchParams()
  const raw = params.get('tab')
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? '') ? (raw as Tab) : 'profiles'
  const Harness = tab === 'profiles' ? null : HARNESS[tab]
  return (
    <div className="grid max-w-4xl grid-cols-[minmax(0,1fr)] gap-2">
      <QueryState query={cfg}>
        {(c) => (
          <>
            <PageHeader title={t('settings.title')} meta={c.configured ? t('settings.statusOn') : t('settings.statusOff')} />
            <div className="mb-6">
              <Segmented label={t('harness.tabs.label')} value={tab} options={TABS.map((v) => ({ value: v, label: t(`harness.tabs.${v}`) }))}
                onChange={(v) => setParams((p) => { const n = new URLSearchParams(p); if (v === 'profiles') n.delete('tab'); else n.set('tab', v); return n }, { replace: true })} />
            </div>
            {Harness ? <Suspense fallback={<Loading />}><Harness /></Suspense> : <ProfilesTab cfg={c} />}
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
      <QueryState query={assign}>{(a) => <AssignSection key={JSON.stringify(a)} profiles={profiles.data?.items ?? []} assign={a} />}</QueryState>
      <TierForm key={`${cfg.tier}|${cfg.daily_cap}|${cfg.redact_pii}`} cfg={cfg} />
      <RetentionForm />
    </>
  )
}

function Flow({ profiles }: { profiles: AiProfile[] }) {
  const { t } = useTranslation('ai')
  const cloud = [...new Set(profiles.filter((p) => p.location === 'cloud').map((p) => hostOf(p.base_url)))]
  return (
    <Section title={t('settings.flow.title')} stories={['S-AI-1']}>
      <Panel className="grid gap-2 p-4 text-sm">
        <p>{cloud.length ? t('settings.flow.remote', { hosts: cloud.join(', ') }) : t('settings.flow.noneRemote')}</p>
        {cloud.length ? <p>{t('settings.flow.abroad')}</p> : null}
        <p className="text-muted">{t('settings.flow.rules')}</p>
      </Panel>
    </Section>
  )
}

// ---------- Hồ sơ AI
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
      onError: (e) => setResult({ name: p.name, error: e instanceof Error ? e.message : String(e) }),
    })
  }
  const Actions = (p: AiProfile) => (
    <span className="flex flex-wrap gap-2">
      <Button size="sm" onClick={() => runTest(p)} disabled={!admin || test.isPending} title={reason} aria-label={t('profiles.testNamed', { name: p.name })}>{test.isPending && test.variables?.id === p.id ? t('profiles.testing') : t('profiles.test')}</Button>
      <Button size="sm" onClick={() => setEdit(p)} disabled={!admin} title={reason} aria-label={t('profiles.editNamed', { name: p.name })}>{t('profiles.edit')}</Button>
      <Button size="sm" onClick={() => setDel(p)} disabled={!admin} title={reason} aria-label={t('profiles.removeNamed', { name: p.name })}>{t('profiles.remove')}</Button>
    </span>
  )
  const keyText = (p: AiProfile) => p.key_last4 ? t('profiles.keyEnds', { last4: p.key_last4 }) : p.location === 'internal' ? t('profiles.noKeyNeeded') : t('profiles.keyMissing')
  const loc = (p: AiProfile) => <Chip tone={p.location === 'internal' ? 'ok' : 'off'}>{t(`profiles.location.${p.location}`)}</Chip>
  return (
    <Section id="ai-profiles" title={t('profiles.title')} description={t('profiles.description')} stories={['S-AI-1']}
      actions={<Button variant="primary" onClick={() => setEdit('new')} disabled={!admin} title={reason}>{t('profiles.add')}</Button>}>
      {profiles.length === 0 ? (
        <EmptyState title={t('profiles.empty')} action={<Button variant="primary" onClick={() => setEdit('new')} disabled={!admin} title={reason}>{t('profiles.add')}</Button>}>{t('profiles.emptyBody')}</EmptyState>
      ) : (
        <DataTable<AiProfile> caption={t('profiles.caption')} data={profiles}
          mobileRow={(p) => (
            <div className="grid gap-1.5 text-sm">
              <p className="flex flex-wrap items-center gap-2 font-medium">{p.name} {loc(p)}</p>
              <p className="text-muted">{t(`profiles.kind.${p.kind}`)}, {p.model}</p>
              <p className="text-muted">{keyText(p)}. {t('profiles.usage', { used: fmtNumber(p.used_today), cap: fmtNumber(p.daily_cap) })}</p>
              {Actions(p)}
            </div>
          )}
          columns={[
            { id: 'name', header: t('profiles.col.name'), accessorKey: 'name', cell: ({ row }: { row: { original: AiProfile } }) => <span className="grid"><span className="font-medium">{row.original.name}</span><span className="text-[12px] text-muted">{t(`profiles.kind.${row.original.kind}`)}</span></span> },
            { id: 'location', header: t('profiles.col.location'), accessorKey: 'location', cell: ({ row }: { row: { original: AiProfile } }) => loc(row.original) },
            { id: 'model', header: t('profiles.col.model'), accessorKey: 'model', cell: ({ row }: { row: { original: AiProfile } }) => <span className="whitespace-nowrap">{row.original.model}</span> },
            { id: 'key', header: t('profiles.col.key'), accessorFn: keyText },
            { id: 'cap', header: t('profiles.col.usage'), accessorKey: 'used_today', cell: ({ row }: { row: { original: AiProfile } }) => t('profiles.usage', { used: fmtNumber(row.original.used_today), cap: fmtNumber(row.original.daily_cap) }) },
            { id: 'actions', header: t('profiles.col.actions'), enableSorting: false, cell: ({ row }: { row: { original: AiProfile } }) => Actions(row.original) },
          ]} />
      )}
      {result ? (
        <p role="status" className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          {result.ok ? <><Chip tone="ok">{t('profiles.testOk')}</Chip>{t('profiles.testDetail', { name: result.name, ms: result.ok.latency_ms, input: result.ok.tokens_in, output: result.ok.tokens_out })} {t(result.ok.capabilities.tools ? 'profiles.capTools' : 'profiles.capNoTools')}</>
            : <span role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2">{result.name}: {result.error}</span>}
        </p>
      ) : null}
      {edit ? <ProfileDialog key={typeof edit === 'string' ? 'new' : edit.id} profile={edit === 'new' ? null : edit} existing={profiles} onClose={() => setEdit(null)} /> : null}
      {del ? <RemoveDialog profile={del} assign={assign} onClose={() => setDel(null)} /> : null}
    </Section>
  )
}

const FIELD_OF: Record<string, 'name' | 'base_url' | 'model' | 'key' | 'cap' | 'style' | 'location'> = { invalid_name: 'name', duplicate_name: 'name', invalid_base_url: 'base_url', invalid_model: 'model', invalid_key: 'key', key_required: 'key', invalid_cap: 'cap', invalid_style: 'style', invalid_location: 'location' }
type Errs = Partial<Record<'name' | 'base_url' | 'model' | 'key' | 'cap' | 'style' | 'location', string>>

const sameOrigin = (a: string, b: string) => { try { return new URL(a).origin === new URL(b.trim()).origin } catch { return false } }

function ProfileDialog({ profile, existing, onClose }: { profile: AiProfile | null; existing: AiProfile[]; onClose: () => void }) {
  const { t } = useTranslation('ai')
  const save = useSaveProfile()
  const test = useTestProfile()
  const first = profile?.kind ?? 'anthropic'
  const [kind, setKind] = useState<ProfileKind>(first)
  const [name, setName] = useState(profile?.name ?? '')
  const [style, setStyle] = useState<ApiStyle>(profile?.api_style ?? DEFAULTS[first].api_style)
  const [baseUrl, setBaseUrl] = useState(profile?.base_url ?? DEFAULTS[first].base_url)
  const [model, setModel] = useState(profile?.model ?? DEFAULTS[first].model)
  const [key, setKey] = useState('')
  const [location, setLocation] = useState<'internal' | 'cloud'>(profile?.location ?? DEFAULTS[first].location)
  const [cap, setCap] = useState(String(profile?.daily_cap ?? 60000))
  const [ack, setAck] = useState(false)
  const [errs, setErrs] = useState<Errs>({})
  const cloudOnly = kind !== 'openai-compatible' && kind !== 'custom'
  const host = hostOf(baseUrl)
  const needAck = location === 'cloud' && (!profile || key !== '' || baseUrl !== profile.base_url || profile.location !== 'cloud')
  const serverField = (e: unknown) => (e instanceof ApiError ? FIELD_OF[e.code] : undefined)
  const err = (k: keyof Errs) => errs[k] ?? (serverField(save.error) === k ? (save.error as Error).message : serverField(testErr) === k ? (testErr as Error).message : undefined)
  const upd = (k: keyof Errs) => setErrs((x) => ({ ...x, [k]: undefined }))
  // The stored key is offered only for the provider and address it was saved for; another provider or origin needs the key again (validate, server).
  const keptKey = profile?.key_last4 && profile.kind === kind && sameOrigin(profile.base_url, baseUrl) ? profile.key_last4 : null

  function pickKind(k: ProfileKind) {
    save.reset(); test.reset(); setErrs({})
    const d = DEFAULTS[k]
    // đổi loại thì điền lại mặc định; tên chỉ đổi khi người dùng chưa tự đặt
    if (!profile && (name === '' || Object.values(DEFAULTS).some((x) => x.name === name))) setName(d.name && !existing.some((p) => p.name === d.name) ? d.name : '')
    // A key belongs to one provider: never carry it to another one.
    setKind(k); setStyle(d.api_style); setBaseUrl(d.base_url); setModel(d.model); setLocation(d.location); setKey(''); setAck(false)
  }
  // A new profile moved off the network keeps no trace of the local defaults: not the name "Local model", not the http://localhost address.
  function clearLocalDefaults(loc: 'internal' | 'cloud') {
    if (profile || loc !== 'cloud') return
    const d = DEFAULTS[kind]
    if (d.location === 'internal' && name === d.name) setName('')
    if (d.location === 'internal' && baseUrl === d.base_url) setBaseUrl('')
  }
  const input = (): ProfileInput => ({ id: profile?.id, name: name.trim(), kind, api_style: style, base_url: baseUrl.trim(), model: model.trim(), api_key: key || undefined, location, daily_cap: Number(cap) })

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
    if (key === '' && location === 'cloud' && moved) n.key = t('profiles.err.keyMoved')
    else if (key === '' && location === 'cloud' && !hadKey) n.key = t('profiles.err.keyRequired')
    else if (key !== '' && (key.length < 8 || /\s/.test(key))) n.key = t('profiles.err.keyShape')
    if (!forTest) { const c = Number(cap); if (!Number.isInteger(c) || c < 1000 || c > 5_000_000) n.cap = t('profiles.err.cap') }
    setErrs(n)
    return Object.keys(n).length === 0
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    test.reset()
    if (!validate(false)) return
    save.mutate(input(), { onSuccess: () => { toast.success(profile ? t('profiles.saved') : t('profiles.added')); onClose() } })
  }
  function runTest() { save.reset(); if (validate(true)) test.mutate(input()) }
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
            <Field label={t('profiles.f.kind')} htmlFor="pf-kind">
              <Select id="pf-kind" value={kind} onChange={(e) => pickKind(e.target.value as ProfileKind)}>{KINDS.map((k) => <option key={k} value={k}>{t(`profiles.kind.${k}`)}</option>)}</Select>
            </Field>
            <Field label={t('profiles.f.name')} htmlFor="pf-name" hint={t('profiles.f.nameHint')} error={err('name')}>
              <Input id="pf-name" value={name} maxLength={40} onChange={(e) => { setName(e.target.value); upd('name') }} autoComplete="off" {...aria('name', true)} />
            </Field>
            {kind === 'custom' ? (
              <Field label={t('profiles.f.style')} htmlFor="pf-style" hint={t('profiles.f.styleHint')} error={err('style')} className="sm:col-span-2">
                <Select id="pf-style" value={style} onChange={(e) => setStyle(e.target.value as ApiStyle)}>{(['openai', 'anthropic', 'gemini'] as const).map((s) => <option key={s} value={s}>{t(`profiles.style.${s}`)}</option>)}</Select>
              </Field>
            ) : null}
            <Field label={t('profiles.f.baseUrl')} htmlFor="pf-base_url" hint={location === 'internal' ? t('profiles.f.baseUrlInternal') : t('profiles.f.baseUrlCloud')} error={err('base_url')} className="sm:col-span-2">
              <Input id="pf-base_url" value={baseUrl} onChange={(e) => { setBaseUrl(e.target.value); upd('base_url') }} autoComplete="off" inputMode="url" {...aria('base_url', true)} />
            </Field>
            <Field label={t('profiles.f.model')} htmlFor="pf-model" hint={t('profiles.f.modelHint')} error={err('model')} className="sm:col-span-2">
              <Input id="pf-model" value={model} onChange={(e) => { setModel(e.target.value); upd('model') }} autoComplete="off" {...aria('model', true)} />
            </Field>
            <Field label={t('profiles.f.key')} htmlFor="pf-key" error={err('key')} hint={keptKey ? t('profiles.f.keySaved', { last4: keptKey }) : location === 'internal' ? t('profiles.f.keyOptional') : t('profiles.f.keyHint')} className="sm:col-span-2">
              <Input id="pf-key" type="password" value={key} onChange={(e) => { setKey(e.target.value); upd('key') }} autoComplete="off" placeholder={keptKey ? `••••${keptKey}` : ''} {...aria('key', true)} />
            </Field>
            <div className="grid gap-1.5 sm:col-span-2">
              <Label id="pf-location-label">{t('profiles.f.location')}</Label>
              <RadioGroup value={location} onValueChange={(v) => { setLocation(v as 'internal' | 'cloud'); setErrs((x) => ({ ...x, base_url: undefined, key: undefined })); clearLocalDefaults(v as 'internal' | 'cloud') }} aria-labelledby="pf-location-label" disabled={cloudOnly}>
                {(['internal', 'cloud'] as const).map((l) => (
                  <div key={l} className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
                    <RadioItem id={`pf-loc-${l}`} value={l} className="mt-0.5" disabled={cloudOnly && l === 'internal'} />
                    <div className="grid gap-0.5"><Label htmlFor={`pf-loc-${l}`}>{t(`profiles.location.${l}`)}</Label><p className="text-[13px] text-muted">{t(`profiles.f.location_${l}`)}</p></div>
                  </div>
                ))}
              </RadioGroup>
              {cloudOnly ? <p className="text-[13px] text-muted">{t('profiles.f.cloudOnly')}</p> : null}
            </div>
            <Field label={t('profiles.f.cap')} htmlFor="pf-cap" hint={t('profiles.f.capHint')} error={err('cap')} className="sm:col-span-2">
              <Input id="pf-cap" type="number" min={1000} max={5000000} step={1000} value={cap} onChange={(e) => { setCap(e.target.value); upd('cap') }} {...aria('cap', true)} />
            </Field>
          </div>
          {needAck ? (
            <div className="flex items-start gap-3">
              <Checkbox id="pf-ack" checked={ack} onCheckedChange={(v) => setAck(v === true)} className="mt-0.5" />
              <Label htmlFor="pf-ack" className="font-normal">{t('profiles.f.ack', { host })}</Label>
            </div>
          ) : null}
          {tested ? <p role="status" className="flex flex-wrap items-center gap-2 text-sm"><Chip tone="ok">{t('profiles.testOk')}</Chip>{t('profiles.testDetail', { name: name.trim() || t('profiles.thisProfile'), ms: tested.latency_ms, input: tested.tokens_in, output: tested.tokens_out })} {t(tested.capabilities.tools ? 'profiles.capTools' : 'profiles.capNoTools')}</p> : null}
          {testErr && !serverField(testErr) ? <ActionError error={testErr} /> : null}
          {save.error && !serverField(save.error) ? <ActionError error={save.error} /> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="button" onClick={runTest} disabled={test.isPending || save.isPending}>{test.isPending ? t('profiles.testing') : t('profiles.test')}</Button>
            <Button type="submit" variant="primary" disabled={save.isPending || (needAck && !ack)}>{save.isPending ? t('profiles.saving') : profile ? t('common:save') : t('profiles.addConfirm')}</Button>
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
      <DialogContent title={t('profiles.removeTitle', { name: profile.name })} description={used.length ? t('profiles.removeBodyUsed', { jobs: used.map((j) => t(`jobs.${j.id}.name`)).join(', ') }) : t('profiles.removeBody')}>
        <ActionError error={remove.error} />
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate(profile.id, { onSuccess: () => { onClose(); toast.success(t('profiles.removed', { name: profile.name })) } })}>{t('profiles.removeConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------- Phân việc
function AssignSection({ profiles, assign }: { profiles: AiProfile[]; assign: Assignments }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const save = useSaveAssignments()
  const [draft, setDraft] = useState<Assignments>(assign)
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
  const noProfiles = profiles.filter(usable).length === 0
  return (
    <Section id="ai-routing" title={t('assign.title')} description={t('assign.description')} stories={['S-AI-4']}
      actions={<Button onClick={() => void suggest()} disabled={!admin || noProfiles} title={reason ?? (noProfiles ? t('assign.needProfile') : undefined)}>{t('assign.suggest')}</Button>}>
      <div className="grid gap-4">
        <div className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
          <Switch id="ai-internal-only" checked={draft.internal_only} onCheckedChange={toggleRule} disabled={!admin} title={reason} className="mt-0.5" />
          <div className="grid gap-0.5">
            <Label htmlFor="ai-internal-only">{t('assign.rule')}</Label>
            <p className="text-[13px] text-muted">{t('assign.ruleBody')}</p>
          </div>
        </div>
        {note ? <p role="status" className="text-sm">{note}</p> : null}
        {noProfiles ? <EmptyState title={t('assign.noProfiles')}>{t('assign.noProfilesBody')}</EmptyState> : (
          <div className="overflow-x-auto rounded-md border border-rule bg-surface">
            <table className="w-full min-w-[760px] border-collapse text-sm">
              <caption className="sr-only">{t('assign.caption')}</caption>
              <thead><tr className="border-b border-rule bg-sunken text-left text-[12px] text-muted">
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.job')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.data')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.primary')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('assign.col.fallback')}</th>
              </tr></thead>
              <tbody>
                {JOBS.map((j) => {
                  const s = draft.jobs[j.id]
                  const opts = (slot: 'primary' | 'fallback') => profiles.map((p) => {
                    const off = !p.usable || blocked(p, j.data) || (slot === 'fallback' && s.primary === p.id)
                    const why = !p.usable ? t('assign.optNoKey') : blocked(p, j.data) ? t('assign.optCloud') : ''
                    return <option key={p.id} value={p.id} disabled={off}>{p.name}{why ? ` (${why})` : ''}</option>
                  })
                  return (
                    <tr key={j.id} className="border-b border-rule align-top last:border-b-0">
                      <th scope="row" className="px-3 py-2 text-left font-normal"><span className="font-medium">{t(`jobs.${j.id}.name`)}</span><span className="block text-[12px] text-muted">{t(`jobs.${j.id}.what`)}</span></th>
                      <td className="px-3 py-2"><Chip tone={j.data === 'internal' ? 'warn' : 'off'}>{t(`assign.data.${j.data}`)}</Chip></td>
                      <td className="px-3 py-2">
                        <Select className="min-w-[13rem]" aria-label={t('assign.primaryFor', { job: t(`jobs.${j.id}.name`) })} value={s.primary ?? ''} onChange={(e) => setSlot(j.id, 'primary', e.target.value)} disabled={!admin} title={reason}>
                          <option value="">{t('assign.none')}</option>{opts('primary')}
                        </Select>
                      </td>
                      <td className="px-3 py-2">
                        <Select className="min-w-[13rem]" aria-label={t('assign.fallbackFor', { job: t(`jobs.${j.id}.name`) })} value={s.fallback ?? ''} onChange={(e) => setSlot(j.id, 'fallback', e.target.value)} disabled={!admin || !s.primary} title={reason ?? (!s.primary ? t('assign.fallbackNeedsPrimary') : undefined)}>
                          <option value="">{t('assign.none')}</option>{opts('fallback')}
                        </Select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="text-[13px] text-muted">{t('assign.fallbackNote')}</p>
        <ActionError error={save.error} />
        <div className="flex flex-wrap gap-3">
          <Button variant="primary" disabled={!admin || !dirty || save.isPending} title={reason ?? (!dirty ? t('assign.nothingToSave') : undefined)}
            onClick={() => save.mutate(draft, { onSuccess: () => { setNote(''); toast.success(t('assign.saved')) } })}>{save.isPending ? t('assign.saving') : t('assign.save')}</Button>
          {dirty ? <Button onClick={() => { setDraft(assign); setNote('') }}>{t('assign.discard')}</Button> : null}
        </div>
      </div>
    </Section>
  )
}

// ---------- Mức dùng token, trần chung, che thông tin cá nhân
function TierForm({ cfg }: { cfg: AiConfigView }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const save = useSaveConfig()
  const [tier, setTier] = useState<AiTier>(cfg.tier)
  const [cap, setCap] = useState(String(cfg.daily_cap))
  const [redact, setRedact] = useState(cfg.redact_pii)
  const [capErr, setCapErr] = useState('')
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const serverCap = save.error instanceof ApiError && save.error.code === 'invalid_cap' ? save.error.message : ''
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const c = Number(cap)
    if (!Number.isInteger(c) || c < 1000 || c > 5_000_000) { setCapErr(t('settings.err.cap')); return }
    setCapErr('')
    save.mutate({ tier, daily_cap: c, redact_pii: redact }, { onSuccess: () => toast.success(t('settings.saved')) })
  }
  const err = capErr || serverCap
  return (
    <form onSubmit={submit} noValidate aria-label={t('settings.tier.title')}>
      <Section title={t('settings.tier.title')} description={t('settings.tier.intro')} stories={['S-AI-4']}>
        <RadioGroup value={tier} onValueChange={(v) => setTier(v as AiTier)} aria-label={t('settings.tier.title')} disabled={!admin}>
          {TIERS.map((k) => (
            <div key={k} className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
              <RadioItem id={`ai-tier-${k}`} value={k} className="mt-0.5" />
              <div className="grid gap-0.5">
                <Label htmlFor={`ai-tier-${k}`}>{t(`settings.tier.${k}.name`)}</Label>
                <p className="text-[13px] text-muted">{t(`settings.tier.${k}.sends`)}</p>
                <p className="text-[13px] text-muted">{cfg.tier_estimates[k] ? t('settings.tier.estimate', { n: fmtNumber(cfg.tier_estimates[k]) }) : t('settings.tier.estimateMax')}</p>
              </div>
            </div>
          ))}
        </RadioGroup>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label={t('settings.cap')} htmlFor="ai-cap" hint={t('settings.capHint')} error={err || undefined}>
            <Input id="ai-cap" type="number" min={1000} max={5000000} step={1000} value={cap} onChange={(e) => { setCap(e.target.value); setCapErr('') }} disabled={!admin} aria-invalid={err ? true : undefined} aria-describedby={err ? 'ai-cap-error' : 'ai-cap-hint'} />
          </Field>
          <div className="flex items-start gap-3 pt-6">
            <Switch id="ai-redact" checked={redact} onCheckedChange={setRedact} disabled={!admin} />
            <div className="grid gap-0.5">
              <Label htmlFor="ai-redact">{t('settings.redact')}</Label>
              <p className="text-[13px] text-muted">{t('settings.redactHint')}</p>
            </div>
          </div>
        </div>
        {save.error && !serverCap ? <div className="mt-3"><ActionError error={save.error} /></div> : null}
        <div className="mt-4"><Button type="submit" variant="primary" disabled={!admin || save.isPending} title={reason}>{save.isPending ? t('settings.saving') : t('common:save')}</Button></div>
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
      <Section title={t('settings.retention.title')} description={t('settings.retention.intro')} stories={['S-AI-8']}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t('settings.retention.label')} htmlFor="ai-retention" hint={t('settings.retention.hint')} error={err || undefined}>
            <Input id="ai-retention" type="number" min={90} max={3650} value={value} onChange={(e) => setDays(e.target.value)} disabled={!admin} aria-invalid={err ? true : undefined} />
          </Field>
        </div>
        {save.error ? <div className="mt-3"><ActionError error={save.error} /></div> : null}
        <div className="mt-4"><Button type="submit" variant="primary" disabled={!admin || !!err || save.isPending || cur.isPending} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })}>{t('common:save')}</Button></div>
      </Section>
    </form>
  )
}
