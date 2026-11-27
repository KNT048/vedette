import { useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Input, Label } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { InfoTip } from '@/components/common/InfoTip'
import { useCan } from '@/lib/session'
import { useGreenbone, useSaveDeepSettings } from './api'
import { MAX_SKIP_PATHS, MAX_SKIP_PORTS } from './contract'
import { DISRUPTIVE, GROUPS, type Group } from './node'
import { useScope } from './ScanBar'
import type { DeepSettings, DeepSettingsBody, TargetNode } from './types'

const PATH_CHARS = /^[A-Za-z0-9._~%!&',;=:@/-]+$/
const MAX_PATH = 200
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const link = 'font-medium text-accent underline-offset-4 hover:underline'

const body = (s: DeepSettings): DeepSettingsBody => ({ dos: s.dos, logins: s.logins, web_active: s.web_active, data_change: s.data_change, openvas: s.openvas, speed: s.speed, skip_ports: s.skip_ports, skip_paths: s.skip_paths })

/** Ports typed or pasted (separated by spaces or commas) added to the list: sorted, without repeats; the first problem is said. */
function addPorts(draft: string, have: number[], t: TFunction): { next: number[]; error: string | null } {
  const next = [...have]
  for (const tok of draft.split(/[\s,]+/).filter(Boolean)) {
    const n = /^\d{1,5}$/.test(tok) ? Number(tok) : NaN
    if (!(n >= 1 && n <= 65535)) return { next: have, error: t('deepSettings.ports.bad', { value: tok.slice(0, 20) }) }
    if (!next.includes(n)) next.push(n)
  }
  if (next.length > MAX_SKIP_PORTS) return { next: have, error: t('deepSettings.ports.tooMany', { max: MAX_SKIP_PORTS }) }
  return { next: next.sort((a, b) => a - b), error: null }
}

/** Paths typed or pasted (separated by spaces) added to the list, each as written; the first problem is said. */
function addPaths(draft: string, have: string[], t: TFunction): { next: string[]; error: string | null } {
  const next = [...have]
  for (const p of draft.split(/\s+/).filter(Boolean)) {
    if (!p.startsWith('/')) return { next: have, error: t('deepSettings.paths.noSlash', { value: p.slice(0, 40) }) }
    if (p.length > MAX_PATH) return { next: have, error: t('deepSettings.paths.tooLong', { max: MAX_PATH }) }
    if (!PATH_CHARS.test(p)) return { next: have, error: t('deepSettings.paths.badChar', { value: p.slice(0, 40) }) }
    if (!next.includes(p)) next.push(p)
  }
  if (next.length > MAX_SKIP_PATHS) return { next: have, error: t('deepSettings.paths.tooMany', { max: MAX_SKIP_PATHS }) }
  return { next, error: null }
}

/** A list of values typed into one box: Enter or Add puts the draft in the list as chips, each with its own remove button. */
function ChipField({ id, label, help, info, items, draft, onDraft, onAdd, onRemove, error, placeholder }: {
  id: string; label: string; help: string; info: string; items: string[]; draft: string; onDraft: (v: string) => void; onAdd: () => void; onRemove: (v: string) => void; error: string | null; placeholder: string
}) {
  const { t } = useTranslation('exposure')
  const key = (e: KeyboardEvent<HTMLInputElement>) => { if (e.key === 'Enter') { e.preventDefault(); onAdd() } }
  return (
    <div className="grid gap-1.5">
      <div className="flex items-center gap-1"><Label htmlFor={id}>{label}</Label><InfoTip topic={label}>{info}</InfoTip></div>
      <p id={`${id}-help`} className="text-meta text-muted">{help}</p>
      {items.length ? (
        <ul className="flex flex-wrap gap-1.5" aria-label={label}>
          {items.map((v) => (
            <li key={v} className="inline-flex items-center gap-1 rounded-md border border-rule bg-surface py-0.5 pl-2 pr-0.5 font-mono text-meta">
              {v}
              <button type="button" className="rounded-sm p-1 text-muted hover:text-ink" aria-label={t('deepSettings.remove', { value: v })} onClick={() => onRemove(v)}><X className="size-3.5" aria-hidden /></button>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="flex gap-2">
        <Input id={id} value={draft} onChange={(e) => onDraft(e.target.value)} onKeyDown={key} placeholder={placeholder} autoComplete="off" spellCheck={false}
          aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-error ${id}-help` : `${id}-help`} />
        <Button onClick={onAdd} disabled={!draft.trim()}>{t('deepSettings.add')}</Button>
      </div>
      {error ? <p id={`${id}-error`} role="alert" className="text-meta text-danger">{error}</p> : null}
    </div>
  )
}

/**
 * How hard the deep scan may hit one target: the groups it may run, its speed, and the ports and web paths it leaves out. A dialog
 * over the target's page; the settings are saved whole. They only narrow what the testing terms allow, so a group that cannot run on
 * this target at all is shown off-limits with the same sentence the scan bar gives. An administrator saves; anyone else reads.
 */
export function DeepSettingsDialog({ node, open, onOpenChange }: { node: TargetNode; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const save = useSaveDeepSettings(node.id)
  const gb = useGreenbone()
  const { disruptive, line } = useScope(node)
  const [form, setForm] = useState<DeepSettingsBody>(() => body(node.deep_settings))
  const [portDraft, setPortDraft] = useState('')
  const [pathDraft, setPathDraft] = useState('')
  const [errors, setErrors] = useState<{ ports: string | null; paths: string | null }>({ ports: null, paths: null })
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  // Every opening starts from the settings the target has now.
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) {
    setWasOpen(open)
    if (open) { setForm(body(node.deep_settings)); setPortDraft(''); setPathDraft(''); setErrors({ ports: null, paths: null }); setError(null) }
  }
  const set = <K extends keyof DeepSettingsBody>(k: K, v: DeepSettingsBody[K]) => setForm((f) => ({ ...f, [k]: v }))
  const openvasOff = gb.data?.state === 'off' || gb.data?.state === 'unavailable'
  const reason = (g: Group): string | null => (DISRUPTIVE.includes(g) && !disruptive ? line : g === 'openvas' && openvasOff ? t('deepSettings.openvasOff') : null)

  /** Puts what is typed in a field into its list; false when it is refused (the problem is shown under the field). */
  function commitPorts(into: DeepSettingsBody): DeepSettingsBody | null {
    if (!portDraft.trim()) return into
    const r = addPorts(portDraft, into.skip_ports, t)
    setErrors((e) => ({ ...e, ports: r.error }))
    if (r.error) return null
    setPortDraft('')
    return { ...into, skip_ports: r.next }
  }
  function commitPaths(into: DeepSettingsBody): DeepSettingsBody | null {
    if (!pathDraft.trim()) return into
    const r = addPaths(pathDraft, into.skip_paths, t)
    setErrors((e) => ({ ...e, paths: r.error }))
    if (r.error) return null
    setPathDraft('')
    return { ...into, skip_paths: r.next }
  }
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    const withPorts = commitPorts(form)
    const withPaths = withPorts && commitPaths(withPorts)
    if (!withPaths) return
    setForm(withPaths)
    save.mutate(withPaths, {
      onSuccess: () => { toast.success(t('deepSettings.toast', { value: node.value })); onOpenChange(false) },
      onError: (er) => setError({ message: errMsg(er), code: (er as { code?: string }).code }),
    })
  }
  const stored = node.deep_settings
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!save.isPending) onOpenChange(o) }}>
      <DialogContent wide title={t('deepSettings.title', { value: node.value })} description={t('deepSettings.description')} info={t('deepSettings.descriptionInfo')}>
        <form onSubmit={submit} noValidate className="grid gap-5">
          {stored.problem ? <p role="alert" className="text-sm text-danger">{t('deepSettings.problem', { problem: stored.problem })}</p> : null}
          {!admin ? <p className="text-meta text-muted">{t('common:needRole', { role: t('common:role.admin') })}</p> : null}
          {!node.deep ? <p className="text-meta text-muted">{t('deepSettings.needTerms')}</p> : null}
          <fieldset disabled={!admin || save.isPending} className="grid gap-5">
            <legend className="sr-only">{t('deepSettings.title', { value: node.value })}</legend>
            {GROUPS.map((g) => {
              const why = reason(g)
              return (
                <div key={g} className="grid gap-1">
                  <div className="flex items-center gap-3">
                    <Switch id={`ds-${g}`} checked={form[g]} disabled={!!why} onCheckedChange={(v) => set(g, v)} aria-describedby={`ds-${g}-help`} />
                    <span className="flex items-center gap-1"><Label htmlFor={`ds-${g}`}>{t(`deepSettings.group.${g}.label`)}</Label><InfoTip topic={t(`deepSettings.group.${g}.label`)}>{t(`deepSettings.group.${g}.info`)}</InfoTip></span>
                  </div>
                  <p id={`ds-${g}-help`} className="text-meta text-muted">{t(`deepSettings.group.${g}.help`)}</p>
                  {why ? <p className="text-meta text-warn">{why}</p> : null}
                  {g === 'data_change' && !form.web_active ? <p className="text-meta text-muted">{t('deepSettings.group.data_change.needsWeb')}</p> : null}
                </div>
              )
            })}
            <div className="grid gap-1.5">
              <span className="text-sm font-medium">{t('deepSettings.speed.label')}</span>
              <Segmented<DeepSettings['speed']> label={t('deepSettings.speed.label')} value={form.speed} onChange={(v) => set('speed', v)}
                options={[{ value: 'normal', label: t('deepSettings.speed.normal') }, { value: 'gentle', label: t('deepSettings.speed.gentle') }]} />
              <p className="text-meta text-muted">{t(`deepSettings.speed.help.${form.speed}`)}</p>
            </div>
            <ChipField id="ds-ports" label={t('deepSettings.ports.label')} help={t('deepSettings.ports.help', { max: MAX_SKIP_PORTS })} info={t('deepSettings.ports.info')} placeholder={t('deepSettings.ports.placeholder')}
              items={form.skip_ports.map(String)} draft={portDraft} onDraft={(v) => { setPortDraft(v); setErrors((e) => ({ ...e, ports: null })) }} error={errors.ports}
              onAdd={() => { const f = commitPorts(form); if (f) setForm(f) }} onRemove={(v) => set('skip_ports', form.skip_ports.filter((p) => String(p) !== v))} />
            <ChipField id="ds-paths" label={t('deepSettings.paths.label')} help={t('deepSettings.paths.help', { max: MAX_SKIP_PATHS })} info={t('deepSettings.paths.info')} placeholder={t('deepSettings.paths.placeholder')}
              items={form.skip_paths} draft={pathDraft} onDraft={(v) => { setPathDraft(v); setErrors((e) => ({ ...e, paths: null })) }} error={errors.paths}
              onAdd={() => { const f = commitPaths(form); if (f) setForm(f) }} onRemove={(v) => set('skip_paths', form.skip_paths.filter((p) => p !== v))} />
          </fieldset>
          <p className="text-meta text-muted">{t('deepSettings.when')}</p>
          {error ? (
            <p role="alert" className="text-sm text-danger">{error.message}{error.code === 'twofa_required' ? <> <Link to="/settings/account?tab=sign-in#two-step" className={link}>{t('scan.needTwoStepLink')}</Link></> : null}</p>
          ) : null}
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)} disabled={save.isPending}>{admin ? t('common:cancel') : t('common:close')}</Button>
            {admin ? <Button type="submit" variant="primary" busy={save.isPending} busyLabel={t('common:busy.saving')}>{t('deepSettings.save')}</Button> : null}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
