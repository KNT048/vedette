import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter, DialogTrigger } from '@/components/ui/dialog'
import { Field, Input, Label } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { InfoTip } from '@/components/common/InfoTip'
import { useCan } from '@/lib/session'
import { useAddNode, useDeleteNode, useEditNode } from './api'
import { needsProof } from './node'
import type { ScopeMode, TargetKind, TargetNode } from './types'

const SCOPES: ScopeMode[] = ['all', 'self', 'selected']
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** The scope choice of a domain: only this name, every name found under it, or the names the person chooses. */
function ScopeChoice({ id, value, onChange, name }: { id: string; value: ScopeMode; onChange: (v: ScopeMode) => void; name: string }) {
  const { t } = useTranslation('exposure')
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">{t('scope.label')}</legend>
      <RadioGroup value={value} onValueChange={(v) => onChange(v as ScopeMode)} aria-label={t('scope.label')}>
        {SCOPES.map((s) => (
          <div key={s} className="flex items-start gap-2.5">
            <RadioItem id={`${id}-${s}`} value={s} className="mt-1" />
            <label htmlFor={`${id}-${s}`} className="grid text-sm"><span className="font-medium">{name ? t(`scope.option.${s}`, { name }) : t(`scope.optionNoName.${s}`)}</span><span className="text-meta text-muted">{t(`scope.hint.${s}`)}</span></label>
          </div>
        ))}
      </RadioGroup>
    </fieldset>
  )
}

/** Add a domain or a public IP. A domain is placed under the domain target it is a name of; the dialog says so before it is added. */
export function AddTargetDialog({ items }: { items: TargetNode[] }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const add = useAddNode()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<TargetKind>('domain')
  const [value, setValue] = useState('')
  const [scope, setScope] = useState<ScopeMode>('all')
  const [error, setError] = useState<string | null>(null)
  // Cancel, Esc and X drop the draft and its error; while it is being added the dialog stays open, so a late answer never lands on a new draft.
  const toggle = (o: boolean) => { if (!o && add.isPending) return; setOpen(o); if (!o) { setError(null); setValue(''); setKind('domain'); setScope('all') } }
  const name = value.trim().toLowerCase().replace(/\.$/, '')
  // Where the new name goes, worked out as the box does it: under the nearest domain target it is a name of; targets under it move with it.
  const parent = kind === 'domain' && name ? items.filter((n) => n.kind === 'domain' && name.endsWith(`.${n.value}`)).sort((a, b) => b.value.length - a.value.length)[0] : undefined
  const children = kind === 'domain' && name ? items.filter((n) => n.kind === 'domain' && n.value.endsWith(`.${name}`)) : []
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!name) return setError(t(`add.empty.${kind}`))
    if (kind === 'domain' && IPV4.test(name)) return setError(t('add.isIp'))
    add.mutate({ value: name, kind, ...(kind === 'domain' ? { scope_mode: scope } : {}) }, {
      // After adding, the person goes into the target: to prove ownership there, unless an ancestor's proof covers it.
      onSuccess: (n) => { toast.success(t('add.toast', { value: n.value })); toggle(false); void nav(`/exposure/${encodeURIComponent(n.id)}${needsProof(n) ? '?tab=ownership' : ''}`) },
      onError: (er) => setError(errMsg(er)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={toggle}>
      <DialogTrigger asChild>
        <Button variant="primary" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Plus />{t('add.button')}</Button>
      </DialogTrigger>
      <DialogContent title={t('add.title')} description={t('add.description')} info={t('add.descriptionInfo')}>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <div className="grid justify-items-start gap-1">
            <span className="text-sm font-medium">{t('add.kind')}</span>
            <Segmented<TargetKind> label={t('add.kind')} value={kind} onChange={(k) => { setKind(k); setError(null) }}
              options={[{ value: 'domain', label: t('add.kindOption.domain') }, { value: 'ip', label: t('add.kindOption.ip') }]} />
          </div>
          <Field label={t(`add.label.${kind}`)} htmlFor="ex-new" hint={t(`add.hint.${kind}`)} info={t(`add.hintInfo.${kind}`)} error={error ?? undefined}>
            <Input id="ex-new" value={value} onChange={(e) => setValue(e.target.value)} autoFocus autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined} aria-describedby={error ? 'ex-new-error' : 'ex-new-hint'} />
          </Field>
          {parent ? <p role="status" className="text-meta">{t(parent.proof.state === 'proven' || parent.proof.state === 'covered' ? 'add.underCovered' : 'add.under', { parent: parent.value })}</p> : null}
          {children.length ? <p role="status" className="text-meta">{t('add.takesChildren', { count: children.length, list: children.map((c) => c.value).join(', ') })}</p> : null}
          {kind === 'domain' ? <ScopeChoice id="ex-new-scope" value={scope} onChange={setScope} name={name} /> : null}
          <DialogFooter>
            <Button onClick={() => toggle(false)} disabled={add.isPending}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" busy={add.isPending} busyLabel={t('common:busy.adding')}>{t('add.submit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Edit a target: a domain's scope, and whether it is scanned at all. The names of a chosen scope are picked on its Names tab. */
/** The one thing an address (not a domain) can edit, "Scan this target", as its switch in place of the Edit dialog. */
export function ScanToggle({ node, disabled, title }: { node: TargetNode; disabled: boolean; title?: string }) {
  const { t } = useTranslation('exposure')
  const edit = useEditNode(node.id)
  return (
    <span className="flex min-h-10 items-center gap-2" title={title}>
      <Switch id="ex-scan-target" checked={node.enabled} disabled={disabled || edit.isPending} aria-describedby="ex-scan-target-hint"
        onCheckedChange={(enabled) => edit.mutate({ enabled }, { onSuccess: () => toast.success(t('edit.toast', { value: node.value })), onError: (er) => toast.error(errMsg(er)) })} />
      <span className="flex items-center gap-1"><Label htmlFor="ex-scan-target">{t('edit.enabled')}</Label><InfoTip topic={t('edit.enabled')}>{t('edit.enabledInfo')}</InfoTip></span>
      <span id="ex-scan-target-hint" className="sr-only">{node.enabled ? t('edit.enabledOn') : t('edit.enabledOff')}</span>
    </span>
  )
}

export function EditTargetDialog({ node, open, onOpenChange }: { node: TargetNode; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('exposure')
  const edit = useEditNode(node.id)
  const [scope, setScope] = useState<ScopeMode>(node.scope_mode ?? 'all')
  const [enabled, setEnabled] = useState(node.enabled)
  const [error, setError] = useState<string | null>(null)
  // Every opening starts from the node as it is now.
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { setWasOpen(open); if (open) { setScope(node.scope_mode ?? 'all'); setEnabled(node.enabled); setError(null) } }
  const domain = node.kind === 'domain'
  const changed = enabled !== node.enabled || (domain && scope !== node.scope_mode)
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!changed) { onOpenChange(false); return }
    edit.mutate({ ...(domain && scope !== node.scope_mode ? { scope_mode: scope } : {}), ...(enabled !== node.enabled ? { enabled } : {}) }, {
      onSuccess: () => { toast.success(t('edit.toast', { value: node.value })); onOpenChange(false) },
      onError: (er) => setError(errMsg(er)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!edit.isPending) onOpenChange(o) }}>
      <DialogContent title={t('edit.title', { value: node.value })}>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <div className="flex items-center gap-3">
            <Switch id="ex-edit-enabled" checked={enabled} onCheckedChange={setEnabled} aria-describedby="ex-edit-enabled-hint" />
            <span className="flex items-center gap-1"><Label htmlFor="ex-edit-enabled">{t('edit.enabled')}</Label><InfoTip topic={t('edit.enabled')}>{t('edit.enabledInfo')}</InfoTip></span>
          </div>
          <p id="ex-edit-enabled-hint" className="-mt-2 text-meta text-muted">{enabled ? t('edit.enabledOn') : t('edit.enabledOff')}</p>
          {domain ? <ScopeChoice id="ex-edit-scope" value={scope} onChange={setScope} name={node.value} /> : null}
          {domain && scope === 'selected' && node.scope_mode !== 'selected' ? <p className="text-meta">{t('edit.chooseOnNames')}</p> : null}
          {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)} disabled={edit.isPending}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" busy={edit.isPending} busyLabel={t('common:busy.saving')}>{t('edit.submit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Delete a target. A public IP offers "Don't add it again if detected", ticked by default (an address the box uses but that is not the
 * company's must not come back). A domain says where the targets under it go and that a name its proof covered needs its own.
 */
export function DeleteTargetDialog({ node, items, open, onOpenChange, onDone }: { node: TargetNode; items: TargetNode[]; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const { t } = useTranslation('exposure')
  const del = useDeleteNode()
  const [ignore, setIgnore] = useState(true)
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { setWasOpen(open); if (open) setIgnore(true) }
  const ip = node.kind === 'ip'
  const children = items.filter((n) => n.parent_id === node.id)
  const parent = items.find((n) => n.id === node.parent_id)
  const covered = children.filter((c) => c.proof.covered_by?.id === node.id)
  const go = () => del.mutateAsync({ id: node.id, ignore: ip ? ignore : undefined }).then(() => {
    toast.success(t(ip && ignore ? 'delete.toastIgnored' : 'delete.toast', { value: node.value })); onOpenChange(false); onDone()
  }, (e: unknown) => toast.error(errMsg(e)))
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!del.isPending) onOpenChange(o) }}>
      <DialogContent title={t('delete.title', { value: node.value })} description={t('delete.body')} info={t('delete.bodyInfo')}>
        {children.length ? (
          <p className="text-sm">{t(parent ? 'delete.childrenUp' : 'delete.childrenTop', { count: children.length, list: children.map((c) => c.value).join(', '), parent: parent?.value })}
            {covered.length ? ` ${t('delete.needOwnProof', { count: covered.length })}` : ''}</p>
        ) : null}
        {ip ? (
          <div className="flex items-start gap-3">
            <Checkbox id="ex-del-ignore" checked={ignore} onCheckedChange={(v) => setIgnore(v === true)} className="mt-0.5" aria-describedby="ex-del-ignore-hint" />
            <div className="grid gap-1">
              <div className="flex items-center gap-1">
                <Label htmlFor="ex-del-ignore" className="font-normal">{t('boxIp.remove.ignoreLabel')}</Label>
                <InfoTip topic={t('boxIp.remove.ignoreLabel')}>{ignore ? t('boxIp.remove.ignoreOnInfo') : t('boxIp.remove.ignoreOffInfo')}</InfoTip>
              </div>
              <p id="ex-del-ignore-hint" className="text-meta text-muted">{ignore ? t('boxIp.remove.ignoreOn') : t('boxIp.remove.ignoreOff')}</p>
            </div>
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} disabled={del.isPending}>{t('common:cancel')}</Button>
          <Button variant="danger" busy={del.isPending} busyLabel={t('common:busy.deleting')} onClick={() => void go()}>{t('delete.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
