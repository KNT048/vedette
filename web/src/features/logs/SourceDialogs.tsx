import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useAddSource, useDeleteSource, useEditSource } from './api'
import { CATALOG, GROUP_LABEL, GROUPS, searchCatalog } from './catalog'
import { BOX_PLACEHOLDER } from './snippets'
import { defaultPort } from './types'
import type { LogSource, Proto, SourceKind } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
type FormField = 'name' | 'ip' | 'proto' | 'port'
// The box names the wrong field by its code: the message goes under that field (a phone may have the top of the dialog scrolled away).
const FIELD_OF: Record<string, FormField> = { bad_name: 'name', bad_ip: 'ip', duplicate: 'ip', bad_proto: 'proto', tls_unavailable: 'proto', bad_port: 'port' }

/** Chọn loại thiết bị: ô tìm + danh sách theo nhóm. Enter chọn kết quả đầu tiên khi chỉ còn một. */
function KindPicker({ find, setFind, onPick }: { find: string; setFind: (v: string) => void; onPick: (k: SourceKind) => void }) {
  const { t } = useTranslation('logs')
  const hits = searchCatalog(find)
  return (
    <div className="grid gap-2">
      <Field label={t('form.kindSearch')} htmlFor="ls-find">
        <Input id="ls-find" type="search" autoFocus value={find} placeholder={t('form.kindPlaceholder')} autoComplete="off"
          onChange={(e) => setFind(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); if (hits.length === 1) onPick(hits[0]!.id) } }} />
      </Field>
      <p role="status" className="text-[13px] text-muted">{hits.length ? t('form.matches', { count: hits.length }) : t('form.noMatch', { q: find })}</p>
      <div className="max-h-72 overflow-y-auto rounded-md border border-rule" tabIndex={-1}>
        {GROUPS.map((g) => {
          const list = hits.filter((e) => e.group === g)
          if (!list.length) return null
          return (
            <section key={g} aria-label={GROUP_LABEL[g]}>
              <h3 className="sticky top-0 border-b border-rule bg-sunken px-3 py-1 text-[12px] font-medium uppercase tracking-wide text-muted">{GROUP_LABEL[g]}</h3>
              <ul>
                {list.map((e) => (
                  <li key={e.id}>
                    <button type="button" onClick={() => onPick(e.id)} className="flex min-h-9 w-full items-center justify-between gap-3 px-3 py-1.5 text-left text-sm hover:bg-sunken focus-visible:bg-sunken">
                      <span>{e.name}</span>
                      <span className="shrink-0 text-[12px] text-muted">{e.reads === 'parsed' ? t('config.parsed') : t('config.stored')}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )
        })}
      </div>
    </div>
  )
}

export function SourceFormDialog({ open, onOpenChange, source, onAdded }: { open: boolean; onOpenChange: (o: boolean) => void; source?: LogSource; onAdded?: (s: LogSource) => void }) {
  const { t } = useTranslation('logs')
  const add = useAddSource()
  const edit = useEditSource()
  const [kind, setKind] = useState<SourceKind | null>(source?.kind ?? null)
  const [find, setFind] = useState('')
  const [name, setName] = useState(source?.name ?? '')
  const [ip, setIp] = useState(source?.sender_ip ?? '')
  const [proto, setProto] = useState<Proto>(source?.proto ?? 'udp')
  const [port, setPort] = useState(String(source?.port ?? 514))
  const [error, setError] = useState<{ field?: FormField; message: string } | null>(null)
  const pending = add.isPending || edit.isPending
  const fieldErr = (f: FormField) => (error?.field === f ? error.message : undefined)
  const fixed = (f: FormField) => { if (error?.field === f) setError(null) }
  const aria = (f: FormField, hint: boolean) => ({ 'aria-invalid': fieldErr(f) ? true : undefined, 'aria-describedby': fieldErr(f) ? `ls-${f}-error` : hint ? `ls-${f}-hint` : undefined })
  const fail = (er: unknown) => {
    const field = er instanceof ApiError ? FIELD_OF[er.code] : undefined
    setError({ field, message: errMsg(er) })
    // Focus after React has drawn the error, so a screen reader reads the field with its message (ConnectionsSection does the same).
    if (field) setTimeout(() => document.getElementById(`ls-${field}`)?.focus(), 0)
  }

  function pickKind(k: SourceKind) {
    setKind(k)
    setError(null)
    const protos = CATALOG[k].protos
    if (!protos.includes(proto)) { setProto(protos[0]!); setPort(String(defaultPort(protos[0]!))) }
  }
  function changeProto(p: Proto) {
    fixed('proto')
    if (Number(port) === defaultPort(proto)) setPort(String(defaultPort(p)))
    setProto(p)
  }
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!kind) return
    const v = { kind, name: name.trim(), sender_ip: ip.trim(), proto, port: Number(port) }
    if (source) {
      edit.mutate({ ...v, id: source.id }, { onSuccess: () => { toast.success(t('form.edited')); onOpenChange(false) }, onError: fail })
    } else {
      add.mutate(v, { onSuccess: (s) => { toast.success(t('form.added')); onOpenChange(false); onAdded?.(s) }, onError: fail })
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={source ? t('form.editTitle') : t('form.addTitle')} description={source ? undefined : t('form.addDesc')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          {error && !error.field ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error.message}</p> : null}
          {kind ? (
            <div className="flex flex-wrap items-start justify-between gap-2 rounded-md border border-rule bg-sunken px-3 py-2">
              <div className="grid gap-0.5 text-sm">
                <span className="font-medium">{t('form.chosen', { name: CATALOG[kind].name })}</span>
                <span className="text-[13px] text-muted">{t('form.reads')}: {CATALOG[kind].readsNote}</span>
              </div>
              <Button size="sm" onClick={() => setKind(null)}>{t('form.change')}</Button>
            </div>
          ) : (
            <KindPicker find={find} setFind={setFind} onPick={pickKind} />
          )}
          {kind ? (<>
          <Field label={t('form.name')} hint={t('form.nameHint')} htmlFor="ls-name" error={fieldErr('name')}>
            <Input id="ls-name" value={name} onChange={(e) => { setName(e.target.value); fixed('name') }} autoComplete="off" required {...aria('name', true)} />
          </Field>
          <Field label={t('form.ip')} hint={t('form.ipHint')} htmlFor="ls-ip" error={fieldErr('ip')}>
            <Input id="ls-ip" value={ip} onChange={(e) => { setIp(e.target.value); fixed('ip') }} inputMode="decimal" autoComplete="off" required {...aria('ip', true)} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('form.proto')} htmlFor="ls-proto" error={fieldErr('proto')}>
              <Select id="ls-proto" value={proto} onChange={(e) => changeProto(e.target.value as Proto)} {...aria('proto', false)}>
                {CATALOG[kind].protos.map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </Select>
            </Field>
            <Field label={t('form.port')} hint={t('form.portHint')} htmlFor="ls-port" error={fieldErr('port')}>
              <Input id="ls-port" type="number" min={1} max={65535} value={port} onChange={(e) => { setPort(e.target.value); fixed('port') }} {...aria('port', true)} />
            </Field>
          </div>
          </>) : null}
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
            {kind ? <Button type="submit" variant="primary" disabled={pending}>{source ? t('common:save') : t('form.submitAdd')}</Button> : null}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function ConfigDialog({ source, boxIp, lan, onClose }: { source: LogSource | null; boxIp: string | null; lan: string | null; onClose: () => void }) {
  const { t } = useTranslation('logs')
  return (
    <Dialog open={source !== null} onOpenChange={(o) => { if (!o) onClose() }}>
      {source ? (() => {
        const e = CATALOG[source.kind]
        const ip = boxIp ?? BOX_PLACEHOLDER
        const ctx = { ip, port: source.port, proto: source.proto }
        return (
          <DialogContent wide title={t('config.title', { name: source.name })} description={t('config.target', { ip, port: source.port, proto: source.proto.toUpperCase(), sender: source.sender_ip })}>
            {boxIp ? null : <p role="alert" className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">{lan ? t('config.noIpLan', { lan, placeholder: BOX_PLACEHOLDER }) : t('config.noIp', { placeholder: BOX_PLACEHOLDER })}</p>}
            <p className="text-sm">{e.intro}</p>
            <p className="rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]"><span className="font-medium">{t('config.reads')}: </span>{e.readsNote}</p>
            <h3 className="text-sm font-medium">{t('config.steps')}</h3>
            <ol className="ml-5 grid list-decimal gap-1 text-sm">{e.steps(ctx).map((x) => <li key={x}>{x}</li>)}</ol>
            {e.snippets(ctx).map((x) => <CodeBlock key={x.label} label={x.label} code={x.code} />)}
            {e.notes.length ? <><h3 className="text-sm font-medium">{t('config.notes')}</h3><ul className="ml-5 grid list-disc gap-1 text-[13px] text-muted">{e.notes.map((x) => <li key={x}>{x}</li>)}</ul></> : null}
            <p className="text-sm font-medium">{t('config.verify')}</p>
            <DialogFooter><Button variant="primary" onClick={onClose}>{t('common:close')}</Button></DialogFooter>
          </DialogContent>
        )
      })() : null}
    </Dialog>
  )
}

export function DeleteDialog({ source, onClose }: { source: LogSource | null; onClose: () => void }) {
  const { t } = useTranslation('logs')
  const del = useDeleteSource()
  return (
    <Dialog open={source !== null} onOpenChange={(o) => { if (!o) onClose() }}>
      {source ? (
        <DialogContent title={t('form.deleteTitle', { name: source.name })} description={t('form.deleteBody')}>
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => del.mutate(source.id, { onSuccess: () => { toast.success(t('form.deleted')); onClose() }, onError: (e) => toast.error(errMsg(e)) })}>{t('common:delete')}</Button>
          </DialogFooter>
        </DialogContent>
      ) : null}
    </Dialog>
  )
}
