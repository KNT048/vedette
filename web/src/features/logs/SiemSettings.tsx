import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Send } from 'lucide-react'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { QueryState, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useModules } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useSaveSiem, useSiem, useTestSiem } from './api'
import { siemSample } from './snippets'
import { SIEM_EVENTS } from './types'
import type { Proto, SiemConfig, SiemEvent, SiemFormat } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))

function randomKey() {
  const b = new Uint8Array(24)
  crypto.getRandomValues(b)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

function SiemForm({ cfg }: { cfg: SiemConfig }) {
  const { t } = useTranslation('logs')
  const isAdmin = useCan('admin')
  const save = useSaveSiem()
  const test = useTestSiem()
  const [enabled, setEnabled] = useState(cfg.enabled)
  const [format, setFormat] = useState<SiemFormat>(cfg.format)
  const [host, setHost] = useState(cfg.host)
  const [port, setPort] = useState(String(cfg.port))
  const [proto, setProto] = useState<Proto>(cfg.proto)
  const [url, setUrl] = useState(cfg.url)
  const [secret, setSecret] = useState('')
  const [events, setEvents] = useState<SiemEvent[]>(cfg.events)
  const [error, setError] = useState<string | null>(null)
  const busy = save.isPending || test.isPending
  // D-420 (5): a container-only install has no honeypot (available false, D-381), so it has no touches to forward.
  const noHoneypot = useModules().data?.modules.find((m) => m.id === 'honeypot')?.available === false
  const shown = (ev: SiemEvent) => !(noHoneypot && ev === 'honeypot')

  const body = () => ({ enabled, format, host: host.trim(), port: Number(port), proto, url: url.trim(), events: events.filter(shown), secret: secret || undefined })
  function onSave(e: { preventDefault(): void }, thenTest = false) {
    e.preventDefault()
    setError(null)
    save.mutate(body(), {
      onSuccess: () => {
        setSecret('')
        toast.success(t('siem.saved'))
        if (thenTest) test.mutate(undefined, { onSuccess: (r) => (r.ok ? toast.success(t('siem.testOk')) : toast.error(r.detail)), onError: (er) => setError(errMsg(er)) })
      },
      onError: (er) => setError(errMsg(er)),
    })
  }
  const toggleEvent = (ev: SiemEvent, on: boolean) => setEvents((l) => (on ? [...l, ev] : l.filter((x) => x !== ev)))
  const last = cfg.last_test

  return (
    <form onSubmit={onSave} className="grid max-w-2xl gap-5" noValidate>
      {error ? <Notice tone="danger" role="alert" title={error} className="mb-0" /> : null}
      <div className="flex items-center gap-3">
        <Switch id="siem-enabled" checked={enabled} onCheckedChange={setEnabled} disabled={!isAdmin} />
        <Label htmlFor="siem-enabled">{t('siem.enabled')}</Label>
      </div>
      <Segmented label={t('siem.format')} value={format} onChange={setFormat} options={(['syslog', 'cef', 'json'] as const).map((f) => ({ value: f, label: t(`siem.formats.${f}`) }))} />
      <fieldset disabled={!isAdmin} className="grid gap-4 border-0 p-0">
        {format === 'json' ? (
          <>
            <Field label={t('siem.url')} hint={t('siem.urlHint')} htmlFor="siem-url"><Input id="siem-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://siem.acme.example/hooks/vedette" autoComplete="off" aria-describedby="siem-url-hint" /></Field>
            <Field label={t('siem.secret')} hint={cfg.secret_last4 ? t('siem.secretSaved', { last4: cfg.secret_last4 }) : t('siem.secretHint')} htmlFor="siem-secret">
              <div className="flex gap-2">
                <Input id="siem-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" aria-describedby="siem-secret-hint" />
                <Button onClick={() => setSecret(randomKey())}>{t('siem.generate')}</Button>
              </div>
            </Field>
          </>
        ) : (
          <div className="grid gap-4 sm:grid-cols-[1fr_120px_120px]">
            <Field label={t('siem.host')} hint={t('siem.hostHint')} htmlFor="siem-host"><Input id="siem-host" value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" aria-describedby="siem-host-hint" /></Field>
            <Field label={t('siem.port')} htmlFor="siem-port"><Input id="siem-port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} /></Field>
            <Field label={t('siem.proto')} htmlFor="siem-proto"><Select id="siem-proto" value={proto} onChange={(e) => setProto(e.target.value as Proto)}>{(['udp', 'tcp', 'tls'] as const).map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}</Select></Field>
          </div>
        )}
        <div role="group" aria-labelledby="siem-events-label" className="grid gap-2">
          <span id="siem-events-label" className="text-sm font-medium">{t('siem.events')}</span>
          {SIEM_EVENTS.map((ev) => (
            <div key={ev} className="flex flex-wrap items-center gap-x-2">
              <Checkbox id={`siem-ev-${ev}`} checked={shown(ev) && events.includes(ev)} disabled={!shown(ev)} aria-describedby={shown(ev) ? undefined : 'siem-ev-honeypot-why'} onCheckedChange={(c) => toggleEvent(ev, c === true)} />
              <Label htmlFor={`siem-ev-${ev}`} className={shown(ev) ? 'font-normal' : 'font-normal text-muted'}>{t(`siem.event.${ev}`)}</Label>
              {shown(ev) ? null : <span id="siem-ev-honeypot-why" className="text-[13px] text-muted">{t('siem.noHoneypot')}</span>}
            </div>
          ))}
        </div>
      </fieldset>
      <CodeBlock label={t('siem.sample')} code={siemSample(format)} />
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" variant="primary" disabled={!isAdmin || busy} title={isAdmin ? undefined : t('siem.adminOnly')}>{t('siem.save')}</Button>
        <Button disabled={!isAdmin || busy} title={isAdmin ? undefined : t('siem.adminOnly')} onClick={(e) => onSave(e, true)}><Send />{test.isPending ? t('siem.testing') : t('siem.saveTest')}</Button>
      </div>
      {last ? <p role="status" className={last.ok ? 'text-sm text-ok' : 'text-sm text-danger'}>{t(last.ok ? 'siem.lastOk' : 'siem.lastFail', { time: fmtDateTime(last.at), detail: last.detail })}</p> : null}
    </form>
  )
}

export default function SiemSettings() {
  const { t } = useTranslation('logs')
  const q = useSiem()
  return (
    <RequireModule module="logs">
      <PageHeader title={t('siem.title')} meta={t('siem.description')} stories={['S-LOG-3']} />
      <QueryState query={q}>{(cfg) => <SiemForm cfg={cfg} />}</QueryState>
    </RequireModule>
  )
}
