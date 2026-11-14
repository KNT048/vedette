import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Globe } from 'lucide-react'
import { Link } from 'react-router'
import { Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useCan } from '@/lib/session'
import { dateTimeText } from './dates'
import { useCheckOutside, useOutside } from './api'
import type { OutsideView, Target } from './types'

/** S-EXP-1, D-558: "What the Internet sees". Our scan runs from inside the network (NAT loopback); Shodan sees the IP from outside.
 * Nothing is sent until an administrator clicks and then confirms what is sent; every check is a click (no job, no polling). */
export function OutsidePanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const q = useOutside(target.id)
  const check = useCheckOutside()
  const [confirm, setConfirm] = useState(false)
  // Only the box's own verified IP that it still goes out through is sent (the server checks again, INV-21).
  const eligible = target.status === 'verified' && target.blocked_reason !== 'ip_not_current'
  const reason = !admin ? t('common:needRole', { role: t('common:role.admin') }) : !eligible ? t('outside.notEligible') : undefined
  const v = q.data ?? null
  function send() {
    check.mutate(target.id, {
      onSuccess: () => { setConfirm(false); toast.success(t('outside.toast', { ip: target.value })) },
      onError: (e) => { setConfirm(false); toast.error(e instanceof Error ? e.message : String(e)) },
    })
  }
  return (
    <Section id="outside" title={t('outside.title')} description={t('outside.description', { ip: target.value })}
      actions={<Button onClick={() => setConfirm(true)} disabled={!!reason || check.isPending} title={reason}><Globe />{v ? t('outside.again') : t('outside.button')}</Button>}>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : v ? <Answer v={v} /> : (
        <Panel className="max-w-3xl px-4 py-3 text-sm">{t('outside.never', { ip: target.value })}</Panel>
      )}
      {!eligible ? <p className="mt-2 max-w-3xl text-[13px] text-muted">{t('outside.notEligible')}</p> : null}
      <Dialog open={confirm} onOpenChange={(o) => { if (!check.isPending) setConfirm(o) }}>
        <DialogContent title={t('outside.confirmTitle', { ip: target.value })} description={t('outside.confirmBody', { ip: target.value })}>
          <DialogFooter>
            <Button onClick={() => setConfirm(false)} disabled={check.isPending}>{t('common:cancel')}</Button>
            <Button variant="primary" onClick={send} disabled={check.isPending}>{t('outside.send')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}

/** Shodan's answer beside our own newest scan: a port only one side saw is called out. Shodan's CVEs stay Shodan's claim. */
export function Answer({ v }: { v: OutsideView }) {
  const { t } = useTranslation('exposure')
  const ours = v.scan_ports
  const ports = [...new Set([...v.ports, ...(ours ?? [])])].sort((a, b) => a - b)
  return (
    <div className="grid max-w-3xl gap-3" data-testid="outside-answer">
      <p className="text-[13px] text-muted">{t('outside.asked', { time: dateTimeText(v.checked_at), by: v.checked_by })}</p>
      {!v.found ? <Panel className="px-4 py-3 text-sm">{t('outside.noRecord', { ip: v.ip })}</Panel> : null}
      {ours === null ? <p className="text-sm">{t('outside.notScanned', { ip: v.ip })}</p> : null}
      {ports.length > 0 ? (
        <Panel className="divide-y divide-rule">
          <h3 className="px-4 pt-3 text-sm font-medium">{t('outside.portsTitle')}</h3>
          {ports.map((p) => {
            const shodan = v.ports.includes(p), scan = ours?.includes(p) ?? false
            const key = ours === null ? 'shodanOnlyNoScan' : shodan && scan ? 'both' : shodan ? 'shodanOnly' : 'oursOnly'
            return (
              <div key={p} className="grid gap-1 px-4 py-3">
                <p className="flex flex-wrap items-center gap-2 text-sm">
                  <span className={key === 'shodanOnly' ? 'font-medium text-warn' : undefined}>{t(`outside.port.${key}`, { port: p })}</span>
                  {key === 'shodanOnly' ? <Chip tone="warn">{t('outside.onlyOutside')}</Chip> : null}
                </p>
                {key === 'shodanOnly' || key === 'oursOnly' ? <p className="text-[13px] text-muted">{t(`outside.hint.${key}`, { port: p })}</p> : null}
              </div>
            )
          })}
        </Panel>
      ) : null}
      {v.hostnames.length > 0 ? <p className="text-sm">{t('outside.hostnames', { list: v.hostnames.join(', ') })}</p> : null}
      {v.tags.length > 0 ? <p className="flex flex-wrap items-center gap-2 text-sm">{t('outside.tags')} {v.tags.map((x) => <Chip key={x} tone="off">{x}</Chip>)}</p> : null}
      {v.cpes.length > 0 ? <p className="break-all text-sm">{t('outside.cpes', { list: v.cpes.join(', ') })}</p> : null}
      {v.vulns.length > 0 ? (
        <Panel className="grid gap-1 px-4 py-3">
          <h3 className="text-sm font-medium">{t('outside.vulnsTitle', { count: v.vulns.length })}</h3>
          <p className="text-[13px] text-muted">{t('outside.vulnsNote')}</p>
          <ul className="grid gap-0.5 text-sm">{v.vulns.map((c) => <li key={c}>{t('outside.vuln', { cve: c })}</li>)}</ul>
        </Panel>
      ) : null}
    </div>
  )
}

/** The list page's "What the Internet sees" tab: the newest answer for each public IP of this box, read only; asking again happens on the IP's own page. */
export function OutsideList({ items }: { items: Target[] }) {
  const { t } = useTranslation('exposure')
  return (
    <Section id="outside-list" title={t('tabs.outside')} description={t('outsideList.description')}>
      {items.length === 0 ? <EmptyState title={t('outsideList.emptyTitle')}>{t('outsideList.emptyBody')}</EmptyState> : (
        <div className="grid gap-6">{items.map((x) => <OutsideOne key={x.id} target={x} />)}</div>
      )}
    </Section>
  )
}

function OutsideOne({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const q = useOutside(target.id)
  return (
    <div className="grid gap-2">
      <h3 className="flex flex-wrap items-center gap-3 text-sm font-medium">{target.value}
        <Link className="text-[13px] font-normal text-accent underline-offset-4 hover:underline" to={`/exposure/${target.id}?tab=outside`}>{t('outsideList.open', { ip: target.value })}</Link>
      </h3>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : q.data ? <Answer v={q.data} /> : (
        <Panel className="max-w-3xl px-4 py-3 text-sm">{t('outside.never', { ip: target.value })}</Panel>
      )}
    </div>
  )
}
