import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Globe } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { CveList } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { BusyNote } from '@/components/common/BusyNote'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useCan } from '@/lib/session'
import { InfoTip } from '@/components/common/InfoTip'
import { InfoLine } from '@/components/common/InfoLine'
import { useCheckOutside, useOutside } from './api'
import type { OutsideView, TargetNode } from './types'
import { fmtDateTime } from '@/lib/format'

/** S-EXP-1: "What the Internet sees". Our scan runs from inside the network (NAT loopback); Shodan sees the IP from outside.
 * Nothing is sent until an administrator clicks and then confirms what is sent; every check is a click (no job, no polling). */
export function OutsidePanel({ node: target }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const q = useOutside(target.id)
  const check = useCheckOutside()
  const [confirm, setConfirm] = useState(false)
  // Only a verified IP is sent: the box's own that it still goes out through, or a typed one whose proof is found now (the server checks again, INV-21).
  const eligible = target.proof.state === 'proven'
  const reason = !admin ? t('common:needRole', { role: t('common:role.admin') }) : !eligible ? t('outside.notEligible') : undefined
  const v = q.data ?? null
  function send() {
    check.mutate(target.id, {
      onSuccess: () => { setConfirm(false); toast.success(t('outside.toast', { ip: target.value })) },
      onError: (e) => { setConfirm(false); toast.error(e instanceof Error ? e.message : String(e)) },
    })
  }
  return (
    <Section id="outside" title={t('outside.title')} description={t('outside.description', { ip: target.value })} info={t('outside.descriptionInfo', { ip: target.value })}
      actions={<Button onClick={() => setConfirm(true)} disabled={!!reason} busy={check.isPending} busyLabel={t('common:busy.checking')} title={reason}><Globe />{v ? t('outside.again') : t('outside.button')}</Button>}>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : v ? <Answer v={v} /> : <Never ip={target.value} />}
      {!eligible ? <p className="mt-2 max-w-3xl text-meta text-muted">{t('outside.notEligible')}</p> : null}
      <Dialog open={confirm} onOpenChange={(o) => { if (!check.isPending) setConfirm(o) }}>
        <DialogContent title={t('outside.confirmTitle', { ip: target.value })} description={t('outside.confirmBody', { ip: target.value })} info={t('outside.confirmBodyInfo', { ip: target.value })}>
          {/* The box may re-check its IP first (5 rounds, 5 s each at most), then Shodan answers within 10 s */}
          <BusyNote busy={check.isPending}>{t('outside.waiting')}</BusyNote>
          <DialogFooter>
            <Button onClick={() => setConfirm(false)} disabled={check.isPending}>{t('common:cancel')}</Button>
            <Button variant="primary" onClick={send} busy={check.isPending} busyLabel={t('common:busy.sending')}>{t('outside.send')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}

/** No Shodan answer yet for this IP: nothing has been sent. */
function Never({ ip }: { ip: string }) {
  const { t } = useTranslation('exposure')
  return <Panel className="max-w-3xl px-4 py-3 text-sm"><InfoLine topic={t('outside.title')} info={t('outside.neverInfo')}>{t('outside.never', { ip })}</InfoLine></Panel>
}

/** Shodan's answer beside our own newest scan: a port only one side saw is called out. Shodan's CVEs stay Shodan's claim. */
export function Answer({ v }: { v: OutsideView }) {
  const { t } = useTranslation('exposure')
  const ours = v.scan_ports
  const ports = [...new Set([...v.ports, ...(ours ?? [])])].sort((a, b) => a - b)
  return (
    <div className="grid max-w-3xl gap-3" data-testid="outside-answer">
      <InfoLine className="text-meta text-muted" topic={t('outside.title')} info={t('outside.askedInfo')}>{t('outside.asked', { time: fmtDateTime(v.checked_at), by: v.checked_by })}</InfoLine>
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
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className={key === 'shodanOnly' ? 'font-medium text-warn' : undefined}>{t(`outside.port.${key}`, { port: p })}</span>
                  {key === 'shodanOnly' ? <span className="flex items-center gap-1"><Chip tone="warn">{t('outside.onlyOutside')}</Chip><InfoTip topic={t('outside.onlyOutside')}>{t('outside.hint.shodanOnlyInfo')}</InfoTip></span> : null}
                  {key === 'oursOnly' ? <InfoTip topic={t(`outside.port.${key}`, { port: p })}>{t('outside.hint.oursOnly', { port: p })}</InfoTip> : null}
                </div>
                {key === 'shodanOnly' ? <p className="text-meta text-muted">{t('outside.hint.shodanOnly')}</p> : null}
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
          <div className="flex items-center gap-1">
            <h3 className="text-sm font-medium">{t('outside.vulnsTitle', { count: v.vulns.length })}</h3>
            <InfoTip topic={t('outside.vulnsTitle', { count: v.vulns.length })}>{t('outside.vulnsNote')}</InfoTip>
          </div>
          <CveList items={v.vulns.map((cve) => ({ cve }))} label={t('outside.vulnsTitle', { count: v.vulns.length })} />
        </Panel>
      ) : null}
    </div>
  )
}
