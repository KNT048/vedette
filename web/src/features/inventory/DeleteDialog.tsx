import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { useCan } from '@/lib/session'

type AgentChoice = 'keep' | 'stop'

/** Confirm removing a device from the inventory (nothing is deleted on the real network). The removal stays: discovery keeps the
 *  device out (Removed, in To review). `agent`: an osquery agent is bound to the device, so the person chooses whether to stop it too
 *  (an administrator's choice) or remove the device only, and the dialog says what each does. `keepsOut`: the server's word that a
 *  removal keeps something out (DeviceDetail.removal_keeps: a fixed card on any address, or the address of a device with no card); when
 *  it keeps nothing, `privateMac` says why (a private Wi-Fi address rotates) and that it comes back. Declared software only: neither. */
export function DeleteDialog({ open, onOpenChange, name, findings, pending, onConfirm, agent = false, privateMac = false, keepsOut = true }: {
  open: boolean; onOpenChange: (o: boolean) => void; name: string; findings: number; pending: boolean; onConfirm: (agent?: AgentChoice) => void
  agent?: boolean; privateMac?: boolean; keepsOut?: boolean
}) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const [choice, setChoice] = useState<AgentChoice>(admin ? 'stop' : 'keep')
  const kept = keepsOut && (!agent || choice === 'stop')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('delete.title', { name })} description={<>{t('delete.body')} {kept ? t('delete.comesBack') : null}{!keepsOut && privateMac ? ` ${t('delete.comesBackPrivate')}` : null}{findings > 0 ? <strong className="mt-2 block font-medium text-ink">{t('delete.findings', { count: findings })}</strong> : null}</>}
        info={<><p>{t('delete.bodyInfo')}</p>{findings > 0 ? <p>{t('delete.findingsInfo')}</p> : null}</>}>
        {agent ? (
          <fieldset className="grid gap-2" data-testid="delete-agent-choice">
            <legend className="mb-1 text-sm font-medium">{t('delete.agentTitle')}</legend>
            <RadioGroup value={choice} onValueChange={(v) => setChoice(v as AgentChoice)} aria-label={t('delete.agentTitle')}>
              {(['stop', 'keep'] as const).map((c) => (
                <div key={c} className="flex items-start gap-2.5">
                  <RadioItem id={`delete-agent-${c}`} value={c} className="mt-1" disabled={c === 'stop' && !admin} />
                  <label htmlFor={`delete-agent-${c}`} className="grid text-sm">
                    <span className="font-medium">{t(c === 'stop' ? 'delete.agentStop' : 'delete.agentKeep')}</span>
                    <span className="text-meta text-muted">{c === 'stop' && !admin ? t('delete.agentStopAdmin') : t(c === 'stop' ? 'delete.agentStopBody' : 'delete.agentKeepBody')}</span>
                  </label>
                </div>
              ))}
            </RadioGroup>
          </fieldset>
        ) : null}
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" busy={pending} busyLabel={t('common:busy.deleting')} onClick={() => onConfirm(agent ? choice : undefined)}>{agent && choice === 'stop' ? t('delete.agentStop') : t('delete.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
