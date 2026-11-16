import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useToggleModule } from '@/features/core/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { errText, useActions, useBlocklist } from './api'
import { undoable } from './state'

// D-624 (#819): AI response is left out of v1. A box that has it on keeps seeing it (D-403's pattern): no new action, every way back
// stays (frozen.ts), and turning the module off is offered with the list of what stays in force (CONTRACT "Khi tắt module").

/** Disables every form control inside: for the parts that only create or edit (catalog, never-touch list, settings form). */
export function Frozen({ on, children }: { on: boolean; children: ReactNode }) {
  if (!on) return <>{children}</>
  return <fieldset disabled className="m-0 min-w-0 border-0 p-0">{children}</fieldset>
}

const SHOWN = 8

/** What stays in force once the module is off (CONTRACT "Khi tắt module"): executed changes are not undone, firewalls keep the block
 *  list they last pulled, waiting requests can no longer be approved. Read from what the page already loads. */
export function InForce({ onRollBack }: { onRollBack?: () => void }) {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const actions = useActions()
  const block = useBlocklist(admin)
  const live = (actions.data?.items ?? []).flatMap((a) => a.items.filter(undoable).map((i) => ({ a, i })))
  const pending = (actions.data?.items ?? []).filter((a) => a.status === 'pending').length
  const entries = block.data?.entries.length ?? 0
  if (!live.length && !pending && !entries) return <p className="text-sm text-muted">{t('leaving.nothing')}</p>
  return (
    <div className="grid gap-2 text-sm">
      {live.length ? (
        <>
          <p className="font-medium">{t('leaving.inForce', { count: live.length })}</p>
          <ul className="grid list-disc gap-0.5 pl-5" aria-label={t('leaving.inForceList')}>
            {live.slice(0, SHOWN).map(({ a, i }) => (
              <li key={i.id}>{t('leaving.item', { title: i.title, device: a.asset_name })} <span className="text-muted">{i.remove_at ? t('leaving.until', { time: fmtDateTime(i.remove_at) }) : t('leaving.byHand')}</span></li>
            ))}
            {live.length > SHOWN ? <li className="text-muted">{t('leaving.more', { count: live.length - SHOWN })}</li> : null}
          </ul>
        </>
      ) : null}
      {entries ? <p>{t('leaving.blocklist', { count: entries })}</p> : null}
      {pending ? <p>{t('leaving.pending', { count: pending })}</p> : null}
      {live.length ? <p><Link to="/response?tab=requests&view=history" onClick={onRollBack} className="text-accent underline underline-offset-4">{t('leaving.rollBackFirst')}</Link></p> : null}
    </div>
  )
}

/** Slot `modules.disable` (Settings → Modules, turn-off dialog): the same list for AI response. */
export function ModulesDisableNote({ module, onClose }: Record<string, unknown>) {
  return module === 'response' ? <InForce onRollBack={onClose as (() => void) | undefined} /> : null
}

/** The way out: PATCH /modules/response off, after listing what stays in force. */
export function TurnOffResponse() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const [ask, setAsk] = useState(false)
  async function off() {
    try {
      await toggle.mutateAsync({ id: 'response', enabled: false })
      setAsk(false)
      toast.success(t('leaving.done'))
    } catch (e) { setAsk(false); toast.error(errText(e)) }
  }
  return (
    <>
      <Button disabled={!admin || toggle.isPending} title={admin ? undefined : t('leaving.needAdmin')} onClick={() => setAsk(true)}>{t('leaving.turnOff')}</Button>
      <Dialog open={ask} onOpenChange={setAsk}>
        <DialogContent title={t('leaving.title')} description={t('leaving.body')}>
          {ask ? <InForce onRollBack={() => setAsk(false)} /> : null}
          <DialogFooter>
            <Button onClick={() => setAsk(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={toggle.isPending} onClick={() => void off()}>{t('leaving.turnOff')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
