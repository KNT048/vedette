import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { useToggleModule } from '@/features/core/api'
import { useCan } from '@/lib/session'
import { errText } from './api'

// D-624 (#819): AI response is left out of v1. A box that has it on keeps seeing it, read-only (D-403's pattern): the state is
// shown, every create, edit, approve and run control is disabled, and the one action left is turning the module off. The line
// under the page title ("Not part of v1: …") comes from PageHeader.


/** Disables every form control inside (buttons, inputs, switches) while leaving; links and disclosure rows still work. */
export function Frozen({ on, children }: { on: boolean; children: ReactNode }) {
  if (!on) return <>{children}</>
  return <fieldset disabled className="m-0 min-w-0 border-0 p-0">{children}</fieldset>
}

/** The way out: PATCH /modules/response off, after saying what is kept. */
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
      <Button variant="danger" disabled={!admin || toggle.isPending} title={admin ? undefined : t('leaving.needAdmin')} onClick={() => setAsk(true)}>{t('leaving.turnOff')}</Button>
      <Dialog open={ask} onOpenChange={setAsk}>
        <DialogContent title={t('leaving.title')} description={t('leaving.body')}>
          <DialogFooter>
            <Button onClick={() => setAsk(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={toggle.isPending} onClick={() => void off()}>{t('leaving.turnOff')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
