import { createElement, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Cable, FileSpreadsheet, PenLine, RadioTower, ServerCog, type LucideIcon } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { QueryState } from '@/components/common/States'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { useModuleEnabled, type ModuleId } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { cn } from '@/lib/utils'
import { AddForm } from './AddDeviceDialog'
import { WazuhForm } from './AgentsSection'
import { AddSnmpDevice } from './AddSnmpDevice'
import { AgentInstall } from './InstallAgent'
import { useAgents } from './api'
import { TurnOnModule } from './Inline'
import { ImportForm } from './ImportDialog'
import { dayOf } from '@/lib/format'

// "Add a device" (#849): ONE dialog with every way a device gets into the list. Manual is first and chosen on open, so the S-INV-2
// "three clicks" path stays three clicks; ?add=<method> opens it on a method (old ?tab=add, the device page's "Add SNMP / osquery").
export const METHODS = ['manual', 'snmp', 'osquery', 'wazuh', 'csv'] as const
export type Method = (typeof METHODS)[number]
const ICON: Record<Method, LucideIcon> = { manual: PenLine, snmp: RadioTower, osquery: ServerCog, wazuh: Cable, csv: FileSpreadsheet }

/** What a method needs that this person or box lacks. `role`: only an admin sets up secrets (SNMP, agents), so the method is locked
 *  with that reason (a role cannot be created here). `module`: the module it runs in is off; the method stays open and its panel turns
 *  the module on right there (#842 "do it where you are"). */
type Need = { role: string | null; module: ModuleId | null }
function useNeeds(): Record<Method, Need> {
  const { t } = useTranslation('inventory')
  const me = useMe()
  const admin = me.data ? me.data.role === 'admin' : true // unknown while loading: ?add=snmp must not fall back to Manual on the first paint
  const snmpOn = useModuleEnabled('sensor-active')
  const agentsOn = useModuleEnabled('agent-intake')
  const role = admin ? null : t('addDialog.adminOnly')
  return {
    manual: { role: null, module: null },
    csv: { role: null, module: null },
    snmp: { role, module: snmpOn === false ? 'sensor-active' : null },
    osquery: { role, module: agentsOn === false ? 'agent-intake' : null },
    wazuh: { role, module: agentsOn === false ? 'agent-intake' : null },
  }
}

/** osquery (S-INV-4): the person picks the operating system first, then sees the one install command; the manual way stays folded. */
function OsqueryMethod({ onCreated }: { onCreated: (on: boolean) => void }) {
  const { t } = useTranslation('inventory')
  const day = dayOf(new Date().toISOString())
  return (
    <div className="grid min-w-0 gap-3">
      <AgentInstall tokenName={t('addDialog.osquery.tokenName', { day })} onCreated={onCreated} />
    </div>
  )
}

function WazuhMethod({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation('inventory')
  const q = useAgents(true)
  return (
    <QueryState query={q}>
      {(d) => (
        <div className="grid min-w-0 gap-3">
          {d.wazuh ? <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.wazuh.connected', { url: d.wazuh.url })}>{t('addDialog.wazuh.connectedBody')}</Notice> : null}
          <WazuhForm current={d.wazuh} onSaved={onDone} />
        </div>
      )}
    </QueryState>
  )
}

/** The method picker: radio cards, one row on a wide dialog, a list of compact rows on a phone. A method that cannot be used says why. */
function MethodPicker({ value, onChange, needs }: { value: Method; onChange: (m: Method) => void; needs: Record<Method, Need> }) {
  const { t } = useTranslation('inventory')
  const uid = useId()
  return (
    <RadioGroup aria-label={t('addDialog.method')} value={value} onValueChange={(v) => onChange(v as Method)} className="grid grid-cols-1 gap-1.5 sm:grid-cols-5">
      {METHODS.map((m) => {
        const why = needs[m].role
        const off = needs[m].module
        const id = `${uid}-${m}`
        return (
          <label key={m} htmlFor={id} className={cn('flex min-h-10 cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 sm:min-h-0 sm:flex-col sm:items-start sm:gap-1.5',
            value === m ? 'border-accent bg-accent-soft' : 'border-rule bg-surface hover:bg-sunken', why && 'cursor-not-allowed opacity-60 hover:bg-surface')}>
            <span className="flex items-center gap-2">
              <RadioItem id={id} value={m} disabled={!!why} aria-describedby={why ? `${id}-why` : undefined} />
              {createElement(ICON[m], { className: cn('size-4 shrink-0', value === m ? 'text-accent' : 'text-muted'), 'aria-hidden': true })}
              <span className="text-sm font-medium">{t(`addDialog.name.${m}`)}</span>
            </span>
            <span id={why ? `${id}-why` : undefined} className="text-caption text-muted max-sm:ml-auto max-sm:text-right">{why ?? (off ? t('addDialog.moduleOff') : t(`addDialog.when.${m}`))}</span>
          </label>
        )
      })}
    </RadioGroup>
  )
}

export function AddDialog({ open, onOpenChange, method: initial = 'manual', onMethod }: { open: boolean; onOpenChange: (o: boolean) => void; method?: Method; onMethod?: (m: Method) => void }) {
  const { t } = useTranslation('inventory')
  const needs = useNeeds()
  const listOpenRef = useRef(false)
  const [picked, setPicked] = useState<Method | null>(null)
  const [tokenShown, setTokenShown] = useState(false)
  const method = picked ?? (needs[initial].role ? 'manual' : initial)
  const close = (o: boolean) => { onOpenChange(o); if (!o) { setPicked(null); setTokenShown(false) } }
  const choose = (m: Method) => { setPicked(m); setTokenShown(false); onMethod?.(m) }
  const done = () => close(false)
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent wide title={t('add.title')} description={t('addDialog.body')} info={t('addDialog.bodyInfo')}
        onEscapeKeyDown={(e) => { if (listOpenRef.current) e.preventDefault() }}
        // Focus starts on the chosen method (APG radio group), not on the title's ⓘ.
        onOpenAutoFocus={(e) => { const r = (e.currentTarget as HTMLElement | null)?.querySelector<HTMLElement>('[role="radio"][data-state="checked"]'); if (r) { e.preventDefault(); r.focus() } }}>
        {/* Once the osquery token is shown the picker goes: switching away would lose the only copy of the secret on screen. */}
        {tokenShown ? null : <MethodPicker value={method} onChange={choose} needs={needs} />}
        <section aria-label={t(`addDialog.name.${method}`)} className="grid min-w-0 grid-cols-1 gap-3 border-t border-rule pt-4 [&>*]:min-w-0">
          <div className="flex items-center gap-1">
            <h3 className="text-sm font-semibold">{t(`addDialog.title.${method}`)}</h3>
            <InfoTip topic={t(`addDialog.name.${method}`)}>{t(`addDialog.info.${method}`)}</InfoTip>
          </div>
          {method === 'manual' ? <AddForm key="manual" mode="device" onDone={done} listOpenRef={listOpenRef} /> : null}
          {needs[method].module ? <TurnOnModule id={needs[method].module!} reason={t(`addDialog.needs.${method}`)} /> : (
            <>
              {method === 'snmp' ? <AddSnmpDevice key="snmp" onDone={done} listOpenRef={listOpenRef} /> : null}
              {method === 'osquery' ? <OsqueryMethod key="osquery" onCreated={setTokenShown} /> : null}
              {method === 'wazuh' ? <WazuhMethod key="wazuh" onDone={done} /> : null}
            </>
          )}
          {method === 'csv' ? <ImportForm key="csv" onClose={done} /> : null}
        </section>
      </DialogContent>
    </Dialog>
  )
}
