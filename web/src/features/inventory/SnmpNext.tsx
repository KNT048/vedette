import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { AddToScopeDialog, asRange, inRanges } from './AddToScopeDialog'
import { useDeviceAction, useSettings } from './api'
import { isPrivateCidr } from './validate'
import { DependencyLink } from '@/components/common/DependencyLink'
import { errMsg } from './kinds'
import type { SnmpCredential, SnmpTestResult } from './types'

/** What to do after an SNMP read that did not work, on the spot (#842 "do it where you are", kien 2026-11-16): fix the credential, add the
 *  address to its scope, approve the device and read again; what lives elsewhere (the scan scope) is one link to the exact tab. */
export function SnmpNext({ r, ip, cred, onWiden, onEdit, onRetry }: {
  r: SnmpTestResult; ip: string; cred: SnmpCredential | undefined; onWiden: () => void; onEdit: () => void; onRetry: () => void
}) {
  const { t } = useTranslation('inventory')
  const approve = useDeviceAction(r.device_id ?? '').approve
  const admin = useCan('admin')
  const lan = useSettings(admin).data?.lan_ranges
  const [toScope, setToScope] = useState<string | null | false>(false)
  const scope = '/devices/setup?tab=scope#range-input' // the range field of Scope (useDeepLinkTarget focuses it)
  const active = '/devices/setup?tab=scope#active-enabled' // the active scanning switch
  const scopeDialog = toScope !== false ? <AddToScopeDialog entry={toScope} onClose={() => setToScope(false)} onDone={onRetry} /> : null
  switch (r.reason) {
    case 'not_for_this_credential':
      return cred && cred.scope.length < 16 ? <div><Button size="sm" onClick={onWiden}>{t('sources.snmp.addToScope', { ip, name: cred.name })}</Button></div> : null
    case 'auth_failed': case 'unknown_user': case 'no_answer':
      return cred ? <div><Button size="sm" onClick={onEdit}>{t('snmpNext.edit', { name: cred.name })}</Button></div> : null
    case 'not_approved':
      return r.device_id ? (
        <div>
          <Button size="sm" variant="primary" busy={approve.isPending} busyLabel={t('common:busy.approving')}
            onClick={() => approve.mutate(undefined, { onSuccess: () => { toast.success(t('snmpNext.approved', { ip })); onRetry() }, onError: (e) => toast.error(errMsg(e)) })}>
            {t('snmpNext.approve', { ip })}
          </Button>
        </div>
      ) : null
    case 'out_of_scope': case 'scope_not_confirmed': {
      const entry = r.reason === 'out_of_scope' ? ip : null
      // Decide before offering "Add to scope" (r2 L4): a public address can never be in scope; one inside a saved range is excluded.
      if (entry && !isPrivateCidr(asRange(entry))) return <p className="text-meta text-muted">{t('snmpNext.publicWhy', { ip })}</p>
      if (entry && lan && inRanges(entry, lan)) return <DependencyLink reason={t('snmpNext.excludedWhy', { ip })} to="/devices/setup?tab=scope#excl-input" label={t('snmpNext.excluded')} />
      if (!admin) return <DependencyLink reason={t('snmpNext.scopeWhy')} to={scope} label={t('snmpNext.scope')} />
      return (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Button size="sm" variant="primary" onClick={() => setToScope(entry)}>{entry ? t('snmpNext.addToScope', { ip }) : t('snmpNext.confirmScope')}</Button>
          {scopeDialog}
        </div>
      )
    }
    case 'scanning_off':
      return <DependencyLink reason={t('snmpNext.scanningWhy')} to={active} label={t('snmpNext.scanning')} />
    case 'regular_scan_never':
      return r.device_id ? <DependencyLink reason={t('snmpNext.neverWhy')} to={`/devices/${encodeURIComponent(r.device_id)}`} label={t('snmpNext.never')} /> : null
    case 'not_in_inventory':
      // ponytail: no way yet to add an address the box has not found (asked of AI-Trưởng on #849); until then the next step is named.
      return <DependencyLink reason={t('snmpNext.notListedWhy')} to="/devices?tab=review" label={t('snmpNext.notListed')} />
    case 'declared_by_hand':
      // A device added manually is never probed (INV-5); turning it into a probed one needs the backend (asked on #849).
      return r.device_id ? <DependencyLink reason={t('snmpNext.manualWhy')} to={`/devices/${encodeURIComponent(r.device_id)}`} label={t('snmpNext.manual')} /> : null
    default:
      return null
  }
}
