import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Plus } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { declaredSoftwareOnly, hasSourcesCard } from './nameOf'
import type { DeviceDetail } from './types'

type A = DeviceDetail['asset']

/** A watched device Vedette cannot check: it knows no software or firmware the device runs (every line gone or marked not installed,
 *  and no OS the device states or a source reads; a network scan's fingerprint guess is matched against nothing). No exploited
 *  vulnerability can match it, so its empty findings say nothing about it. Not the box (it reads its own packages), not a device
 *  waiting for review or ignored (not watched), not a product declared without a device. */
export const uncheckable = (a: A) =>
  a.approved && !a.is_box && !a.ignored_at && !declaredSoftwareOnly(a) && !a.software.some((s) => !s.not_installed) &&
  !(a.os && a.os.basis !== 'guess' && !a.os.software_id)

/**
 * What to do to get such a device checked, at the top of its page: a firewall whose SNMP read fails and whose scan sees only an SSH
 * port otherwise sits with "no findings" that reads as safe. The notice says what Vedette tried (the open ports a scan saw) and the
 * three ways it learns what runs there: the version typed by a person (Add its firmware), SNMP read access (the Sources card) or an
 * agent on a computer.
 */
export function UncheckableNotice({ a, onAdd }: { a: A; onAdd: () => void }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  if (!uncheckable(a)) return null
  const ports = a.services.length
  return (
    <Notice tone="warn" role="note" data-testid="uncheckable" title={t('uncheckable.title')} info={t('uncheckable.info')}
      actions={<Button disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={onAdd}><Plus />{t('uncheckable.add')}</Button>}>
      <p>{ports ? t('uncheckable.bodyPorts', { count: ports }) : t('uncheckable.body')}</p>
      <ul className="mt-1 list-disc pl-5">
        <li>{t('uncheckable.wayVersion')}</li>
        {hasSourcesCard(a) ? (
          <li>{t('uncheckable.waySnmp')} <Link to="?tab=overview#sources" className="font-medium text-accent underline-offset-4 hover:underline">{t('uncheckable.waySnmpLink')}</Link></li>
        ) : null}
        <li>{t('uncheckable.wayAgent')} <Link to="/devices/setup?tab=agents" className="font-medium text-accent underline-offset-4 hover:underline">{t('uncheckable.wayAgentLink')}</Link></li>
      </ul>
    </Notice>
  )
}
