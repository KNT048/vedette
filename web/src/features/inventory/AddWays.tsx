import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Cable, FileSpreadsheet, PenLine, Radar, ServerCog } from 'lucide-react'
import { Button, buttonVariants } from '@/components/ui/button'
import { download } from '@/lib/api'
import { useModuleEnabled } from '@/lib/modules'
import { cn } from '@/lib/utils'
import { errMsg } from './kinds'

function Way({ icon, title, when, children }: { icon: ReactNode; title: string; when: string; children: ReactNode }) {
  const { t } = useTranslation('inventory')
  return (
    <li className="grid content-start gap-2 rounded-md border border-rule bg-surface p-4">
      <h2 className="flex items-center gap-2 text-sm font-semibold">{icon}{title}</h2>
      <p className="text-[13px] text-muted"><span className="sr-only">{t('ways.when')}: </span>{when}</p>
      <div className="mt-1 flex flex-wrap items-center gap-2">{children}</div>
    </li>
  )
}

/** "Add devices" (D-471, kien item 10): every way Vedette learns about a device today, side by side, each with when to use it.
 *  Only ways that exist: network discovery, by hand, CSV, osquery, Wazuh. SSH, HTTP push and API keys have no code (plan §5). */
export function AddWays({ canOp, canAdmin, needRole, onAdd, onImport }: { canOp: boolean; canAdmin: boolean; needRole: string | undefined; onAdd: () => void; onImport: () => void }) {
  const { t } = useTranslation('inventory')
  const agentsOn = useModuleEnabled('agent-intake')
  const icon = 'size-4 text-muted'
  const setup = (to: string, label: string) => (canAdmin
    ? <Link to={to} className={cn(buttonVariants({ variant: 'secondary', size: 'sm' }))}>{label}</Link>
    : <p className="text-[13px] text-muted">{t('ways.adminOnly')}</p>)
  const agent = (label: string) => (agentsOn === false ? <p className="text-[13px] text-muted">{t('ways.agentsOff')}</p> : setup('/devices/setup#agents', label))
  return (
    <section aria-label={t('tabs.add')} className="grid gap-3">
      <p className="max-w-3xl text-[13px] text-muted">{t('ways.intro')}</p>
      <ul className="grid gap-3 md:grid-cols-2">
        <Way icon={<Radar className={icon} aria-hidden />} title={t('ways.discovery.title')} when={t('ways.discovery.when')}>
          {setup('/devices/setup', t('ways.discovery.action'))}
        </Way>
        <Way icon={<PenLine className={icon} aria-hidden />} title={t('ways.manual.title')} when={t('ways.manual.when')}>
          <Button size="sm" variant="primary" disabled={!canOp} title={needRole} onClick={onAdd}>{t('add.open')}</Button>
        </Way>
        <Way icon={<FileSpreadsheet className={icon} aria-hidden />} title={t('ways.csv.title')} when={t('ways.csv.when')}>
          <Button size="sm" disabled={!canOp} title={needRole} onClick={onImport}>{t('import.open')}</Button>
          <Button size="sm" variant="ghost" onClick={() => void download('/inventory/import-template.csv', 'vedette-devices-template.csv').catch((e: unknown) => toast.error(errMsg(e)))}>{t('import.template')}</Button>
        </Way>
        <Way icon={<ServerCog className={icon} aria-hidden />} title={t('ways.osquery.title')} when={t('ways.osquery.when')}>
          {agent(t('ways.osquery.action'))}
        </Way>
        <Way icon={<Cable className={icon} aria-hidden />} title={t('ways.wazuh.title')} when={t('ways.wazuh.when')}>
          {agent(t('ways.wazuh.action'))}
        </Way>
      </ul>
    </section>
  )
}
