import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState, Loading, RequireModule } from '@/components/common/States'
import { PageModule } from '@/lib/v1'
import { useMe } from '@/lib/session'
import History from './History'

/** Settings › Alert channels › History (/settings/channels/history): a page of its own, reached from the Alert channels header and from
 *  every link to the send history. The same gate as the Alert channels section: administrators, with the notify module on. */
export default function HistoryPage() {
  const { t } = useTranslation(['notify', 'core'])
  const me = useMe()
  const crumbs = [{ label: t('channels.title'), to: '/settings/channels' }]
  if (me.isPending) return <Loading />
  if (me.data?.role !== 'admin') {
    return (
      <>
        {/* no link to Alert channels: only an administrator can open it */}
        <PageHeader title={t('history.pageTitle')} />
        <EmptyState title={t('core:settings.needRole.title', { name: t('history.pageTitle') })}>{t('core:settings.needRole.body', { role: t('common:role.admin') })}</EmptyState>
      </>
    )
  }
  return (
    <PageModule.Provider value="notify">
      <RequireModule module="notify" page>
        <PageHeader breadcrumbs={crumbs} title={t('history.pageTitle')} meta={t('history.description')} info={<><p>{t('history.metaInfo')}</p><p>{t('history.retention')}</p></>} stories={['S-NOT-1']} />
        <History />
      </RequireModule>
    </PageModule.Provider>
  )
}
