import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'

/** The "Sample data" label when running on the mock API (risk: testers trusting fake data, ROADMAP). */
export function SampleDataNote() {
  const { t } = useTranslation()
  // Same queryKey as useSetup (src/app/RequireSession.tsx). A clean install → no sample data to label.
  const setup = useQuery({ queryKey: ['setup'], queryFn: () => api.get<{ complete: boolean; org: string; data_mode?: 'sample' | 'clean' }>('/setup'), staleTime: 60_000 })
  if (import.meta.env.VITE_API_MOCK === 'off' || setup.data?.data_mode !== 'sample') return null
  return <span className="inline-flex h-6 items-center rounded-sm border border-rule bg-sunken px-2 text-caption text-muted">{t('sampleData')}</span>
}
