import { Suspense, lazy } from 'react'
import { House, Search } from 'lucide-react'
import type { Feature } from '@/app/feature'
import { Loading } from '@/components/common/States'

const FeedsSettings = lazy(() => import('./FeedsSettings'))

// Module feeds (S-FEED-1/2/3, S-FEED-4/5). Mẫu tham chiếu cho mọi module FE: index.tsx · mocks.ts · api.ts · types.ts · *Page.tsx · *.test.tsx · locales/<lng>/feeds.json.
export const feature: Feature = {
  id: 'feeds',
  routes: [
    { index: true, lazy: () => import('./HomePage').then((m) => ({ Component: m.default })) },
    { path: 'lookup', lazy: () => import('./LookupPage').then((m) => ({ Component: m.default })) },
    { path: 'cve/:id', lazy: () => import('./CvePage').then((m) => ({ Component: m.default })) },
  ],
  nav: [
    { to: '/', label: 'common:shell.home', icon: House, module: 'feeds', group: 'monitor', order: 10, end: true },
    { to: '/lookup', label: 'common:shell.lookup', icon: Search, module: 'feeds', group: 'monitor', order: 40 },
  ],
  settings: [{ id: 'feeds', label: 'common:shell.feedsSettings', module: 'feeds', minRole: 'viewer', order: 25, element: <Suspense fallback={<Loading />}><FeedsSettings /></Suspense> }],
}
