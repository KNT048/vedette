import type { Feature } from '@/app/feature'

// The Help pages: the user cookbook (docs/cookbook) rendered from the build, so it works offline. The menu entry is the shell's
// (Sidebar, next to Settings); each main screen links to its own guide through PageHeader (components/common/HelpLink.tsx).
export const feature: Feature = {
  id: 'help',
  routes: [
    { path: 'help', lazy: () => import('./HelpPage').then((m) => ({ Component: m.HelpIndex })) },
    { path: 'help/:slug', lazy: () => import('./HelpPage').then((m) => ({ Component: m.HelpRecipe })) },
  ],
}
