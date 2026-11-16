import { cn } from '@/lib/utils'

// The #827 line drawings (docs/brand/README.md): 240×160, one stroke, currentColor only, so they take the theme through `text-accent`.
// They are static files of the build, imported as text and inlined so currentColor works (an <img> cannot inherit it). This is the
// only dangerouslySetInnerHTML in src and it never receives data (docs/UI.md §6).
const FILES = import.meta.glob<string>('../../assets/illustrations/*.svg', { query: '?raw', import: 'default', eager: true })

export type IllustrationName = 'no-devices' | 'no-findings' | 'no-alerts' | 'scanning' | 'welcome' | 'setup-done'

const svg = (name: IllustrationName) => FILES[`../../assets/illustrations/${name}.svg`] ?? ''

/** Decorative (aria-hidden): the text next to it carries the meaning. 180×120, 120×80 on phones. */
export function Illustration({ name, className }: { name: IllustrationName; className?: string }) {
  return <span aria-hidden className={cn('block h-20 w-30 text-accent sm:h-30 sm:w-45 [&>svg]:size-full', className)} dangerouslySetInnerHTML={{ __html: svg(name) }} />
}
