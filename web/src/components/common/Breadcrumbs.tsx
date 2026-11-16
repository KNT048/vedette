import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ChevronRight } from 'lucide-react'

export type Crumb = { label: string; to: string }

/** The parents of a detail page, above its title (docs/UI.md §3); the h1 names the page itself, so it is not repeated here. */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  const { t } = useTranslation()
  if (!items.length) return null
  return (
    <nav aria-label={t('layout.breadcrumb')} className="mb-1.5">
      <ol className="flex flex-wrap items-center gap-1 text-meta text-muted">
        {items.map((c) => (
          <li key={c.to} className="inline-flex items-center gap-1">
            <Link to={c.to} className="no-underline hover:text-ink hover:underline">{c.label}</Link>
            <ChevronRight aria-hidden className="size-3.5" />
          </li>
        ))}
      </ol>
    </nav>
  )
}
