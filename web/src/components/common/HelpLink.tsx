import { Link, useInRouterContext, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { CircleHelp } from 'lucide-react'
import { guideOf } from '@/lib/guides'

function GuideLink() {
  const { t } = useTranslation()
  const guide = guideOf(useLocation().pathname)
  if (!guide) return null
  return (
    <Link to={`/help/${guide}`} className="inline-flex items-center gap-1.5 text-meta text-muted no-underline hover:text-ink hover:underline [&_svg]:size-4">
      <CircleHelp aria-hidden />{t('layout.guide')}
    </Link>
  )
}

/** "How-to guide": a link from a main screen to its Help page. Nothing outside a router (a component rendered alone in a test). */
export function HelpLink() {
  return useInRouterContext() ? <GuideLink /> : null
}
