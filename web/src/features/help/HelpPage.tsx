import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Markdown } from './Markdown'
import { RECIPES, recipeBySlug } from './cookbook'

/** /help: the guides of docs/cookbook, each with its goal. */
export function HelpIndex() {
  const { t } = useTranslation('help')
  return (
    <>
      <PageHeader title={t('title')} meta={t('meta')} />
      <ul aria-label={t('listLabel')} className="grid max-w-4xl gap-px overflow-hidden rounded-md border border-rule bg-rule">
        {RECIPES.map((r) => (
          <li key={r.slug} className="grid gap-1 bg-surface px-4 py-3">
            <Link to={`/help/${r.slug}`} className="font-medium text-accent underline-offset-4 hover:underline">{r.title}</Link>
            {r.goal ? <p className="text-meta text-muted">{r.goal}</p> : null}
          </li>
        ))}
      </ul>
      <p className="mt-4 max-w-3xl text-meta text-muted">{t('offline')}</p>
    </>
  )
}

/** /help/:slug: one recipe, rendered from its Markdown. */
export function HelpRecipe() {
  const { t } = useTranslation('help')
  const { slug } = useParams()
  const recipe = recipeBySlug(slug)
  if (!recipe) {
    return <EmptyState title={t('notFound.title')} action={<Link to="/help" className="text-accent underline-offset-4 hover:underline">{t('notFound.back')}</Link>}>{t('notFound.body')}</EmptyState>
  }
  return (
    <>
      <PageHeader breadcrumbs={[{ label: t('title'), to: '/help' }]} title={recipe.title} />
      <Markdown blocks={recipe.blocks} />
    </>
  )
}
