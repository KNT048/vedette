import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { fmtNumber } from '@/lib/format'

/**
 * Every AI output: dotted border + the label "AI generated, needs a person to confirm" (S-AI-6, legal rule: never remove the label).
 * `origin` tells the customer's own AI (BYOK) apart from the pack the Vedette project drafted with AI; the two are never mixed.
 * `status` (a pack a maintainer confirmed): its one status line, which itself says it was drafted with AI, in place of the label that
 * asks for a person's review (a person did review it).
 */
export function AiBlock({ children, model, tokens, origin = 'customer', citations, status }: { children: ReactNode; model?: string; tokens?: { input: number; output: number }; origin?: 'customer' | 'project'; citations?: { title: string; url?: string }[]; status?: ReactNode }) {
  const { t } = useTranslation()
  return (
    <div className="rounded-md border border-dotted border-muted/70 bg-surface p-4" data-ai="true">
      {status ? <div className="mb-3">{status}</div> : (
        <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-muted">
          <span className="font-medium text-ink">{t('ai.label')}</span>
          <span>{origin === 'customer' ? t('ai.originCustomer') : t('ai.originProject')}</span>
          {model ? <span>{t('ai.model', { model })}</span> : null}
          {tokens ? <span>{t('ai.tokens', { input: fmtNumber(tokens.input), output: fmtNumber(tokens.output) })}</span> : null}
        </div>
      )}
      <div className="grid gap-3 text-sm leading-relaxed">{children}</div>
      {citations ? (
        citations.length ? (
          <div className="mt-3 border-t border-rule pt-2 text-caption text-muted">
            {t('ai.sources')}{' '}
            {citations.map((c, i) => (
              <span key={`${c.url ?? c.title}-${i}`}>{i > 0 ? ', ' : ''}{c.url ? <a className="underline" href={c.url} target="_blank" rel="noopener noreferrer">{c.title}</a> : c.title}</span>
            ))}
          </div>
        ) : (
          <div className="mt-3 border-t border-rule pt-2 text-caption text-warn">{t('ai.noSources')}</div>
        )
      ) : null}
    </div>
  )
}
