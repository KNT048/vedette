import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { fmtNumber } from '@/lib/format'

/**
 * Mọi output AI: viền chấm + nhãn "AI tạo, cần người xác nhận" (S-AI-6, rule legal.md: không gỡ nhãn).
 * `origin` phân biệt AI của khách (BYOK) với gói dự án Vedette soạn bằng AI (D-21) — không bao giờ trộn.
 */
export function AiBlock({ children, model, tokens, origin = 'customer', citations }: { children: ReactNode; model?: string; tokens?: { input: number; output: number }; origin?: 'customer' | 'project'; citations?: { title: string; url?: string }[] }) {
  const { t } = useTranslation()
  return (
    <div className="rounded-md border border-dotted border-muted/70 bg-surface p-4" data-ai="true">
      <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted">
        <span className="font-medium text-ink">{t('ai.label')}</span>
        <span>{origin === 'customer' ? t('ai.originCustomer') : t('ai.originProject')}</span>
        {model ? <span>{t('ai.model', { model })}</span> : null}
        {tokens ? <span>{t('ai.tokens', { input: fmtNumber(tokens.input), output: fmtNumber(tokens.output) })}</span> : null}
      </div>
      <div className="grid gap-3 text-sm leading-relaxed">{children}</div>
      {citations ? (
        citations.length ? (
          <div className="mt-3 border-t border-rule pt-2 text-[12px] text-muted">
            {t('ai.sources')}{' '}
            {citations.map((c, i) => (
              <span key={`${c.url ?? c.title}-${i}`}>{i > 0 ? ', ' : ''}{c.url ? <a className="underline" href={c.url} target="_blank" rel="noopener noreferrer">{c.title}</a> : c.title}</span>
            ))}
          </div>
        ) : (
          <div className="mt-3 border-t border-rule pt-2 text-[12px] text-warn">{t('ai.noSources')}</div>
        )
      ) : null}
    </div>
  )
}
