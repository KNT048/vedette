import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ExternalLink } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { Field, Select } from '@/components/ui/input'
import { GUIDES, type Check, type GuideId } from './guideData'

const TONE: Record<Check, 'ok' | 'warn' | 'off'> = { vendor: 'ok', partial: 'warn', general: 'off' }

/** How to make the switch send a copy of traffic to the SPAN port, by switch vendor (D-56). */
export function SpanGuides({ spanPort }: { spanPort: string }) {
  const { t } = useTranslation('core')
  const [id, setId] = useState<GuideId | ''>('')
  const g = GUIDES.find((x) => x.id === id)
  return (
    <Section id="guides" title={t('network.guides.title')} description={t('network.guides.desc', { port: spanPort })} stories={['S-CORE-8']}>
      <div className="grid max-w-3xl gap-4">
        <Field label={t('network.guides.pick')} htmlFor="guide-vendor" className="max-w-sm">
          <Select id="guide-vendor" value={id} onChange={(e) => setId(e.target.value as GuideId | '')}>
            <option value="">{t('network.guides.choose')}</option>
            {GUIDES.map((x) => <option key={x.id} value={x.id}>{x.vendor}</option>)}
          </Select>
        </Field>
        {g ? (
          <div className="grid gap-3" aria-live="polite">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold">{g.vendor}</h3>
              <Chip tone={TONE[g.check]}>{t(`network.guides.check.${g.check}`)}</Chip>
            </div>
            <p className="text-[13px] text-muted">{t('network.guides.replace', { port: spanPort })}</p>
            {g.steps ? <ol className="grid max-w-2xl list-decimal gap-1 pl-5 text-sm">{g.steps.map((s) => <li key={s}>{s}</li>)}</ol> : null}
            {g.commands?.map((c) => <CodeBlock key={c.label} label={c.label} code={c.code} />)}
            {g.notes.length ? <ul className="grid max-w-2xl list-disc gap-1 pl-5 text-[13px] text-muted">{g.notes.map((n) => <li key={n}>{n}</li>)}</ul> : null}
            {g.source ? <a href={g.source} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 text-[13px] text-accent underline-offset-4 hover:underline">{t('network.guides.source')}<ExternalLink className="size-3.5" aria-hidden /></a> : null}
          </div>
        ) : <p className="text-sm text-muted">{t('network.guides.prompt')}</p>}
        <p className="max-w-2xl text-[13px] text-muted">{t('network.guides.after', { port: spanPort })}</p>
      </div>
    </Section>
  )
}
