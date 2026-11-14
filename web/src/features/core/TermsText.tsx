import { useTranslation } from 'react-i18next'
import { TERMS, TERMS_VERSION } from 'virtual:terms'

/** One block of TERMS.md: a heading, a paragraph or a bullet list. */
type Block = { kind: 'h' | 'p'; text: string } | { kind: 'ul'; items: string[] }

/**
 * TERMS.md (D-544) as blocks. The file keeps to headings, paragraphs and "- " lists, and its only inline markup is a
 * link, shown as its text. ponytail: no Markdown library for one file the project writes; upgrade path: a renderer once
 * a second Markdown text is shown.
 */
function blocks(md: string): Block[] {
  const plain = (s: string) => s.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').trim()
  return md.split(/\n\s*\n/).flatMap((chunk): Block[] => {
    const lines = chunk.split('\n').filter((l) => l.trim())
    const first = lines[0]
    if (!first || first.startsWith('# ') || first.startsWith('Version: ')) return [] // the page has its own title and shows the version itself
    if (first.startsWith('## ')) return [{ kind: 'h', text: plain(first.slice(3)) }]
    if (first.startsWith('- ')) return [{ kind: 'ul', items: lines.map((l) => plain(l.replace(/^- /, ''))) }]
    return [{ kind: 'p', text: plain(lines.join(' ')) }]
  })
}

const BLOCKS = blocks(TERMS)

/** The terms of use in a scrolling box that keyboard users can scroll too (it takes focus). */
export function TermsText({ id }: { id?: string }) {
  const { t } = useTranslation('core')
  return (
    <div id={id} role="region" aria-label={t('setup.terms.region')} tabIndex={0}
      className="grid max-h-80 gap-3 overflow-y-auto rounded-md border border-rule bg-sunken p-4 text-sm">
      {BLOCKS.map((b, i) => b.kind === 'h'
        ? <h3 key={i} className="font-semibold">{b.text}</h3>
        : b.kind === 'ul'
          ? <ul key={i} className="grid list-disc gap-1.5 pl-5">{b.items.map((x, k) => <li key={k}>{x}</li>)}</ul>
          : <p key={i}>{b.text}</p>)}
      <p className="text-[13px] text-muted">{t('setup.terms.version', { version: TERMS_VERSION })}</p>
    </div>
  )
}
