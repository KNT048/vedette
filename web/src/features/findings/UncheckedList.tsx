// #910 phase 1: exploited CVEs of software the box has that it could not check are shown, never silent.
// No finding is created from this list; the customer checks the advisory. The lines sit in their device's block of Needs
// your input (NeedsInput.tsx), each with its next step there.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import type { UncheckedItem } from './types'

/** Home's "could not be checked" link lands here (`/findings?tab=input#unchecked`). */
export const UNCHECKED_ANCHOR = 'unchecked'
const SHOWN = 3

/** A software name with its version, once: a scanner's name often already ends with the version ("OpenSSH 10.2"). */
export function nameWithVersion(name: string, version?: string | null): string {
  const v = version?.trim()
  if (!v) return name
  return name.split(/\s+/).includes(v) ? name : `${name} ${v}`
}

const nvdUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`

/** One software of a device that could not be checked: why, in plain words, and its CVEs with their advisory (three, then "Show N more"). */
export function UncheckedLine({ item }: { item: UncheckedItem }) {
  const { t } = useTranslation('findings')
  const [all, setAll] = useState(false)
  const shown = all ? item.cves : item.cves.slice(0, SHOWN)
  return (
    <div className="grid gap-1">
      <p className="text-sm">
        <span className="font-medium">{nameWithVersion(item.software, item.version)}</span>
        {' - '}{t(`unchecked.reason.${item.reason === 'not_comparable' && !item.version ? 'not_comparable_none' : item.reason}`, { software: item.software, version: item.version ?? '' })}
      </p>
      <ul className="grid gap-0.5 pl-4 text-meta">
        {shown.map((c) => (
          <li key={c.cve} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <a href={c.advisory ?? nvdUrl(c.cve)} target="_blank" rel="noreferrer noopener" className="text-accent underline-offset-4 hover:underline"
              aria-label={t(c.advisory ? 'unchecked.advisoryLabel' : 'unchecked.nvdLabel', { cve: c.cve })}>{c.cve}</a>
            <span>{c.name}</span>
            {c.ransomware ? <Chip tone="danger">{t('unchecked.ransomware')}</Chip> : null}
          </li>
        ))}
      </ul>
      {item.cves.length > SHOWN ? (
        <div className="pl-4"><Button size="sm" variant="ghost" aria-expanded={all} onClick={() => setAll(!all)}>
          {all ? t('unchecked.less') : t('unchecked.more', { count: item.cves.length - SHOWN })}
        </Button></div>
      ) : null}
    </div>
  )
}
