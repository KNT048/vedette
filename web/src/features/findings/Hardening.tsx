import { useTranslation } from 'react-i18next'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import type { FindingDetail } from './types'

// Mitigation INV-8: general "Have I been hit?" checks for the software family, written by reviewed code. The generated firewall configs
// and their admin network field (M2-1) are gone: D-629, kien 2026-11-17 ("remove the General hardening feature that tells the user to
// allow traffic from the box to devices; it is useless").

/** "General hardening" label: code-written, never a Vedette recommendation for the CVE (D-21, FORBID-2). */
export function GeneralLabel() {
  const { t } = useTranslation('findings')
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Chip tone="off">{t('hardening.chip')}</Chip>
      <InfoTip topic={t('hardening.title')}>{t('hardening.chipInfo')}</InfoTip>
    </span>
  )
}

/** M2-1: general "Have I been hit?" checks for the software family when no confirmed pack lists signs for the CVE (INV-8). */
export function GeneralChecks({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const c = finding.hardening?.checks
  if (!c) return null
  return (
    <div className="grid gap-4" data-testid="general-checks">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 className="text-sm font-semibold">{t('hardening.checksTitle', { family: finding.hardening!.family })}</h3>
        <GeneralLabel />
      </div>
      <p className="max-w-3xl text-sm">{c.summary}</p>
      <ul className="grid gap-4">
        {c.indicators.map((i) => (
          <li key={i.title} className="grid gap-2">
            <p className="text-sm font-medium">{i.title}</p>
            <p className="max-w-3xl text-meta text-muted">{i.detail}</p>
            {i.commands?.map((cmd) => <CodeBlock key={cmd.label} code={cmd.code} label={cmd.label} wrapOnPhone />)}
          </li>
        ))}
      </ul>
      <div className="grid gap-1.5 border-t border-rule pt-3">
        <h3 className="text-sm font-semibold">{t('compromise.ifFound')}</h3>
        <ol className="grid list-decimal gap-1 pl-5 text-sm">{c.if_found.map((s) => <li key={s}>{s}</li>)}</ol>
      </div>
    </div>
  )
}
