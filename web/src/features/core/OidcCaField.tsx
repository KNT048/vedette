import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Field, Textarea } from '@/components/ui/input'
import { fmtDate } from '@/lib/format'
import type { OidcConfig } from './types'

const SOON = 30 * 24 * 60 * 60 * 1000

/** D-378 (S-CORE-3): the CA of an identity provider behind a private CA. `value` undefined = unchanged (the saved text shows); the
 *  save sends `ca_pem` only once it is edited, so a save that leaves it alone keeps the saved CA; Remove sets it to "". */
export function OidcCaField({ cfg, value, error, onChange }: { cfg: OidcConfig; value: string | undefined; error?: string; onChange: (v: string) => void }) {
  const { t } = useTranslation('core')
  const text = value ?? cfg.ca_pem
  const edited = value !== undefined && value !== cfg.ca_pem
  const now = Date.now()
  return (
    <Field label={t('oidc.ca')} hint={t('oidc.caHint')} htmlFor="oidc-ca" error={error}>
      <Textarea id="oidc-ca" className="font-mono text-[12px]" rows={text ? 6 : 3} spellCheck={false} autoComplete="off" value={text} aria-invalid={!!error} onChange={(e) => onChange(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
      {cfg.ca_certs.length > 0 && !edited ? (
        <ul className="grid gap-0.5 text-[13px]" aria-label={t('oidc.caSavedList')}>
          {cfg.ca_certs.map((c, i) => {
            const left = Date.parse(c.expires_at) - now
            return (
              <li key={i} className={left < SOON ? 'text-danger' : 'text-muted'}>
                {t(left < 0 ? 'oidc.caExpired' : left < SOON ? 'oidc.caExpiring' : 'oidc.caSaved', { subject: c.subject, date: fmtDate(c.expires_at) })}
              </li>
            )
          })}
        </ul>
      ) : null}
      {text ? <div><Button size="sm" variant="ghost" onClick={() => onChange('')}>{t('oidc.caRemove')}</Button></div> : null}
    </Field>
  )
}
