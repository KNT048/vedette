import { Link } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'

/** Connections live in core now (D-93): this tab only points to them, so old links with ?tab=connections still land somewhere useful. */
export default function ConnectionsMoved() {
  const { t } = useTranslation('ai')
  return (
    <Card className="text-sm">
      <p><Trans t={t} i18nKey="harness.conn.moved" components={{ go: <Link className="text-accent underline underline-offset-4" to="/settings/connections" /> }} /></p>
    </Card>
  )
}
