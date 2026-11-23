import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download, ExternalLink } from 'lucide-react'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Notice } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useModules } from '@/lib/modules'
import { buildBundle, downloadBundle, issueUrl } from './bugReport'

/** S-CORE-5: a description, a preview of the filtered diagnostic bundle, a download, a pre-filled GitHub issue. The box sends nothing by itself. */
export function BugReportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('core')
  const { data } = useModules()
  const [text, setText] = useState({ what: '', steps: '', expected: '' })
  // Rebuilt on every open to get the latest errors.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const bundle = useMemo(() => buildBundle(data?.modules), [data, open])
  const set = (k: keyof typeof text) => (e: { target: { value: string } }) => setText((s) => ({ ...s, [k]: e.target.value }))
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide title={t('bug.title')} description={t('bug.desc')}>
        <div className="grid gap-4">
          <Notice tone="off" role="note" className="mb-0" title={t('bug.noSend')} info={t('bug.noSendInfo')} />
          <Field label={t('bug.what')} htmlFor="bug-what"><Textarea id="bug-what" rows={3} value={text.what} onChange={set('what')} /></Field>
          <Field label={t('bug.steps')} htmlFor="bug-steps"><Textarea id="bug-steps" rows={3} value={text.steps} onChange={set('steps')} /></Field>
          <Field label={t('bug.expected')} htmlFor="bug-expected"><Textarea id="bug-expected" rows={2} value={text.expected} onChange={set('expected')} /></Field>
          <div className="grid gap-2">
            <div className="flex items-center gap-1">
              <p className="text-sm font-medium">{t('bug.bundle')}</p>
              <InfoTip topic={t('bug.bundle')}>{t('bug.bundleInfo')}</InfoTip>
            </div>
            <p className="text-meta text-muted">{t('bug.bundleDesc')}</p>
            <CodeBlock label={t('bug.bundleLabel')} code={JSON.stringify(bundle, null, 2)} />
          </div>
          <div className="flex items-center gap-1">
            <p className="text-meta text-muted">{t('bug.attach')}</p>
            <InfoTip>{t('bug.attachInfo')}</InfoTip>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:close')}</Button>
          <Button onClick={() => downloadBundle(text, bundle)}><Download />{t('bug.download')}</Button>
          <Button variant="primary" onClick={() => window.open(issueUrl(text, bundle), '_blank', 'noopener,noreferrer')}><ExternalLink />{t('bug.open')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
