import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download, ExternalLink } from 'lucide-react'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useModules } from '@/lib/modules'
import { buildBundle, downloadBundle, issueUrl } from './bugReport'

/** S-CORE-5 (D-42): mô tả, xem trước gói chẩn đoán đã lọc, tải về, mở GitHub issue điền sẵn. Hộp không tự gửi gì. */
export function BugReportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('core')
  const { data } = useModules()
  const [text, setText] = useState({ what: '', steps: '', expected: '' })
  // Dựng lại mỗi lần mở để lấy lỗi mới nhất.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const bundle = useMemo(() => buildBundle(data?.modules), [data, open])
  const set = (k: keyof typeof text) => (e: { target: { value: string } }) => setText((s) => ({ ...s, [k]: e.target.value }))
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide title={t('bug.title')} description={t('bug.desc')}>
        <div className="grid gap-4">
          <p role="note" className="rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]">{t('bug.noSend')}</p>
          <Field label={t('bug.what')} htmlFor="bug-what"><Textarea id="bug-what" rows={3} value={text.what} onChange={set('what')} /></Field>
          <Field label={t('bug.steps')} htmlFor="bug-steps"><Textarea id="bug-steps" rows={3} value={text.steps} onChange={set('steps')} /></Field>
          <Field label={t('bug.expected')} htmlFor="bug-expected"><Textarea id="bug-expected" rows={2} value={text.expected} onChange={set('expected')} /></Field>
          <div className="grid gap-2">
            <p className="text-sm font-medium">{t('bug.bundle')}</p>
            <p className="text-[13px] text-muted">{t('bug.bundleDesc')}</p>
            <CodeBlock label={t('bug.bundleLabel')} code={JSON.stringify(bundle, null, 2)} />
          </div>
          <p className="text-[13px] text-muted">{t('bug.attach')}</p>
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
