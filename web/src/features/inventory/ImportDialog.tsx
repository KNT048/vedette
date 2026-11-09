import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Upload } from 'lucide-react'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/input'
import { download } from '@/lib/api'
import { useImportDevices } from './api'
import { errMsg, readText, sha256Hex } from './kinds'
import type { ImportResult } from './types'

const MAX_BYTES = 200_000

function ImportForm({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const input = useRef<HTMLInputElement>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const imp = useImportDevices()

  async function onFile(file: File | undefined) {
    setError(null); setResult(null)
    if (!file) return
    if (file.size > MAX_BYTES) { setError(t('import.tooLarge', { kb: MAX_BYTES / 1000 })); return }
    try {
      const text = await readText(file)
      const sha256 = await sha256Hex(text)
      imp.mutate({ filename: file.name, size: file.size, sha256, text }, {
        onSuccess: (r) => { setResult(r); if (r.created > 0) toast.success(t('import.done', { count: r.created })) },
        onError: (e) => setError(errMsg(e)),
      })
    } catch (e) { setError(errMsg(e)) }
    if (input.current) input.current.value = ''
  }

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted">{t('import.body')}</p>
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => void download('/inventory/import-template.csv', 'vedette-devices-template.csv').catch((e: unknown) => toast.error(errMsg(e)))}>{t('import.template')}</Button>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="import-file">{t('import.file')}</Label>
        <input id="import-file" ref={input} type="file" accept=".csv,text/csv" className="text-sm file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-rule file:bg-surface file:px-3 file:text-sm" onChange={(e) => void onFile(e.target.files?.[0])} />
        <p className="text-[13px] text-muted">{t('import.fileHint', { kb: MAX_BYTES / 1000 })}</p>
      </div>
      {imp.isPending ? <p role="status" className="text-sm"><Upload className="mr-1 inline size-4" aria-hidden />{t('import.working')}</p> : null}
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
      {result ? (
        <div role="status" className="grid gap-2 rounded-md border border-rule bg-sunken p-3 text-sm">
          <p className="font-medium">{t('import.summary', { created: result.created, skipped: result.skipped })}</p>
          {result.errors.length ? (
            <>
              <p className="text-[13px] text-muted">{t('import.errorsHint')}</p>
              <ul className="grid max-h-48 gap-1 overflow-y-auto">
                {result.errors.map((e) => <li key={e.line}><span className="font-medium">{t('import.line', { line: e.line })}</span> {e.message}</li>)}
              </ul>
            </>
          ) : null}
        </div>
      ) : null}
      <DialogFooter><DialogClose asChild><Button variant={result ? 'primary' : 'secondary'} onClick={onClose}>{t('import.close')}</Button></DialogClose></DialogFooter>
    </div>
  )
}

export function ImportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('import.title')}><ImportForm onClose={() => onOpenChange(false)} /></DialogContent>
    </Dialog>
  )
}
