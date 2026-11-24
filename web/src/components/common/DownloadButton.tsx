import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button, type ButtonProps } from '@/components/ui/button'
import { download } from '@/lib/api'

/**
 * A button that downloads a file from the box. download() reads the whole file before saving it (a backup, a log export), so it
 * waits on the server: the shared busy state "Downloading…" shows meanwhile and a second click cannot start a second download
 * (docs/UI.md §8, #930 review r1). `onSaved` gets the saved file name; a failure goes to `onError`, else a toast.
 */
export function DownloadButton({ path, filename, onStart, onSaved, onError, ...props }: Omit<ButtonProps, 'onClick' | 'busy' | 'busyLabel'> & {
  path: string; filename: string; onStart?: () => void; onSaved?: (name: string) => void; onError?: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const dl = useMutation({ mutationFn: () => download(path, filename) })
  return (
    <Button {...props} busy={dl.isPending} busyLabel={t('busy.downloading')}
      onClick={() => { onStart?.(); dl.mutate(undefined, { onSuccess: onSaved, onError: onError ?? ((e) => toast.error(e instanceof Error ? e.message : String(e))) }) }} />
  )
}
