import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'

/** Đoạn cấu hình/lệnh: mono, nút sao chép. Mono CHỈ dùng ở đây và cho log (FRONTEND §3). */
export function CodeBlock({ code, label }: { code: string; label?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard bị chặn: người dùng tự chọn văn bản */ }
  }
  return (
    <div className="overflow-hidden rounded-md border border-rule bg-sunken">
      <div className="flex items-center justify-between gap-2 border-b border-rule px-3 py-1.5">
        <span className="text-[12px] text-muted">{label ?? ''}</span>
        <Button size="sm" variant="ghost" onClick={() => void copy()} aria-label={t('copy')}>
          {copied ? <Check /> : <Copy />}
          {copied ? t('copied') : t('copy')}
        </Button>
      </div>
      {/* tabIndex: khối cuộn ngang phải dùng được bằng bàn phím (WCAG 2.1.1) */}
      <pre tabIndex={0} aria-label={label || t('codeBlock')} className="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed"><code>{code}</code></pre>
    </div>
  )
}
