import { useRef, useState, type FormEvent, type RefObject } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { useAddDevice, useDeviceAction } from './api'
import { errMsg } from './kinds'
import { ProductPicker, productFields, type ChosenProduct } from './ProductPicker'

function AddForm({ onDone, deviceId, listOpenRef }: { onDone: () => void; deviceId?: string; listOpenRef: RefObject<boolean> }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const [product, setProduct] = useState<ChosenProduct | null>(null)
  const [version, setVersion] = useState('')
  const [name, setName] = useState('')
  const [ip, setIp] = useState('')
  const [error, setError] = useState<string | null>(null)
  const addDevice = useAddDevice()
  const addSoftware = useDeviceAction(deviceId ?? '').addSoftware
  const pending = addDevice.isPending || addSoftware.isPending

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!product) return
    setError(null)
    if (deviceId) {
      addSoftware.mutate({ ...productFields(product), version: version.trim() || undefined }, {
        onSuccess: (r) => { toast.success(r.kev_cves > 0 ? t('add.softwareDoneKev', { name: product.display, count: r.kev_cves }) : t('add.softwareDone', { name: product.display })); onDone() },
        onError: (er) => setError(errMsg(er)),
      })
      return
    }
    addDevice.mutate({ ...productFields(product), version: version.trim() || undefined, name: name.trim() || undefined, ip: ip.trim() || undefined }, {
      onSuccess: (r) => {
        toast.success(r.kev_cves > 0 ? t('add.doneKev', { name: r.display, count: r.kev_cves }) : t('add.done', { name: r.display }), { action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${r.id}`) } })
        onDone()
      },
      onError: (er) => setError(errMsg(er)),
    })
  }

  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      <ProductPicker value={product} onChange={setProduct} label={t('add.product')} listOpenRef={listOpenRef} />
      <Field label={t('add.version')} htmlFor="add-version" hint={product?.version_hint || t('add.versionHint')}>
        <Input id="add-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder={t('add.versionPlaceholder')} maxLength={40} aria-describedby="add-version-hint" />
      </Field>
      {deviceId ? null : (
        <>
          <Field label={t('add.name')} htmlFor="add-name" hint={t('add.nameHint')}>
            <Input id="add-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} aria-describedby="add-name-hint" />
          </Field>
          <Field label={t('add.ip')} htmlFor="add-ip" hint={t('add.ipHint')}>
            <Input id="add-ip" inputMode="decimal" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.168.10.25" aria-describedby="add-ip-hint" />
          </Field>
        </>
      )}
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
      <DialogFooter>
        <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
        <Button type="submit" variant="primary" disabled={!product || pending}>{t('add.submit')}</Button>
      </DialogFooter>
    </form>
  )
}

/** S-INV-2: "Khai thiết bị" → chọn gợi ý → "Thêm" = 3 bấm. Dùng lại cho "Thêm phần mềm" trên trang chi tiết (có `deviceId`). */
export function AddDeviceDialog({ open, onOpenChange, deviceId }: { open: boolean; onOpenChange: (o: boolean) => void; deviceId?: string }) {
  const { t } = useTranslation('inventory')
  const listOpenRef = useRef(false)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={deviceId ? t('add.softwareTitle') : t('add.title')} description={deviceId ? t('add.softwareBody') : t('add.body')}
        onEscapeKeyDown={(e) => { if (listOpenRef.current) e.preventDefault() }}>
        <AddForm deviceId={deviceId} onDone={() => onOpenChange(false)} listOpenRef={listOpenRef} />
      </DialogContent>
    </Dialog>
  )
}
