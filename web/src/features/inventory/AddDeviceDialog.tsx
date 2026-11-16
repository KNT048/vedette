import { useRef, useState, type FormEvent, type RefObject } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { useAddDevice, useDeviceAction } from './api'
import { errMsg } from './kinds'
import { ProductPicker, productFields, type ChosenProduct } from './ProductPicker'
import { IPV4_RE_UI } from './validate'

/** What the form adds (#849): `device`, the Manual method of Add a device (an IP or a host name, and the product it runs; #829 item 2:
 *  never a nameless, addressless row); `software` on a device (its page); `declared`, a product with no device (Settings › Declared software). */
export type AddMode = 'device' | 'software' | 'declared'

export function AddForm({ mode, onDone, deviceId, listOpenRef }: { mode: AddMode; onDone: () => void; deviceId?: string; listOpenRef: RefObject<boolean> }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const [product, setProduct] = useState<ChosenProduct | null>(null)
  const [version, setVersion] = useState('')
  const [name, setName] = useState('')
  const [ip, setIp] = useState('')
  const [ipErr, setIpErr] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const addDevice = useAddDevice()
  const addSoftware = useDeviceAction(deviceId ?? '').addSoftware
  const pending = addDevice.isPending || addSoftware.isPending

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!product) return
    setError(null)
    if (mode === 'software' && deviceId) {
      addSoftware.mutate({ ...productFields(product), version: version.trim() || undefined }, {
        onSuccess: (r) => { toast.success(r.kev_cves > 0 ? t('add.softwareDoneKev', { name: product.display, count: r.kev_cves }) : t('add.softwareDone', { name: product.display })); onDone() },
        onError: (er) => setError(errMsg(er)),
      })
      return
    }
    if (mode === 'device') {
      const v = ip.trim()
      const bad = !v && !name.trim() ? t('add.needAddress') : v && !IPV4_RE_UI.test(v) ? t('add.ipBad') : null
      setIpErr(bad)
      if (bad) return
    }
    const where = mode === 'device' ? { name: name.trim() || undefined, ip: ip.trim() || undefined } : {}
    addDevice.mutate({ ...productFields(product), version: version.trim() || undefined, ...where }, {
      onSuccess: (r) => {
        const msg = mode === 'declared'
          ? (r.kev_cves > 0 ? t('declaredPage.doneKev', { name: r.display, count: r.kev_cves }) : t('declaredPage.done', { name: r.display }))
          : (r.kev_cves > 0 ? t('add.doneKev', { name: r.display, count: r.kev_cves }) : t('add.done', { name: r.display }))
        toast.success(msg, mode === 'declared' ? undefined : { action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${r.id}`) } })
        onDone()
      },
      onError: (er) => setError(errMsg(er)),
    })
  }

  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      {mode === 'device' ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Field label={t('add.ip')} htmlFor="add-ip" hint={t('add.ipHint')} error={ipErr ?? undefined}>
            <Input id="add-ip" inputMode="decimal" value={ip} onChange={(e) => { setIp(e.target.value); setIpErr(null) }} placeholder="192.168.10.25" />
          </Field>
          <Field label={t('add.name')} htmlFor="add-name" hint={t('add.nameHint')}>
            <Input id="add-name" value={name} onChange={(e) => { setName(e.target.value); setIpErr(null) }} maxLength={64} />
          </Field>
        </div>
      ) : null}
      <ProductPicker value={product} onChange={setProduct} label={mode === 'device' ? t('add.productRuns') : t('add.product')} listOpenRef={listOpenRef} />
      <Field label={t('add.version')} htmlFor="add-version" hint={product?.version_hint || t('add.versionHint')}>
        <Input id="add-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder={t('add.versionPlaceholder')} maxLength={40} />
      </Field>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <DialogFooter>
        <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
        <Button type="submit" variant="primary" disabled={!product || pending}>{t('add.submit')}</Button>
      </DialogFooter>
    </form>
  )
}

/** S-INV-2: pick a suggestion, Add = 3 clicks. "Add software" on a device page (`deviceId`) and Settings › Declared software
 *  (`declared`) use it on its own; adding a device goes through the Add a device dialog (AddDialog, #849). */
export function AddDeviceDialog({ open, onOpenChange, deviceId, declared }: { open: boolean; onOpenChange: (o: boolean) => void; deviceId?: string; declared?: boolean }) {
  const { t } = useTranslation('inventory')
  const listOpenRef = useRef(false)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={declared ? t('declaredPage.addTitle') : t('add.softwareTitle')} description={declared ? t('declaredPage.addBody') : t('add.softwareBody')} info={declared ? t('declaredPage.addInfo') : undefined}
        onEscapeKeyDown={(e) => { if (listOpenRef.current) e.preventDefault() }}>
        <AddForm mode={declared ? 'declared' : 'software'} deviceId={deviceId} onDone={() => onOpenChange(false)} listOpenRef={listOpenRef} />
      </DialogContent>
    </Dialog>
  )
}
