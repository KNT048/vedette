import { useRef, useState, type FormEvent, type RefObject } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { kindLabel } from '@/lib/deviceTypes'
import { useAddDevice, useDeviceAction, useDevices, useIgnoredDevices } from './api'
import { nameOf } from './nameOf'
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
  const [productErr, setProductErr] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dup, setDup] = useState<{ id: string; name: string; ignored?: boolean } | null>(null)
  const devices = useDevices()
  const ignoredDevices = useIgnoredDevices(false) // Read only when an address is taken by a device the list leaves out
  const addDevice = useAddDevice()
  const addSoftware = useDeviceAction(deviceId ?? '').addSoftware
  const pending = addDevice.isPending || addSoftware.isPending

  function submit(e: FormEvent) {
    e.preventDefault()
    // Add is never off without a reason: sent without a product, the form says what is missing where it is missing
    const bad = mode === 'device' ? (!ip.trim() && !name.trim() ? t('add.needAddress') : ip.trim() && !IPV4_RE_UI.test(ip.trim()) ? t('add.ipBad') : null) : null
    if (mode === 'device') setIpErr(bad)
    setProductErr(product ? null : t(mode === 'device' ? 'add.needProductDevice' : 'add.needProduct'))
    if (!product || bad) return
    setError(null)
    if (mode === 'software' && deviceId) {
      addSoftware.mutate({ ...productFields(product), version: version.trim() || undefined }, {
        onSuccess: (r) => { toast.success(r.kev_cves > 0 ? t('add.softwareDoneKev', { name: product.display, count: r.kev_cves }) : t('add.softwareDone', { name: product.display })); onDone() },
        onError: (er) => setError(errMsg(er)),
      })
      return
    }
    const where = mode === 'device' ? { name: name.trim() || undefined, ip: ip.trim() || undefined } : {}
    setDup(null)
    addDevice.mutate({ ...productFields(product), version: version.trim() || undefined, ...where }, {
      onSuccess: (r) => {
        // a device is named as the list names it (the name typed, else its address), with the product it runs
        const device = name.trim() || ip.trim()
        const msg = mode === 'declared'
          ? (r.kev_cves > 0 ? t('declaredPage.doneKev', { name: r.display, count: r.kev_cves }) : t('declaredPage.done', { name: r.display }))
          : (r.kev_cves > 0 ? t('add.doneDeviceKev', { name: device, product: r.display, count: r.kev_cves }) : t('add.doneDevice', { name: device, product: r.display }))
        toast.success(msg, mode === 'declared' ? undefined : { action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${r.id}`) } })
        onDone()
      },
      onError: (er) => {
        setError(errMsg(er))
        // 409 duplicate_ip: the device is already in the list; open it from here instead of searching for it (#842).
        const at = ip.trim()
        const isDup = er instanceof ApiError && er.code === 'duplicate_ip'
        const same = isDup ? devices.data?.items.find((d) => d.ip === at) : undefined
        setDup(same ? { id: same.id, name: nameOf(same, kindLabel(same.kind)) } : null)
        // review r1 L9 of #945: an ignored device holds the address; the Devices list leaves it out, so look there and say so
        if (isDup && !same) {
          void ignoredDevices.refetch().then((r) => {
            const hit = r.data?.items.find((d) => d.ip === at)
            if (hit) setDup({ id: hit.id, name: nameOf(hit, kindLabel(hit.kind)), ignored: true })
          })
        }
      },
    })
  }

  return (
    <form onSubmit={submit} className="grid grid-cols-1 gap-4" noValidate>
      {mode === 'device' ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={t('add.ip')} htmlFor="add-ip" hint={t('add.ipHint')} error={ipErr ?? undefined}>
            <Input id="add-ip" inputMode="decimal" value={ip} onChange={(e) => { setIp(e.target.value); setIpErr(null) }} placeholder="192.168.10.25" />
          </Field>
          <Field label={t('add.name')} htmlFor="add-name" hint={t('add.nameHint')}>
            <Input id="add-name" value={name} onChange={(e) => { setName(e.target.value); setIpErr(null) }} maxLength={64} />
          </Field>
        </div>
      ) : null}
      <ProductPicker value={product} onChange={(p) => { setProduct(p); if (p) setProductErr(null) }} label={mode === 'device' ? t('add.productRuns') : t('add.product')} listOpenRef={listOpenRef} error={productErr} />
      <Field label={t('add.version')} htmlFor="add-version" hint={product?.version_hint || t('add.versionHint')}>
        <Input id="add-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder={t('add.versionPlaceholder')} maxLength={40} />
      </Field>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error}
        actions={dup ? <Link to={`/devices/${encodeURIComponent(dup.id)}`} onClick={onDone} className="text-sm font-medium text-accent underline-offset-4 hover:underline">{t(dup.ignored ? 'add.openIgnored' : 'add.openExisting', { name: dup.name })}</Link> : undefined} /> : null}
      <DialogFooter>
        <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
        <Button type="submit" variant="primary" busy={pending} busyLabel={t('common:busy.adding')}>{t('add.submit')}</Button>
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
