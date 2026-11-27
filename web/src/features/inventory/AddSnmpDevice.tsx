import { useRef, useState, type RefObject } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Notice } from '@/components/common/PageHeader'
import { Field, Input } from '@/components/ui/input'
import { api, ApiError } from '@/lib/api'
import { kindLabel } from '@/lib/deviceTypes'
import { useAddDevice, useDevices, useSnmp } from './api'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import { ProductPicker, productFields, type ChosenProduct } from './ProductPicker'
import { SnmpForm } from './SnmpCard'
import type { DeviceSnmp, DeviceSnmpInput } from './types'
import { IPV4_RE_UI } from './validate'

/** "SNMP" in Add a device: the address and the SNMP settings in one form. Submitting creates the device, then saves the SNMP settings
 *  on it (which turns SNMP on for it), so the first read can happen without a second visit. If the settings are refused after the
 *  device exists, the device is kept and the form keeps asking only for the settings: nothing is created twice. */
export function AddSnmpDevice({ onDone, listOpenRef }: { onDone: () => void; listOpenRef: RefObject<boolean> }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const qc = useQueryClient()
  const addDevice = useAddDevice()
  const devices = useDevices()
  const list = useSnmp(true)
  const [product, setProduct] = useState<ChosenProduct | null>(null)
  const [name, setName] = useState('')
  const [ip, setIp] = useState('')
  const [ipErr, setIpErr] = useState<string | null>(null)
  const [productErr, setProductErr] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dup, setDup] = useState<{ id: string; name: string } | null>(null)
  const [created, setCreated] = useState<{ id: string; name: string } | null>(null)
  const [adopt, setAdopt] = useState<{ id: string; name: string } | null>(null) // the device that already has this address: SNMP goes on it
  const adoptRef = useRef<{ id: string; name: string } | null>(null)
  const adoptDevice = (d: { id: string; name: string } | null) => { adoptRef.current = d; setAdopt(d) }
  const [saving, setSaving] = useState(false)
  const address = ip.trim()

  const precheck = () => {
    if (created || adoptRef.current) return true
    const bad = !address ? t('addDialog.snmp.needAddress') : !IPV4_RE_UI.test(address) ? t('add.ipBad') : null
    const noProduct = product ? null : t('addDialog.snmp.needProduct')
    setIpErr(bad)
    setProductErr(noProduct)
    return !bad && !noProduct
  }

  const save = async (body: DeviceSnmpInput) => {
    setError(null); setDup(null)
    setSaving(true)
    try {
      let target = created ?? adoptRef.current
      if (!target) {
        try {
          const r = await addDevice.mutateAsync({ ...productFields(product!), name: name.trim() || undefined, ip: address })
          target = { id: r.id, name: r.display }
          setCreated(target)
        } catch (er) {
          setError(errMsg(er))
          if (er instanceof ApiError && er.code === 'duplicate_ip') {
            const same = devices.data?.items.find((d) => d.ip === address)
            if (same) setDup({ id: same.id, name: nameOf(same, kindLabel(same.kind)) })
          }
          return
        }
      }
      await api.put<DeviceSnmp>(`/inventory/snmp/devices/${encodeURIComponent(target.id)}`, body)
      await qc.invalidateQueries({ queryKey: ['inventory'] })
      toast.success(t('addDialog.snmp.done', { name: target.name }), { action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${target.id}`) } })
      onDone()
    } finally {
      setSaving(false)
    }
  }

  const lead = adopt ? (
    <Notice tone="accent" role="status" className="mb-0" title={t('addDialog.snmp.dupUsing', { name: adopt.name, ip: address })}
      actions={<Button size="sm" onClick={() => adoptDevice(null)}>{t('common:cancel')}</Button>}>
      {t('addDialog.snmp.dupUsingBody')}
    </Notice>
  ) : created ? (
    <Notice tone="warn" role="status" className="mb-0" title={t('addDialog.snmp.addedNotSet', { name: created.name })}
      actions={<Link to={`/devices/${encodeURIComponent(created.id)}`} onClick={onDone} className="text-sm text-accent underline-offset-4 hover:underline">{t('addDialog.snmp.openDevice')}</Link>}>
      {t('addDialog.snmp.addedNotSetBody')}
    </Notice>
  ) : (
    <>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Field label={t('addDialog.snmp.address')} htmlFor="add-snmp-ip" hint={t('addDialog.snmp.addressHint')} error={ipErr ?? undefined}>
          <Input id="add-snmp-ip" inputMode="decimal" value={ip} onChange={(e) => { setIp(e.target.value); setIpErr(null); setDup(null); setError(null) }} placeholder="192.168.10.1" />
        </Field>
        <Field label={t('add.name')} htmlFor="add-snmp-name" hint={t('add.nameHint')}>
          <Input id="add-snmp-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />
        </Field>
      </div>
      <div className="grid gap-1.5">
        <ProductPicker value={product} onChange={(p) => { setProduct(p); setProductErr(null) }} label={t('addDialog.snmp.product')} listOpenRef={listOpenRef} />
        {productErr ? <p className="text-meta text-danger">{productErr}</p> : <p className="text-meta text-muted">{t('addDialog.snmp.productHint')}</p>}
      </div>
      {error ? (dup ? (
        <Notice tone="danger" role="alert" className="mb-0" title={t('addDialog.snmp.dupTitle', { ip: address, name: dup.name })}
          actions={<>
            <Button size="sm" variant="primary" onClick={(e) => { adoptDevice(dup); setError(null); const f = e.currentTarget.closest('form'); queueMicrotask(() => f?.requestSubmit()) }}>{t('addDialog.snmp.dupTurnOn')}</Button>
            <Link to={`/devices/${encodeURIComponent(dup.id)}`} onClick={onDone} className="inline-flex items-center text-sm text-accent underline-offset-4 hover:underline">{t('add.openExisting', { name: dup.name })}</Link>
          </>}>
          {t('addDialog.snmp.dupBody')}
        </Notice>
      ) : <Notice tone="danger" role="alert" className="mb-0" title={error} />) : null}
    </>
  )
  return (
    <SnmpForm ip={address} s={null} others={list.data?.devices ?? []} switchOff saving={saving} save={save} precheck={precheck}
      onCancel={onDone} onLinkClick={onDone} submitLabel={t('addDialog.snmp.submit')} lead={lead} />
  )
}
