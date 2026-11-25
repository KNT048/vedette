import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { InfoTip } from '@/components/common/InfoTip'
import { Card } from '@/components/common/Card'
import { Notice } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddToken, useDeleteToken, useEditTrapIp, useOverview, useToggleTrapIp, useTrapIps } from './api'
import { LOGIN_SERVICES, LOGIN_TO_ADD, SMB_LOOKS, TOKEN_PRESETS, presetToken, tokenPresetName, type TokenPresetDef } from './presets'
import { HP_SERVICES, TOKEN_TYPES, type HpService, type OfferedTokenType, type Token, type TrapIP } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** What closes a group's gap: switch on a Trap IP that has the service, add the service to a switched-on Trap IP of a fitting look,
 *  or, when either needs choices (no Trap IP yet), the Trap IPs tab with the Add dialog open on a look that has it. */
type Fix = { kind: 'enable'; trap: TrapIP } | { kind: 'add'; trap: TrapIP; service: HpService } | { kind: 'link'; to: string; label: string }

function fixFor(type: OfferedTokenType, traps: TrapIP[] | undefined): Fix {
  const l = traps ?? []
  if (type === 'file') {
    const off = l.find((x) => !x.enabled && x.services.includes('smb'))
    if (off) return { kind: 'enable', trap: off }
    const on = l.find((x) => x.enabled && SMB_LOOKS.includes(x.preset))
    if (on) return { kind: 'add', trap: on, service: 'smb' }
    return { kind: 'link', to: '?tab=trap-ips&add=file_server#trap-ips', label: 'addFileServer' }
  }
  const off = l.find((x) => !x.enabled && x.services.some((s) => LOGIN_SERVICES.includes(s)))
  if (off) return { kind: 'enable', trap: off }
  const on = l.find((x) => x.enabled)
  if (on) return { kind: 'add', trap: on, service: LOGIN_TO_ADD[on.preset] }
  return { kind: 'link', to: '?tab=trap-ips&add=linux#trap-ips', label: 'addLoginServer' }
}

/** The file a file preset puts on the share, as the box names it (mutate.go AddToken: spaces become hyphens, then the extension). */
const fileOf = (p: TokenPresetDef) => `${tokenPresetName(p).split(/\s+/).join('-')}.${p.ext ?? 'xlsx'}`

/** Ready-made decoys: every token preset is a row with a switch. On creates the token with the preset's name and place, off deletes it
 *  (its hits stay). Files and accounts alert as soon as they are on, because the decoy itself serves them; a link alerts only once it
 *  is pasted somewhere, so its row says so and offers Copy. A group whose decoys cannot fire yet (no SMB share, no login service) says
 *  why, with the one action that fixes it. The Create custom dialog stays for anything else. */
export default function ReadyMade({ items }: { items: Token[] }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const ov = useOverview().data
  const traps = useTrapIps().data?.items
  const add = useAddToken()
  const del = useDeleteToken()
  const [pending, setPending] = useState<string | null>(null)
  const [asking, setAsking] = useState<{ p: TokenPresetDef; tok: Token } | null>(null)
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const label = (p: TokenPresetDef) => t(`token.preset.${p.id}.label`)

  // Blocked: the decoys of the group exist but nothing can touch them yet. Unknown while the overview loads: then nothing is claimed.
  const blocked: Record<OfferedTokenType, boolean> = {
    file: !!ov && !ov.smb_name,
    credential: !!ov && !ov.traps.some((x) => x.enabled && LOGIN_SERVICES.includes(x.service)),
    url: false,
  }

  function turnOn(p: TokenPresetDef) {
    setPending(p.id)
    const plant = p.type === 'file' ? t('token.ready.filePlant') : t(`token.preset.${p.id}.plant`)
    add.mutate({ type: p.type, name: tokenPresetName(p), plant_at: plant, ...(p.type === 'file' ? { ext: p.ext ?? 'xlsx' } : {}) }, {
      onSuccess: () => toast.success(t('token.ready.onToast', { name: label(p) })),
      onError: (e) => toast.error(errMsg(e)),
      onSettled: () => setPending(null),
    })
  }
  function turnOff(p: TokenPresetDef, tok: Token) {
    setPending(p.id)
    del.mutate(tok.id, {
      onSuccess: () => toast.success(t('token.ready.offToast', { name: label(p) })),
      onError: (e) => toast.error(errMsg(e)),
      onSettled: () => { setPending(null); setAsking(null) },
    })
  }
  // A file without hits comes back the same when switched on again. A link or an account comes back with a new value, so the copy
  // planted earlier would stop alerting: ask first, as for anything that has already fired.
  const askFirst = (tok: Token) => tok.triggers > 0 || tok.type !== 'file'

  return (
    <Card>
      <div id="ready-decoys" className="grid gap-6">
        {TOKEN_TYPES.map((type) => (
          <section key={type} aria-labelledby={`ready-${type}`} className="grid gap-2">
            <div className="grid gap-0.5">
              <div className="flex items-center gap-1">
                <h3 id={`ready-${type}`} className="text-sm font-medium">{t(`token.ready.group.${type}.title`)}</h3>
                <InfoTip topic={t(`token.ready.group.${type}.title`)}>{t(`token.ready.group.${type}.info`)}</InfoTip>
              </div>
              <p className="text-meta text-muted">{type === 'file' && ov?.smb_name ? t('token.ready.group.file.bodyNamed', { name: ov.smb_name }) : t(`token.ready.group.${type}.body`)}</p>
            </div>
            {blocked[type] ? <Blocked type={type} fix={fixFor(type, traps)} admin={admin} /> : null}
            <ul aria-label={t(`token.ready.group.${type}.title`)} className="grid divide-y divide-rule">
              {TOKEN_PRESETS.filter((p) => p.type === type).map((p) => {
                const tok = presetToken(p, items)
                return (
                  <li key={p.id} className="grid gap-2 py-2.5 first:pt-0 last:pb-0">
                    <div className="flex items-start justify-between gap-3">
                      <div className="grid min-w-0 gap-0.5">
                        <span className="text-sm font-medium">{label(p)}</span>
                        <span className="text-meta text-muted [overflow-wrap:anywhere]">{tok ? onLine(t, tok, ov?.smb_name ?? null) : offLine(t, p)}</span>
                        {tok ? <span className="text-meta text-muted">{tok.last_triggered_at ? t('token.lastTriggered', { when: fmtRelative(tok.last_triggered_at), count: tok.triggers }) : t('token.never')}</span> : null}
                      </div>
                      <Switch checked={!!tok} disabled={!admin || pending !== null} title={needAdmin} aria-label={label(p)}
                        onCheckedChange={(v) => { if (v) turnOn(p); else if (tok) { if (askFirst(tok)) setAsking({ p, tok }); else turnOff(p, tok) } }} />
                    </div>
                    {tok && tok.type === 'url' ? <CodeBlock code={tok.value} label={t('token.ready.pasteIn', { where: tok.plant_at })} wrapOnPhone /> : null}
                    {tok && tok.type === 'credential' && operator ? <CodeBlock code={`user: ${tok.value}\npassword: ${tok.password ?? ''}`} label={t('token.ready.putIn', { where: tok.plant_at })} /> : null}
                  </li>
                )
              })}
            </ul>
          </section>
        ))}
      </div>
      <Dialog open={!!asking} onOpenChange={(o) => { if (!o) setAsking(null) }}>
        {asking ? (
          <DialogContent title={t('token.ready.confirm.title', { name: label(asking.p) })}>
            <div className="grid gap-2 text-sm">
              <p>{t(`token.ready.confirm.${asking.p.type}`)}</p>
              {asking.tok.triggers > 0 ? <p>{t('token.ready.confirm.hits', { count: asking.tok.triggers })}</p> : null}
            </div>
            <DialogFooter>
              <Button type="button" onClick={() => setAsking(null)}>{t('common:cancel')}</Button>
              <Button type="button" variant="danger" busy={del.isPending} busyLabel={t('common:busy.turningOff')} onClick={() => turnOff(asking.p, asking.tok)}>{t('token.ready.confirm.turnOff')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </Card>
  )
}

type T = ReturnType<typeof useTranslation>['t']

function offLine(t: T, p: TokenPresetDef) {
  return p.type === 'file' ? t('token.ready.off.file', { value: fileOf(p) }) : t(`token.ready.off.${p.type}`)
}

function onLine(t: T, tok: Token, smbName: string | null) {
  if (tok.type === 'file') return smbName ? t('token.ready.on.file', { value: tok.value, name: smbName }) : t('token.ready.on.fileNoSmb', { value: tok.value })
  if (tok.type === 'credential') return t('token.ready.on.credential', { value: tok.value })
  return t('token.ready.on.url')
}

/** Why a group's decoys cannot fire yet, with the one action that fixes it (administrators only). */
function Blocked({ type, fix, admin }: { type: OfferedTokenType; fix: Fix; admin: boolean }) {
  const { t } = useTranslation('honeypot')
  const toggle = useToggleTrapIp()
  const edit = useEditTrapIp()
  const busy = toggle.isPending || edit.isPending
  const short = (s: HpService) => t(`service.${s}`).split(' (')[0]
  const done = (name: string) => toast.success(t('token.ready.fix.done', { name }))
  function run() {
    if (fix.kind === 'enable') {
      toggle.mutate({ id: fix.trap.id, enabled: true }, { onSuccess: () => done(fix.trap.name), onError: (e) => toast.error(errMsg(e)) })
    } else if (fix.kind === 'add') {
      const d = fix.trap
      edit.mutate({ id: d.id, name: d.name, ip: d.ip, preset: d.preset, vendor: d.vendor, services: HP_SERVICES.filter((s) => s === fix.service || d.services.includes(s)) },
        { onSuccess: () => done(d.name), onError: (e) => toast.error(errMsg(e)) })
    }
  }
  const action = !admin ? null
    : fix.kind === 'link' ? <Link to={fix.to} className="text-meta font-medium text-accent underline underline-offset-4">{t(`token.ready.fix.${fix.label}`)}</Link>
      : (
        <Button size="sm" busy={busy} busyLabel={t('common:busy.saving')} onClick={run}>
          {fix.kind === 'enable' ? t('token.ready.fix.enable', { name: fix.trap.name }) : t('token.ready.fix.add', { service: short(fix.service), name: fix.trap.name })}
        </Button>
      )
  return (
    <Notice tone="warn" role="status" className="mb-0" title={t(`token.ready.group.${type}.blocked`)} actions={action}>
      {admin ? null : t('token.ready.fix.askAdmin')}
    </Notice>
  )
}
