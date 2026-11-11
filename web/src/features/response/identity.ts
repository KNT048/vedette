// Approver identities (S-RESP-2, D-191), mock side. An administrator types each approver's address or ID on a notify channel;
// it counts for buttons and links only after that person proved it: a code mailed to the address (email), or a code Vedette
// answers privately to a button press from that ID (chat). The code is entered in My account by the signed-in person.
// Rules (same as the real box): 6 digits, 10 minutes, single use, 5 wrong codes cancel it, a new code replaces the old one;
// email: a new code after 60 seconds and 5 an hour per person; chat: 5 codes an hour per person and channel.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { maskEmail } from '@/features/core/emailCode'
import { approversOf, chanLabel, identityStore, isLinked, rawChans, step, APPROVAL_TYPES } from './state'
import type { Identity } from './types'

const TTL_MS = 10 * 60_000
const MAX_TRIES = 5
const RESEND_S = 60
const PER_HOUR = 5
const CHAT_NAME: Record<string, string> = { slack: 'Slack', telegram: 'Telegram', 'zalo-personal': 'Zalo' }

interface Pending { address: string; code: string; expires: number; tries: number; sent_at: number }
interface Codes { pending: Record<string, Pending>; sends: Record<string, number[]> }
const codesStore = collection<Codes>('resp_link_codes', () => ({ pending: {}, sends: {} }))
const key = (userId: string, channel: string) => `${userId}|${channel}`
const randomCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0')

/** A new code for (person, channel, address), or null when 5 were made in the last hour. It replaces any code still waiting. */
function newCode(userId: string, channel: string, address: string): Pending | null {
  const c = codesStore.get(), k = key(userId, channel), now = Date.now()
  const sends = (c.sends[k] ?? []).filter((t) => now - t < 3_600_000)
  if (sends.length >= PER_HOUR) return null
  const p = { address, code: randomCode(), expires: now + TTL_MS, tries: 0, sent_at: now }
  codesStore.set({ pending: { ...c.pending, [k]: p }, sends: { ...c.sends, [k]: [...sends, now] } })
  return p
}
const dropCode = (k: string) => codesStore.update((c) => { const pending = { ...c.pending }; delete pending[k]; return { ...c, pending } })

/** My rows: every approval channel whose approver list names me. */
function mine(userId: string): Identity[] {
  const waiting = codesStore.get().pending
  return APPROVAL_TYPES.flatMap((type) => {
    const ch = rawChans().find((c) => c.type === type && c.configured)
    if (!ch) return []
    return approversOf(ch).filter((a) => a.user_id === userId).map((a) => {
      const row = identityStore.get().find((x) => x.user_id === userId && x.channel === type && x.address === a.address)
      const linked = isLinked(userId, type, a.address)
      const p = waiting[key(userId, type)]
      return { channel: type, label: chanLabel(ch), address: a.address, linked, linked_at: linked ? row!.linked_at : null, method: type === 'email' ? 'email_code' as const : 'chat_code' as const,
        code_waiting: !linked && !!p && p.address === a.address && Date.now() < p.expires }
    })
  })
}

/**
 * The refusal for a button press from a listed approver who has not linked this ID yet: nothing is decided, and the answer, which only the
 * person who pressed sees, holds a link code. The log line never holds the code.
 */
export function chatNotLinked(userId: string, channel: string, address: string, target: string) {
  const name = CHAT_NAME[channel] ?? channel
  const p = newCode(userId, channel, address)
  step('response.refused', target, 'refused', `approver_not_linked: ${name} ${address} is not linked to a Vedette account yet${p ? '; a link code was shown to the person who pressed' : '; too many link codes this hour'}`)
  return fail(403, 'approver_not_linked', p
    ? `Your ${name} account is not linked to Vedette yet. Sign in to Vedette, open My account and enter code ${p.code} within 10 minutes, then press again.`
    : `Your ${name} account is not linked to Vedette yet, and too many link codes were made this hour. Approve in Vedette, or try again later.`)
}

export const identityHandlers = [
  http.get(`${API}/response/me/identities`, () => {
    const denied = guard('operator'); if (denied) return denied
    return HttpResponse.json({ items: mine(currentUser()!.id) })
  }),

  http.post(`${API}/response/me/identities/:channel/code`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const u = currentUser()!, channel = String(params.channel)
    const row = mine(u.id).find((r) => r.channel === channel)
    if (!row) return fail(404, 'not_listed', 'You are not on the approver list of this channel.')
    if (row.method !== 'email_code') return fail(400, 'chat_channel', 'Press Approve or Reject on the next approval message in this channel; Vedette answers you privately with a code.')
    if (row.linked) return fail(409, 'already_linked', 'This address is already linked.')
    if (row.address.toLowerCase() !== u.email.toLowerCase()) return fail(409, 'address_mismatch', 'The address on the email approval list is not your sign-in email. Ask an administrator to correct the list.')
    const email = rawChans().find((c) => c.type === 'email')
    if (!email?.configured || !email.enabled) return fail(503, 'email_not_ready', 'Email is not set up, so no code can be sent. Ask an administrator to set up the email channel.')
    const old = codesStore.get().pending[key(u.id, channel)]
    if (old && Date.now() - old.sent_at < RESEND_S * 1000) {
      const wait = Math.ceil((RESEND_S * 1000 - (Date.now() - old.sent_at)) / 1000)
      return HttpResponse.json({ error: { code: 'resend_too_soon', message: `Wait ${wait} seconds before asking for a new code.`, retry_after: wait } }, { status: 429 })
    }
    const p = newCode(u.id, channel, row.address)
    if (!p) return fail(429, 'too_many_codes', 'Too many codes were sent in the last hour. Try again later.')
    return HttpResponse.json({ sent_to: maskEmail(row.address), resend_after: RESEND_S, preview_code: p.code })
  }),

  http.post(`${API}/response/me/identities/:channel/confirm`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const u = currentUser()!, channel = String(params.channel), k = key(u.id, channel)
    const b = await body<{ code: string }>(request)
    const p = codesStore.get().pending[k]
    // The code must be for an address that is still on the list for me now: a list changed after the code was made does not link.
    const row = p ? mine(u.id).find((r) => r.channel === channel && r.address === p.address) : undefined
    if (!p || !row) return fail(400, 'no_code', 'No code is waiting for this channel. Ask for a new code.')
    if (Date.now() > p.expires) { dropCode(k); return fail(400, 'code_expired', 'This code has expired. Ask for a new code.') }
    if (typeof b.code !== 'string' || !/^\d{6}$/.test(b.code)) return fail(400, 'invalid_code', 'The code is 6 digits.')
    if (b.code !== p.code) {
      const tries = p.tries + 1
      if (tries >= MAX_TRIES) { dropCode(k); return fail(400, 'too_many_tries', 'Too many wrong codes. Ask for a new code.') }
      codesStore.update((c) => ({ ...c, pending: { ...c.pending, [k]: { ...p, tries } } }))
      const left = MAX_TRIES - tries
      return fail(400, 'wrong_code', `Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left.`)
    }
    dropCode(k)
    identityStore.update((l) => [...l.filter((x) => !(x.user_id === u.id && x.channel === channel)), { user_id: u.id, channel, address: p.address, linked_at: nowIso() }])
    audit('response.identity_link', channel, `${u.email} linked ${p.address}`)
    return HttpResponse.json(mine(u.id).find((r) => r.channel === channel && r.address === p.address)!)
  }),

  http.delete(`${API}/response/me/identities/:channel`, ({ params }) => {
    const denied = guard('operator'); if (denied) return denied
    const u = currentUser()!, channel = String(params.channel)
    const had = identityStore.get().filter((x) => x.user_id === u.id && x.channel === channel)
    if (!had.length) return fail(404, 'not_linked', 'Nothing is linked on this channel.')
    identityStore.update((l) => l.filter((x) => !(x.user_id === u.id && x.channel === channel)))
    dropCode(key(u.id, channel))
    audit('response.identity_unlink', channel, `${u.email} unlinked ${had.map((x) => x.address).join(', ')}`)
    return new HttpResponse(null, { status: 204 })
  }),
]
