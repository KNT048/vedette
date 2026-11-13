// Approver identities (S-RESP-2, D-191), mock side. An administrator types each approver's address or ID on a notify channel;
// it counts for buttons and links only after that person proved it: a code mailed to the address (email), or a confirm link the box sends
// to that chat ID which the person confirms signed in as themself (Zalo personal D-447, Telegram D-414). The code is entered in My account,
// the link confirmed on /link/<telegram|zalo>, by the signed-in person.
// Rules (same as the real box): 10 minutes, single use, 5 wrong tries cancel it, a new one replaces the old one, a new one after 60 seconds
// and 5 an hour per person and channel.
import { http, HttpResponse } from 'msw'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { maskEmail } from '@/features/core/emailCode'
import { approversOf, chanLabel, identityStore, isLinked, linkable, rawChans, sameAddress, step, APPROVAL_TYPES } from './state'
import type { Identity } from './types'

const TTL_MS = 10 * 60_000
const MAX_TRIES = 5
const RESEND_S = 60
const PER_HOUR = 5
const CHAT_NAME: Record<string, string> = { slack: 'Slack', telegram: 'Telegram', 'zalo-personal': 'Zalo' }
const SEND_LINK = ['zalo-personal', 'telegram'] // a confirm link goes TO the ID and is confirmed by the person signed in (D-447, D-414)
type Refusal = { status: number; code: string; message: string }
/** How the notify mock sends a new confirm link to a listed person's own chat ID (My account, Send again; D-414). link: the page to open when
 * nothing was sent (your own row with the box's own Zalo account). notify registers these; response never imports notify. */
export const chatLinkSenders: Partial<Record<string, (userId: string) => { link?: string } | Refusal>> = {}

interface Pending { address: string; code: string; expires: number; tries: number; sent_at: number }
interface Codes { pending: Record<string, Pending>; sends: Record<string, number[]> }
const codesStore = collection<Codes>('resp_link_codes', () => ({ pending: {}, sends: {} }))
const key = (userId: string, channel: string) => `${userId}|${channel}`
const randomCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0')

/** The hint of a confirm-link token: tells, before anything is read, that a token is someone else's (the box hashes the user ID). */
const hintOf = (userId: string) => { let h = 0x811c9dc5; for (const ch of userId) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0; return h.toString(16).padStart(8, '0') }
const randomToken = (userId: string) => `${hintOf(userId)}-${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`
const TOKEN_RE = /^[0-9a-f]{8}-[A-Za-z0-9_-]{22}$/

/** A new code for (person, channel, address), or null when 5 were made in the last hour. It replaces any code still waiting. */
function newCode(userId: string, channel: string, address: string): Pending | null {
  const c = codesStore.get(), k = key(userId, channel), now = Date.now()
  const sends = (c.sends[k] ?? []).filter((t) => now - t < 3_600_000)
  if (sends.length >= PER_HOUR) return null
  const p = { address, code: SEND_LINK.includes(channel) ? randomToken(userId) : randomCode(), expires: now + TTL_MS, tries: 0, sent_at: now }
  codesStore.set({ pending: { ...c.pending, [k]: p }, sends: { ...c.sends, [k]: [...sends, now] } })
  return p
}
const dropCode = (k: string) => codesStore.update((c) => { const pending = { ...c.pending }; delete pending[k]; return { ...c, pending } })

/** My rows: every approval channel whose approver list names me. */
function mine(userId: string): Identity[] {
  const waiting = codesStore.get().pending
  return APPROVAL_TYPES.flatMap((type) => {
    // notify names approvers of an enabled channel with approvals on only (ApprovalChannels), as on the real box
    const ch = rawChans().find((c) => c.type === type && c.configured && c.enabled && c.approvals === true)
    if (!ch || !linkable(type)) return []
    return approversOf(ch).filter((a) => a.user_id === userId).map((a) => {
      const row = identityStore.get().find((x) => x.user_id === userId && x.channel === type && x.address === a.address)
      const linked = isLinked(userId, type, a.address)
      const p = waiting[key(userId, type)]
      return { channel: type, label: chanLabel(ch), address: a.address, ...((a as { name?: string }).name ? { name: (a as { name?: string }).name } : {}), linked, linked_at: linked ? row!.linked_at : null, method: type === 'email' ? 'email_code' as const : SEND_LINK.includes(type) ? 'send_code' as const : 'unavailable' as const,
        code_waiting: !linked && !!p && sameAddress(type, p.address, a.address) && Date.now() < p.expires }
    })
  })
}

/**
 * The refusal for a button press from a listed approver who has not linked this ID yet: nothing is decided, and the answer, which only the
 * person who pressed sees, says how to link (D-414: no code any more; a confirm link is sent to the ID).
 */
export function chatNotLinked(channel: string, address: string, target: string) {
  const name = CHAT_NAME[channel] ?? channel
  if (SEND_LINK.includes(channel)) {
    step('response.refused', target, 'refused', `approver_not_linked: ${name} ${address} is not linked to a Vedette account yet`)
    return fail(403, 'approver_not_linked', `Your ${name} account is not linked to Vedette yet. Open the link Vedette sent to this account and confirm it while signed in to Vedette, or ask your administrator to send it again.`)
  }
  step('response.refused', target, 'refused', `approver_not_linked: ${name} ${address} is not linked to a Vedette account yet; this channel cannot be linked`)
  return fail(403, 'approver_not_linked', `Your ${name} account is not linked to Vedette yet. Approve in Vedette for now.`)
}

/**
 * The token of a confirm link for a listed approver's chat ID (the notify mock sends it to that ID when an administrator saves them,
 * D-447): one a minute, five an hour, a new one replaces the old. Only that person, signed in, confirms it (POST …/confirm).
 */
export function newLinkToken(userId: string, channel: string, address: string): { token: string } | Refusal {
  const row = mine(userId).find((r) => r.channel === channel && r.address === address)
  if (!SEND_LINK.includes(channel)) return { status: 400, code: 'chat_channel', message: 'This channel is not linked by a confirm link.' }
  if (!row) return { status: 404, code: 'not_listed', message: 'This person is not listed with this address on the channel. Save the channel first.' }
  if (row.linked) return { status: 409, code: 'already_linked', message: 'This address is already linked.' }
  const old = codesStore.get().pending[key(userId, channel)]
  if (old && Date.now() - old.sent_at < RESEND_S * 1000) return { status: 429, code: 'resend_too_soon', message: `Wait ${Math.ceil((RESEND_S * 1000 - (Date.now() - old.sent_at)) / 1000)} seconds before sending a new link.` }
  const p = newCode(userId, channel, address)
  return p ? { token: p.code } : { status: 429, code: 'too_many_codes', message: 'Too many links were made for this person in the last hour. Try again later.' }
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
    if (row.method === 'send_code') { // D-414: Send again sends my own listed ID a new confirm link through notify
      if (row.linked) return fail(409, 'already_linked', 'This address is already linked.')
      const sender = chatLinkSenders[channel]
      if (!sender) return fail(400, 'chat_channel', `An administrator sends a link to your ${CHAT_NAME[channel]} account when they list you; open it and confirm while signed in to Vedette.`)
      const r = sender(u.id)
      if ('status' in r) return fail(r.status, r.code, r.message)
      return HttpResponse.json({ sent_to: `${CHAT_NAME[channel]} ${row.address}`, resend_after: RESEND_S, ...(r.link ? { link: r.link } : {}) })
    }
    if (row.method !== 'email_code') return fail(400, 'chat_channel', 'This channel cannot be linked yet. Approve in Vedette.')
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
    const link = SEND_LINK.includes(channel)
    const given = typeof b.code === 'string' ? b.code.trim() : ''
    if (link && !TOKEN_RE.test(given)) return fail(400, 'invalid_link', `This link is not complete. Open it again from the ${CHAT_NAME[channel]} message.`)
    // another signed-in person: refused before anything is read, so the link stays good for its person
    if (link && given.slice(0, 8) !== hintOf(u.id)) {
      audit('response.identity_link_refused', channel, `${u.email} opened a ${CHAT_NAME[channel]} confirm link made for another Vedette account; nothing was linked`)
      return fail(403, 'other_account', `This link is for another Vedette account. Sign out, then sign in as the person the ${CHAT_NAME[channel]} message names.`)
    }
    const p = codesStore.get().pending[k]
    // The code must be for an address that is still on the list for me now: a list changed after the code was made does not link.
    const row = p ? mine(u.id).find((r) => r.channel === channel && sameAddress(channel, r.address, p.address)) : undefined
    if (!p || !row) return fail(400, 'no_code', link ? 'This link was already used or was replaced by a newer one.' : 'No code is waiting for this channel. Ask for a new code.')
    if (Date.now() > p.expires) { dropCode(k); return fail(400, 'code_expired', link ? 'This link has expired. Press Send again in My account, or ask your administrator to press Send again.' : 'This code has expired. Ask for a new code.') }
    const code = given
    if (!link && !/^\d{6}$/.test(code)) return fail(400, 'invalid_code', 'The code is 6 digits.')
    if (code !== p.code) {
      const tries = p.tries + 1
      if (tries >= MAX_TRIES) { dropCode(k); return fail(400, 'too_many_tries', link ? 'This link is not valid. Ask your administrator to press Send again.' : 'Too many wrong codes. Ask for a new code.') }
      codesStore.update((c) => ({ ...c, pending: { ...c.pending, [k]: { ...p, tries } } }))
      const left = MAX_TRIES - tries
      return fail(400, 'wrong_code', link ? 'This link is not valid. Ask your administrator to press Send again.' : `Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left.`)
    }
    dropCode(k)
    identityStore.update((l) => [...l.filter((x) => !(x.user_id === u.id && x.channel === channel)), { user_id: u.id, channel, address: p.address, linked_at: nowIso() }])
    audit('response.identity_link', channel, `${u.email} linked ${p.address}`)
    return HttpResponse.json(mine(u.id).find((r) => r.channel === channel && sameAddress(channel, r.address, p.address))!)
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
