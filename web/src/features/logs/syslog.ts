// The syslog header of a stored line, read for display (W1-22, D-485), as the box does it (modules/logs/listen/parse.go ParseSyslog):
// "<PRI>" then RFC 5424 ("1 TIMESTAMP HOST APP PROCID MSGID SD MSG") or RFC 3164 ("Mmm dd hh:mm:ss HOST TAG[PID]: MSG"). What is not a
// header stays in the message. The mock uses it to answer like the box.

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const nil = (s: string) => (s === '-' || s === '' ? null : s)

export function syslogHeader(line: string): { host: string | null; app: string | null; message: string } {
  const pri = /^<(\d{1,3})>/.exec(line)
  if (!pri || Number(pri[1]) > 191) return { host: null, app: null, message: line }
  const rest = line.slice(pri[0].length)
  // RFC 5424, structured data "-" or [..] elements (no escaped "]" in the sample lines the mock keeps).
  const v5 = /^1 (\S{1,40}) (\S{1,255}) (\S{1,48}) (\S{1,128}) (\S{1,32}) (-|(?:\[[^\]]*\])+)(?: (.*))?$/s.exec(rest)
  if (v5) return { host: nil(v5[2]!), app: nil(v5[3]!), message: (v5[7] ?? '').replace(/^\uFEFF/, '') }
  const bsd = /^([A-Z][a-z]{2}) [ \d]\d \d\d:\d\d:\d\d /.exec(rest)
  if (!bsd || !MONTHS.includes(bsd[1]!)) return { host: null, app: null, message: rest }
  let s = rest.slice(16)
  let host: string | null = null
  const sp = s.indexOf(' ')
  if (sp > 0 && sp <= 255) { host = nil(s.slice(0, sp)); s = s.slice(sp + 1) }
  const tag = /^([A-Za-z0-9_./-]{1,47})(\[[^\]]{0,128}\])?:? ?/.exec(s)
  if (tag && (s[tag[1]!.length] === ':' || s[tag[1]!.length] === '[')) return { host, app: tag[1]!, message: s.slice(tag[0].length) }
  return { host, app: null, message: s }
}
