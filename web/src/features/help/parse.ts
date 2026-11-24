// The Markdown of docs/cookbook, parsed into blocks for the Help pages. The recipes keep to a small part of Markdown: headings,
// paragraphs, numbered and bulleted lists (nested by indentation, with paragraphs, images and code inside an item), fenced code,
// pipe tables, and inline bold, code, links and images. Anything else shows as plain text. A test renders every recipe and fails
// on Markdown this parser would show as raw marks, so a recipe that needs more fails before it ships.

export type Inline =
  | { kind: 'text'; text: string }
  | { kind: 'strong'; children: Inline[] }
  | { kind: 'code'; text: string }
  | { kind: 'link'; href: string; children: Inline[] }
  | { kind: 'image'; src: string; alt: string }

export type Block =
  | { kind: 'heading'; level: 1 | 2 | 3; children: Inline[]; text: string }
  | { kind: 'paragraph'; children: Inline[] }
  | { kind: 'image'; src: string; alt: string }
  | { kind: 'code'; text: string }
  | { kind: 'list'; ordered: boolean; start: number; items: Block[][] }
  | { kind: 'table'; head: Inline[][]; rows: Inline[][][] }

const INLINE = /(\*\*(.+?)\*\*)|(`([^`]+)`)|(!\[([^\]]*)\]\(([^)\s]+)\))|(\[([^\]]+)\]\(([^)\s]+)\))/

export function parseInline(src: string): Inline[] {
  const out: Inline[] = []
  let rest = src
  while (rest) {
    const m = INLINE.exec(rest)
    if (!m) { out.push({ kind: 'text', text: rest }); break }
    if (m.index > 0) out.push({ kind: 'text', text: rest.slice(0, m.index) })
    if (m[1]) out.push({ kind: 'strong', children: parseInline(m[2]!) })
    else if (m[3]) out.push({ kind: 'code', text: m[4]! })
    else if (m[5]) out.push({ kind: 'image', alt: m[6]!, src: m[7]! })
    else out.push({ kind: 'link', children: parseInline(m[9]!), href: m[10]! })
    rest = rest.slice(m.index + m[0].length)
  }
  return out
}

export const plainText = (xs: Inline[]): string => xs.map((x) => (x.kind === 'text' || x.kind === 'code' ? x.text : x.kind === 'image' ? x.alt : plainText(x.children))).join('')

const indentOf = (line: string) => line.length - line.trimStart().length
const LIST_ITEM = /^(\s*)(\d+\.|[-*])\s+(.*)$/
const IMAGE_LINE = /^!\[([^\]]*)\]\(([^)\s]+)\)$/
const cells = (line: string) => line.trim().replace(/^\||\|$/g, '').split('|').map((c) => parseInline(c.trim()))

export function parseMarkdown(md: string): Block[] {
  return parseLines(md.replace(/\r\n/g, '\n').split('\n'))
}

function parseLines(lines: string[]): Block[] {
  const blocks: Block[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]!
    const trimmed = line.trim()
    if (!trimmed) { i++; continue }
    if (trimmed.startsWith('```')) {
      const body: string[] = []
      const base = indentOf(line)
      for (i++; i < lines.length && !lines[i]!.trim().startsWith('```'); i++) body.push(lines[i]!.slice(Math.min(base, indentOf(lines[i]!))))
      blocks.push({ kind: 'code', text: body.join('\n') })
      i++
      continue
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(trimmed)
    if (h) {
      const children = parseInline(h[2]!)
      blocks.push({ kind: 'heading', level: h[1]!.length as 1 | 2 | 3, children, text: plainText(children) })
      i++
      continue
    }
    if (trimmed.startsWith('|')) {
      const rows: string[] = []
      for (; i < lines.length && lines[i]!.trim().startsWith('|'); i++) rows.push(lines[i]!)
      const body = rows.slice(1).filter((r) => !/^\s*\|?[\s:|-]+\|?\s*$/.test(r))
      blocks.push({ kind: 'table', head: cells(rows[0]!), rows: body.map(cells) })
      continue
    }
    const li = LIST_ITEM.exec(line)
    if (li) {
      const ordered = /\d/.test(li[2]!)
      const base = li[1]!.length
      const items: Block[][] = []
      const start = ordered ? parseInt(li[2]!, 10) : 1
      while (i < lines.length) {
        const m = LIST_ITEM.exec(lines[i]!)
        if (!m || m[1]!.length !== base || /\d/.test(m[2]!) !== ordered) break
        const content = base + m[2]!.length + 1
        const body = [m[3]!]
        for (i++; i < lines.length; i++) {
          const next = lines[i]!
          if (next.trim() && indentOf(next) < content) break
          body.push(next.slice(Math.min(content, indentOf(next))))
        }
        items.push(parseLines(body))
      }
      blocks.push({ kind: 'list', ordered, start, items })
      continue
    }
    const img = IMAGE_LINE.exec(trimmed)
    if (img) { blocks.push({ kind: 'image', alt: img[1]!, src: img[2]! }); i++; continue }
    const para: string[] = []
    for (; i < lines.length; i++) {
      const l = lines[i]!
      const t = l.trim()
      if (!t || t.startsWith('```') || t.startsWith('|') || /^#{1,3}\s/.test(t) || LIST_ITEM.test(l) || IMAGE_LINE.test(t)) break
      para.push(t)
    }
    blocks.push({ kind: 'paragraph', children: parseInline(para.join(' ')) })
  }
  return blocks
}
