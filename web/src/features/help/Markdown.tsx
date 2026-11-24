import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { cn } from '@/lib/utils'
import { imageUrl, linkTarget } from './cookbook'
import type { Block, Inline } from './parse'

function Image({ src, alt }: { src: string; alt: string }) {
  const url = imageUrl(src)
  if (!url) return null
  return <img src={url} alt={alt} loading="lazy" className="h-auto max-w-full rounded-md border border-rule bg-surface" />
}

function Inlines({ items }: { items: Inline[] }): ReactNode {
  return items.map((x, i) => {
    switch (x.kind) {
      case 'text': return x.text
      case 'strong': return <strong key={i} className="font-semibold"><Inlines items={x.children} /></strong>
      case 'code': return <code key={i} className="rounded bg-sunken px-1 py-0.5 font-mono text-meta">{x.text}</code>
      case 'image': return <Image key={i} src={x.src} alt={x.alt} />
      case 'link': {
        const to = linkTarget(x.href)
        if (!to) return <Inlines key={i} items={x.children} />
        return 'internal' in to
          ? <Link key={i} to={to.internal} className="text-accent underline underline-offset-4">{<Inlines items={x.children} />}</Link>
          : <a key={i} href={to.external} target="_blank" rel="noreferrer" className="text-accent underline underline-offset-4"><Inlines items={x.children} /></a>
      }
    }
  })
}

function BlockView({ block, nested }: { block: Block; nested?: boolean }): ReactNode {
  switch (block.kind) {
    case 'heading': {
      const H = block.level === 1 ? 'h2' : block.level === 2 ? 'h2' : 'h3'
      return <H className={cn('font-semibold', block.level <= 2 ? 'mt-4 text-base' : 'mt-2 text-sm')}><Inlines items={block.children} /></H>
    }
    case 'paragraph': return <p className={cn(nested ? '' : 'max-w-3xl')}><Inlines items={block.children} /></p>
    case 'image': return <figure className="my-1"><Image src={block.src} alt={block.alt} /></figure>
    case 'code': return <pre className="overflow-x-auto rounded-md border border-rule bg-sunken p-3 font-mono text-meta"><code>{block.text}</code></pre>
    case 'list': {
      const items = block.items.map((item, i) => <li key={i} className="pl-1">{/* not a grid on the li: that would drop its number */}<div className="grid gap-3"><Blocks blocks={item} nested /></div></li>)
      return block.ordered
        ? <ol start={block.start} className="grid list-decimal gap-5 pl-6 marker:font-semibold">{items}</ol>
        : <ul className="grid list-disc gap-2 pl-6">{items}</ul>
    }
    case 'table': return (
      <div className="overflow-x-auto rounded-md border border-rule">
        <table className="w-full text-sm">
          <thead className="bg-sunken text-left text-meta text-muted"><tr>{block.head.map((c, i) => <th key={i} className="px-3 py-2 font-medium"><Inlines items={c} /></th>)}</tr></thead>
          <tbody>{block.rows.map((r, i) => <tr key={i} className="border-t border-rule">{r.map((c, k) => <td key={k} className="px-3 py-2 align-top"><Inlines items={c} /></td>)}</tr>)}</tbody>
        </table>
      </div>
    )
  }
}

function Blocks({ blocks, nested }: { blocks: Block[]; nested?: boolean }) {
  return blocks.map((b, i) => <BlockView key={i} block={b} nested={nested} />)
}

/** A recipe's blocks as a page body: readable line length, the screenshots as wide as the column. */
export function Markdown({ blocks }: { blocks: Block[] }) {
  return <div className="grid max-w-5xl gap-4 text-sm leading-relaxed">{<Blocks blocks={blocks} />}</div>
}
