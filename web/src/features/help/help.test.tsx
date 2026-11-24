// The Help pages: the cookbook of docs/cookbook, rendered from the build. Every recipe parses into known blocks (no raw Markdown
// marks on screen), every image and link it names exists, the menu has Help, and each main screen links to its own guide.
import { beforeEach, describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { IMAGES, PAGES } from 'virtual:cookbook'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { GUIDE_OF, guideOf } from '@/lib/guides'
import { RECIPES, linkTarget } from './cookbook'
import { parseInline, parseMarkdown, type Block, type Inline } from './parse'

beforeEach(() => localStorage.clear())

/** Every inline and every image or link of a recipe's blocks. */
function walk(blocks: Block[]): { texts: string[]; images: string[]; links: string[] } {
  const out = { texts: [] as string[], images: [] as string[], links: [] as string[] }
  const inl = (xs: Inline[]) => xs.forEach((x) => {
    if (x.kind === 'text') out.texts.push(x.text)
    else if (x.kind === 'image') out.images.push(x.src)
    else if (x.kind === 'link') { out.links.push(x.href); inl(x.children) }
    else if (x.kind === 'strong') inl(x.children)
  })
  const blk = (b: Block) => {
    if (b.kind === 'heading' || b.kind === 'paragraph') inl(b.children)
    else if (b.kind === 'image') out.images.push(b.src)
    else if (b.kind === 'list') b.items.forEach((i) => i.forEach(blk))
    else if (b.kind === 'table') [b.head, ...b.rows].flat().forEach(inl)
  }
  blocks.forEach(blk)
  return out
}

describe('the cookbook files', () => {
  it('has the eight recipes and the index, each recipe with a title and a goal', () => {
    expect(PAGES.map((p) => p.file)).toContain('README.md')
    expect(RECIPES).toHaveLength(8)
    for (const r of RECIPES) {
      expect(r.slug).toMatch(/^0\d-[a-z-]+$/)
      expect(r.title.length, r.slug).toBeGreaterThan(5)
      expect(r.goal.length, r.slug).toBeGreaterThan(10)
    }
  })

  it('every recipe and the index show no raw Markdown, and every image and link they name exists', () => {
    for (const p of PAGES) {
      const { texts, images, links } = walk(parseMarkdown(p.markdown))
      const raw = texts.filter((t) => /\*\*|!\[|\]\(|`|^#{1,6}\s|^\s*\|/.test(t))
      expect(raw, `${p.file}: Markdown the Help page would show as marks`).toEqual([])
      expect(images.filter((src) => !IMAGES[src]), `${p.file}: images missing from docs/cookbook/images`).toEqual([])
      expect(links.filter((href) => !linkTarget(href)), `${p.file}: links that lead nowhere`).toEqual([])
    }
  })

  it('every image in docs/cookbook/images is used by a recipe (a renamed shot leaves no orphan)', () => {
    const used = new Set(PAGES.flatMap((p) => walk(parseMarkdown(p.markdown)).images))
    expect(Object.keys(IMAGES).filter((k) => !used.has(k))).toEqual([])
  })

  it('parses nested lists, code and inline marks', () => {
    const blocks = parseMarkdown('1. **Open** it.\n\n   ![Shot](images/x.webp)\n\n   - a `cmd`\n   - [next](02-x.md)\n\n2. Second\n\n```\nsudo sh\n```')
    expect(blocks.map((b) => b.kind)).toEqual(['list', 'code'])
    const list = blocks[0]!
    expect(list.kind === 'list' && list.items.map((i) => i.map((b) => b.kind))).toEqual([['paragraph', 'image', 'list'], ['paragraph']])
    expect(parseInline('a **b** `c` [d](e.md)').map((x) => x.kind)).toEqual(['text', 'strong', 'text', 'code', 'text', 'link'])
  })
})

describe('Help pages', () => {
  it('Help is in the menu and lists every guide with its goal', async () => {
    const u = userEvent.setup()
    renderApp('/')
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    await u.click(within(nav).getByRole('link', { name: 'Help' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Help' })).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Guides' })
    for (const r of RECIPES) expect(within(list).getByRole('link', { name: r.title })).toHaveAttribute('href', `/help/${r.slug}`)
    await expectNoA11yViolations()
  })

  it('a guide shows its steps, its screenshots from the build and links to the other guides', async () => {
    renderApp('/help/03-read-and-fix-a-finding')
    expect(await screen.findByRole('heading', { level: 1, name: 'Read a finding and fix it' })).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Breadcrumb' })).getByRole('link', { name: 'Help' })).toHaveAttribute('href', '/help')
    const shot = screen.getByRole('img', { name: 'The Mark as handled dialog' })
    expect(shot.getAttribute('src')).toMatch(/^\/assets\/cookbook\/03-mark-handled-[0-9a-f]{8}\.webp$/)
    expect(screen.getByRole('link', { name: 'recipe 02' })).toHaveAttribute('href', '/help/02-add-devices-and-agents')
    expect(screen.getByRole('heading', { name: 'Check that it worked' })).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\*\*|!\[/)
    await expectNoA11yViolations()
  })

  it('an unknown guide says so and leads back to the list', async () => {
    renderApp('/help/99-nothing')
    expect(await screen.findByText('No such guide')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See all guides' })).toHaveAttribute('href', '/help')
  })
})

describe('main screens link to their guide', () => {
  it('every guide a screen names exists', () => {
    const slugs = new Set(RECIPES.map((r) => r.slug))
    expect(Object.values(GUIDE_OF).filter((g) => !slugs.has(g))).toEqual([])
  })

  it('a path takes the guide of its screen, a detail page included; other pages have none', () => {
    expect(guideOf('/findings')).toBe('03-read-and-fix-a-finding')
    expect(guideOf('/findings/fv-1')).toBe('03-read-and-fix-a-finding')
    expect(guideOf('/settings/channels')).toBe('04-alerts-email-telegram-zalo')
    expect(guideOf('/settings/general')).toBeUndefined()
    expect(guideOf('/devicesx')).toBeUndefined()
  })

  it.each([
    ['/findings', '03-read-and-fix-a-finding'],
    ['/devices', '02-add-devices-and-agents'],
    ['/settings/updates', '08-updates-backup-restore'],
  ])('%s shows "How-to guide" to its guide', async (path, guide) => {
    renderApp(path)
    expect(await screen.findByRole('link', { name: 'How-to guide' })).toHaveAttribute('href', `/help/${guide}`)
  })

  it('a screen without a guide shows no guide link', async () => {
    renderApp('/incidents')
    await screen.findByRole('heading', { level: 1 })
    expect(screen.queryByRole('link', { name: 'How-to guide' })).toBeNull()
  })
})
