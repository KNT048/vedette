// The recipes of docs/cookbook, from the build (virtual:cookbook): the same files GitHub shows. README.md is GitHub's index; the
// Help page builds its own list from the recipes' titles and goals, so the index carries no notes for contributors.
import { IMAGES, PAGES } from 'virtual:cookbook'
import { parseMarkdown, plainText, type Block } from './parse'

export type Recipe = { slug: string; title: string; goal: string; blocks: Block[] }

function recipeOf(file: string, markdown: string): Recipe {
  const blocks = parseMarkdown(markdown)
  const h1 = blocks.find((b) => b.kind === 'heading' && b.level === 1)
  const goal = blocks.find((b) => b.kind === 'paragraph' && plainText(b.children).startsWith('Goal:'))
  return {
    slug: file.replace(/\.md$/, ''),
    title: h1?.kind === 'heading' ? h1.text : file,
    goal: goal?.kind === 'paragraph' ? plainText(goal.children).replace(/^Goal:\s*/, '') : '',
    // The page shows the title in its header.
    blocks: blocks.filter((b) => b !== h1),
  }
}

export const RECIPES: Recipe[] = PAGES.filter((p) => p.file !== 'README.md').map((p) => recipeOf(p.file, p.markdown))

export const recipeBySlug = (slug: string | undefined) => RECIPES.find((r) => r.slug === slug)

/** The served URL of an image a recipe names ("images/x.webp"); undefined for an image that is not in docs/cookbook/images. */
export const imageUrl = (src: string) => IMAGES[src.replace(/^\.\//, '')]

/** Where a link of a recipe goes: another recipe (xx.md) is its Help page, the index (README.md) is /help, the web stays the web. */
export function linkTarget(href: string): { internal: string } | { external: string } | null {
  if (/^https?:\/\//.test(href)) return { external: href }
  const md = /^(?:\.\/)?([\w-]+)\.md$/.exec(href)
  if (!md) return null
  if (md[1] === 'README') return { internal: '/help' }
  return recipeBySlug(md[1]) ? { internal: `/help/${md[1]}` } : null
}
