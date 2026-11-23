import { slotComponents } from '@/app/feature'

/** Shows every block that other modules plug into `name` (Feature.slots). None → shows nothing. */
export function Slot({ name, props }: { name: string; props: Record<string, unknown> }) {
  return <>{slotComponents(name).map((C, i) => <C key={i} {...props} />)}</>
}
