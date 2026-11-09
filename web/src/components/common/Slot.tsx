import { slotComponents } from '@/app/feature'

/** Hiện mọi khối mà module khác cắm vào `name` (Feature.slots). Không có → không hiện gì. */
export function Slot({ name, props }: { name: string; props: Record<string, unknown> }) {
  return <>{slotComponents(name).map((C, i) => <C key={i} {...props} />)}</>
}
