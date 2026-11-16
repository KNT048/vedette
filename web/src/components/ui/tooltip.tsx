import type { ReactElement, ReactNode } from 'react'
import { Tooltip as TooltipPrimitive } from 'radix-ui'

/** One provider for the app (App.tsx), so moving along the rail skips the delay after the first tooltip. */
export function TooltipProvider({ children }: { children: ReactNode }) {
  return <TooltipPrimitive.Provider delayDuration={300} skipDelayDuration={300}>{children}</TooltipPrimitive.Provider>
}

/** The visible name of an icon-only control (docs/UI.md §2, §9): opens on hover and on keyboard focus, Esc closes it (WCAG 1.4.13).
 *  An explanation belongs in InfoTip, never here. `describe={false}` when the trigger already carries the same words as its name
 *  (a rail link keeps its label as sr-only text), so a screen reader does not hear them twice. Radix's Slot always joins the tooltip
 *  into the child's aria-describedby, so then the trigger is a wrapping span: it gets the description, the control keeps none, and
 *  hover and focus (focus events bubble from the control) still open the tooltip. */
export function Tooltip({ content, children, side = 'right', describe = true }: { content: ReactNode; children: ReactElement; side?: 'top' | 'right' | 'bottom' | 'left'; describe?: boolean }) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{describe ? children : <span className="inline-flex">{children}</span>}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={8}
          collisionPadding={8}
          className="z-[60] max-w-xs rounded-lg border border-rule bg-surface px-2.5 py-1.5 text-meta text-ink shadow-md"
        >
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  )
}
