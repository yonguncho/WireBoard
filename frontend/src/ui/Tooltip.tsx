import { useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { TERMS } from './terms'

interface Props {
  term: string
  children: React.ReactNode
  position?: 'top' | 'bottom'
}

/** Tooltip that shows a beginner-friendly explanation when hovering over a term.
 *  The bubble is rendered through a portal with position:fixed so it is never
 *  clipped by an ancestor's overflow:hidden (e.g. .panel-card). */
export function Tooltip({ term, children, position = 'top' }: Props) {
  const def = TERMS[term]
  const wrapRef = useRef<HTMLSpanElement>(null)
  const [coords, setCoords] = useState<{ left: number; top: number } | null>(null)

  if (!def) return <>{children}</>

  const show = () => {
    const el = wrapRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const half = 140 // tooltip max-width 280 / 2
    const left = Math.min(Math.max(r.left + r.width / 2, half + 8), window.innerWidth - half - 8)
    const top = position === 'top' ? r.top - 7 : r.bottom + 7
    setCoords({ left, top })
  }
  const hide = () => setCoords(null)

  return (
    <span ref={wrapRef} className="tooltip-wrap" onMouseEnter={show} onMouseLeave={hide}>
      {children}
      {coords &&
        createPortal(
          <span
            className={`tooltip-box tooltip-fixed tooltip-${position}`}
            style={{ left: coords.left, top: coords.top }}
          >
            {def}
          </span>,
          document.body,
        )}
    </span>
  )
}
