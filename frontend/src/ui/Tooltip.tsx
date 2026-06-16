import { TERMS } from './terms'

interface Props {
  term: string
  children: React.ReactNode
  position?: 'top' | 'bottom'
}

/** Tooltip that shows a beginner-friendly explanation when hovering over a term. Renders children as-is if the term is not in the TERMS dictionary. */
export function Tooltip({ term, children, position = 'top' }: Props) {
  const def = TERMS[term]
  if (!def) return <>{children}</>

  return (
    <span className={`tooltip-wrap tooltip-${position}`}>
      {children}
      <span className="tooltip-box">{def}</span>
    </span>
  )
}
