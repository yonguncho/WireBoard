import { TERMS } from './terms'

interface Props {
  term: string
  children: React.ReactNode
  position?: 'top' | 'bottom'
}

/** 용어 위에 호버하면 초보자 설명을 보여주는 tooltip. TERMS 사전에 없으면 그냥 children 렌더링. */
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
