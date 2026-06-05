import { useEffect, useRef } from 'react'
import Plotly from 'plotly.js-dist-min'

interface Props {
  data: Plotly.Data[]
  layout?: Partial<Plotly.Layout>
  height?: number
  onRelayout?: (e: Record<string, unknown>) => void
}

export function PlotlyChart({ data, layout, height = 260, onRelayout }: Props) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!ref.current) return
    const config: Partial<Plotly.Config> = { displayModeBar: false, responsive: true }
    const l: Partial<Plotly.Layout> = {
      paper_bgcolor: 'transparent',
      plot_bgcolor: 'transparent',
      font: { color: '#e2e8f0', size: 11 },
      margin: { l: 48, r: 12, t: 8, b: 40 },
      height,
      ...layout,
    }
    Plotly.newPlot(ref.current, data, l, config)

    if (onRelayout) {
      // Plotly attaches .on() to the DOM element after newPlot
      const el = ref.current as HTMLDivElement & { on?: (event: string, fn: (e: Record<string, unknown>) => void) => void }
      el.on?.('plotly_relayout', onRelayout)
    }

    return () => { if (ref.current) Plotly.purge(ref.current) }
  }, [data, layout, height, onRelayout])

  return <div ref={ref} style={{ width: '100%' }} />
}
