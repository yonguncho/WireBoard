import { useEffect, useRef } from 'react'
import Plotly from 'plotly.js-dist-min'

interface Props {
  data: Plotly.Data[]
  layout?: Partial<Plotly.Layout>
  height?: number
}

export function PlotlyChart({ data, layout, height = 260 }: Props) {
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
    return () => { if (ref.current) Plotly.purge(ref.current) }
  }, [data, layout, height])

  return <div ref={ref} style={{ width: '100%' }} />
}
