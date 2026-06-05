import { PlotlyChart } from './PlotlyChart'
import type { BucketEntry } from '../api'

interface Props { data: { buckets: BucketEntry[] } }

export function Panel3Timeline({ data }: Props) {
  const buckets = data.buckets ?? []
  if (!buckets.length) return <div className="no-data">데이터 없음</div>

  const xs: string[] = []
  const ys: number[] = []
  for (const b of buckets) {
    xs.push(new Date(b.ts * 1000).toISOString())
    ys.push(b.bytes)
  }

  const traces = [{
    type: 'scatter' as const,
    mode: 'lines' as const,
    x: xs,
    y: ys,
    fill: 'tozeroy' as const,
    line: { color: '#4299e1', width: 1.5 },
    fillcolor: 'rgba(66,153,225,0.15)',
  }]

  return (
    <PlotlyChart
      data={traces}
      layout={{ xaxis: { title: { text: '시간' }, type: 'date' }, yaxis: { title: { text: 'bytes' } } }}
      height={240}
    />
  )
}
