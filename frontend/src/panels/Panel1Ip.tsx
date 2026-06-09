import { PlotlyChart } from './PlotlyChart'
import { IpEntry } from '../api'

interface Props { data: { top_src: IpEntry[]; top_dst: IpEntry[] } }

function fmt(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function Panel1Ip({ data }: Props) {
  const top5src = (data.top_src ?? []).slice(0, 10)
  const top5dst = (data.top_dst ?? []).slice(0, 10)
  const traces = [
    {
      type: 'bar' as const,
      name: 'SRC',
      x: top5src.map(e => fmt(e.bytes)),
      y: top5src.map(e => e.ip),
      orientation: 'h' as const,
      marker: { color: '#4299e1' },
    },
    {
      type: 'bar' as const,
      name: 'DST',
      x: top5dst.map(e => fmt(e.bytes)),
      y: top5dst.map(e => e.ip),
      orientation: 'h' as const,
      marker: { color: '#f6ad55' },
    },
  ]
  if (!top5src.length && !top5dst.length) return <div className="no-data">데이터 없음</div>
  return <PlotlyChart data={traces} layout={{ barmode: 'group', xaxis: { title: 'bytes' } }} />
}
