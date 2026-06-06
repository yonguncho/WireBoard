import { PlotlyChart } from './PlotlyChart'
import type { IpEntry } from '../api'

interface Props { data: { top_src: IpEntry[]; top_dst: IpEntry[] } }

function fmtBytes(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function Panel1Ip({ data }: Props) {
  const srcList = (data.top_src ?? []).slice(0, 8)
  const dstList = (data.top_dst ?? []).slice(0, 8)

  if (!srcList.length && !dstList.length) return <div className="no-data">데이터 없음</div>

  const traces = [
    {
      type: 'bar' as const,
      name: '송신',
      x: srcList.map(e => e.bytes),
      y: srcList.map(e => e.ip),
      orientation: 'h' as const,
      marker: { color: '#3b82f6' },
      hovertemplate: '<b>%{y}</b><br>%{customdata}<extra>송신</extra>',
      customdata: srcList.map(e => fmtBytes(e.bytes)),
    },
    {
      type: 'bar' as const,
      name: '수신',
      x: dstList.map(e => e.bytes),
      y: dstList.map(e => e.ip),
      orientation: 'h' as const,
      marker: { color: '#f59e0b' },
      hovertemplate: '<b>%{y}</b><br>%{customdata}<extra>수신</extra>',
      customdata: dstList.map(e => fmtBytes(e.bytes)),
    },
  ]

  return (
    <PlotlyChart
      data={traces}
      layout={{
        barmode: 'group',
        xaxis: { tickformat: '.2s', title: { text: 'bytes' } },
        margin: { l: 110, r: 12, t: 8, b: 36 },
      }}
      height={240}
    />
  )
}
