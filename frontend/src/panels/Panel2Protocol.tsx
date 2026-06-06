import { PlotlyChart } from './PlotlyChart'
import { Tooltip } from '../ui/Tooltip'

interface Props { data: { distribution: Record<string, number>; top_ports: { port: number; count: number }[] } }

const PIE_COLORS = ['#4299e1', '#48bb78', '#f6ad55', '#fc8181', '#9f7aea', '#76e4f7', '#f687b3', '#fbd38d']

function fmtPct(v: number, total: number) {
  return total > 0 ? ((v / total) * 100).toFixed(1) + '%' : '—'
}

export function Panel2Protocol({ data }: Props) {
  const dist   = data.distribution ?? {}
  const labels = Object.keys(dist)
  const values = Object.values(dist)
  const total  = values.reduce((a, b) => a + b, 0)

  if (!labels.length) return <div className="no-data">데이터 없음</div>

  const traces = [{
    type: 'pie' as const,
    labels,
    values,
    hole: 0.35,
    marker: { colors: PIE_COLORS },
    textinfo: 'label+percent' as const,
  }]

  return (
    <div>
      <PlotlyChart data={traces} layout={{ showlegend: false }} height={200} />

      {/* 프로토콜 범례 — hover tooltip 포함 */}
      <table className="mini-table full-width" style={{ marginTop: 8 }}>
        <thead><tr><th>프로토콜</th><th>세션</th><th>비율</th></tr></thead>
        <tbody>
          {labels.map((proto, i) => (
            <tr key={proto}>
              <td>
                <Tooltip term={proto}>
                  <span style={{ color: PIE_COLORS[i % PIE_COLORS.length], cursor: 'help' }}>
                    {proto}
                  </span>
                </Tooltip>
              </td>
              <td>{values[i].toLocaleString()}</td>
              <td>{fmtPct(values[i], total)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {data.top_ports?.length > 0 && (
        <table className="mini-table" style={{ marginTop: 10 }}>
          <thead><tr><th>상위 포트</th><th>세션수</th></tr></thead>
          <tbody>
            {data.top_ports.slice(0, 5).map(p => (
              <tr key={p.port}><td>{p.port}</td><td>{p.count}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
