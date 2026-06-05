import { PlotlyChart } from './PlotlyChart'

interface Props { data: { distribution: Record<string, number>; top_ports: { port: number; count: number }[] } }

export function Panel2Protocol({ data }: Props) {
  const dist = data.distribution ?? {}
  const labels = Object.keys(dist)
  const values = Object.values(dist)

  if (!labels.length) return <div className="no-data">데이터 없음</div>

  const traces = [{
    type: 'pie' as const,
    labels,
    values,
    hole: 0.35,
    marker: { colors: ['#4299e1', '#48bb78', '#f6ad55', '#fc8181', '#9f7aea', '#76e4f7'] },
    textinfo: 'label+percent' as const,
  }]

  return (
    <div>
      <PlotlyChart data={traces} layout={{ showlegend: false }} height={220} />
      {data.top_ports?.length > 0 && (
        <table className="mini-table">
          <thead><tr><th>포트</th><th>세션수</th></tr></thead>
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
