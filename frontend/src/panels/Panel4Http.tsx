import { PlotlyChart } from './PlotlyChart'

interface Props { data: { counts: Record<string, number>; groups: Record<string, number>; top_errors: { status_code: number; count: number }[] } }

const STATUS_COLOR: Record<string, string> = {
  '2xx': '#48bb78', '3xx': '#4299e1', '4xx': '#f6ad55', '5xx': '#fc8181',
}

export function Panel4Http({ data }: Props) {
  const groups = data.groups ?? {}
  const keys = Object.keys(groups)
  if (!keys.length) return <div className="no-data">HTTP 트래픽 없음</div>

  const traces = [{
    type: 'bar' as const,
    x: keys,
    y: keys.map(k => groups[k]),
    marker: { color: keys.map(k => STATUS_COLOR[k] ?? '#718096') },
  }]

  return (
    <div>
      <PlotlyChart data={traces} layout={{ xaxis: { title: { text: '상태 그룹' } }, yaxis: { title: { text: '횟수' } } }} height={200} />
      {(data.top_errors ?? []).length > 0 && (
        <table className="mini-table">
          <thead><tr><th>상태 코드</th><th>횟수</th></tr></thead>
          <tbody>
            {data.top_errors.slice(0, 5).map(e => (
              <tr key={e.status_code} className={e.status_code >= 500 ? 'row-error' : ''}>
                <td>{e.status_code}</td><td>{e.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
