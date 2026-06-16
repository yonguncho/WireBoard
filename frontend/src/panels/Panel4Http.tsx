import { PlotlyChart } from './PlotlyChart'
import type { ErrorEntry } from '../api'

interface Props { data: { counts: Record<string, number>; groups: Record<string, number>; top_errors: ErrorEntry[] } }

const STATUS_COLOR: Record<string, string> = {
  '2xx': '#48bb78', '3xx': '#4299e1', '4xx': '#f6ad55', '5xx': '#fc8181',
}

export function Panel4Http({ data }: Props) {
  const groups = data.groups ?? {}
  const keys = Object.keys(groups)
  if (!keys.length) return <div className="no-data">No HTTP traffic</div>

  const traces = [{
    type: 'bar' as const,
    x: keys,
    y: keys.map(k => groups[k]),
    marker: { color: keys.map(k => STATUS_COLOR[k] ?? '#718096') },
  }]

  return (
    <div>
      <PlotlyChart data={traces} layout={{ xaxis: { title: { text: 'Status Group' } }, yaxis: { title: { text: 'Count' } } }} height={200} />
      {(data.top_errors ?? []).length > 0 && (
        <table className="mini-table">
          <thead><tr><th>Status Code</th><th>Count</th></tr></thead>
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
