import type { ConvEntry } from '../api'

interface Props { data: ConvEntry[] }

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function Panel9Conversations({ data }: Props) {
  const rows = (data ?? []).slice(0, 20)
  if (!rows.length) return <div className="no-data">데이터 없음</div>
  return (
    <table className="mini-table full-width">
      <thead>
        <tr><th>SRC</th><th>DST</th><th>패킷</th><th>바이트</th><th>시간(s)</th></tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td className="mono">{r.src}</td>
            <td className="mono">{r.dst}</td>
            <td>{r.packets.toLocaleString()}</td>
            <td>{fmtBytes(r.bytes)}</td>
            <td>{r.duration_s.toFixed(1)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
