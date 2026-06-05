import type { IpRankEntry } from '../api'

interface Props { data: IpRankEntry[] }

function fmt(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function Panel6IpRanking({ data }: Props) {
  const rows = (data ?? []).slice(0, 20)
  if (!rows.length) return <div className="no-data">데이터 없음</div>
  return (
    <table className="mini-table full-width">
      <thead>
        <tr><th>#</th><th>IP</th><th>바이트</th><th>유형</th></tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={r.ip} className={i < 3 ? 'row-highlight' : ''}>
            <td>{i + 1}</td>
            <td className="mono">{r.ip}</td>
            <td>{fmt(r.bytes)}</td>
            <td><span className={`badge ${r.is_internal ? 'badge-int' : 'badge-ext'}`}>{r.is_internal ? 'INT' : 'EXT'}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
