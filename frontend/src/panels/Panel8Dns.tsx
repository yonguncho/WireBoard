import type { DnsEntry } from '../api'

interface Props { data: DnsEntry[] }

export function Panel8Dns({ data }: Props) {
  const rows = (data ?? []).slice(0, 50)
  if (!rows.length) return <div className="no-data">DNS 쿼리 없음</div>
  return (
    <table className="mini-table full-width">
      <thead><tr><th>도메인</th><th>타입</th><th>응답</th><th>상태</th></tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className={r.nxdomain ? 'row-error' : ''}>
            <td className="mono">{r.domain}</td>
            <td>{r.type}</td>
            <td className="mono">{r.response || '—'}</td>
            <td>{r.nxdomain ? <span className="badge badge-err">NXDOMAIN</span> : <span className="badge badge-ok">OK</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
