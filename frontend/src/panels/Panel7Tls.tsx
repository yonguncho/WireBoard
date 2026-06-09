import { TlsEntry } from '../api'

interface Props { data: TlsEntry[] }

export function Panel7Tls({ data }: Props) {
  const rows = (data ?? []).slice(0, 50)
  if (!rows.length) return <div className="no-data">TLS 세션 없음</div>
  return (
    <table className="mini-table full-width">
      <thead><tr><th>SNI</th><th>버전</th><th>DST IP</th></tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className={r.version === 'TLS 1.0' || r.version === 'TLS 1.1' ? 'row-warn' : ''}>
            <td className="mono">{r.sni || '—'}</td>
            <td>{r.version}</td>
            <td className="mono">{r.dst_ip}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
