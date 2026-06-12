import { TlsEntry } from '../api'

interface Props { data: { entries: TlsEntry[]; no_meta_count: number } }

export function Panel7Tls({ data }: Props) {
  const rows = (data?.entries ?? []).slice(0, 50)
  const noMeta = data?.no_meta_count ?? 0
  if (!rows.length && !noMeta) return <div className="no-data">TLS 세션 없음</div>
  return (
    <div>
      {rows.length > 0 ? (
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
      ) : (
        <div className="no-data">TLS 핸드셰이크 메타데이터 없음</div>
      )}
      {noMeta > 0 && (
        <div style={{ color: '#a0aec0', fontSize: 11, marginTop: 6 }}>
          ℹ 443 포트 세션 중 핸드셰이크 미캡처 {noMeta.toLocaleString()}건
        </div>
      )}
    </div>
  )
}
