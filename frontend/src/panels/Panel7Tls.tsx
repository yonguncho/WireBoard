import { TlsEntry } from '../api'

interface Props {
  data: { entries: TlsEntry[]; no_meta_count: number; handshake_ok?: number; handshake_fail?: number }
}

const FAIL_REASON_LABELS: Record<string, string> = {
  no_server_response: 'no server response',
  rst_after_client_hello: 'RST after ClientHello',
}

function failLabel(reason?: string): string {
  if (!reason) return ''
  if (reason.startsWith('fatal_alert:')) return `alert: ${reason.slice('fatal_alert:'.length)}`
  return FAIL_REASON_LABELS[reason] ?? reason
}

function HandshakeCell({ e }: { e: TlsEntry }) {
  if (e.handshake === 'complete') return <td style={{ color: '#48bb78' }}>✓ established</td>
  if (e.handshake === 'failed')
    return <td style={{ color: '#fc8181' }}>✗ {failLabel(e.fail_reason) || 'failed'}</td>
  if (e.handshake === 'incomplete') return <td style={{ color: '#ecc94b' }}>~ incomplete</td>
  return <td style={{ color: '#a0aec0' }}>—</td>
}

export function Panel7Tls({ data }: Props) {
  const rows = (data?.entries ?? []).slice(0, 50)
  const noMeta = data?.no_meta_count ?? 0
  const ok = data?.handshake_ok ?? 0
  const fail = data?.handshake_fail ?? 0
  if (!rows.length && !noMeta) return <div className="no-data">No TLS sessions</div>
  return (
    <div>
      {(ok > 0 || fail > 0) && (
        <div style={{ fontSize: 12, marginBottom: 6 }}>
          <span style={{ color: '#48bb78' }}>✓ established {ok.toLocaleString()}</span>
          {fail > 0 && (
            <span style={{ color: '#fc8181', marginLeft: 12 }}>✗ failed {fail.toLocaleString()}</span>
          )}
        </div>
      )}
      {rows.length > 0 ? (
        <table className="mini-table full-width">
          <thead><tr><th>SNI</th><th>Version</th><th>DST IP</th><th>Sess</th><th>Handshake</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={r.version === 'TLS 1.0' || r.version === 'TLS 1.1' ? 'row-warn' : ''}>
                <td className="mono">{r.sni || '—'}</td>
                <td>{r.version}</td>
                <td className="mono">{r.dst_ip}</td>
                <td>{r.count ?? 1}</td>
                <HandshakeCell e={r} />
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="no-data">No TLS handshake metadata</div>
      )}
      {noMeta > 0 && (
        <div style={{ color: '#a0aec0', fontSize: 11, marginTop: 6 }}>
          ℹ {noMeta.toLocaleString()} port 443 sessions with no captured handshake
        </div>
      )}
    </div>
  )
}
