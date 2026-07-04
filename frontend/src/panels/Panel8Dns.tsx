import { DnsEntry, DnsTiming } from '../api'

interface Props { data: DnsEntry[]; timing?: DnsTiming }

const RCODE_BAD = new Set(['SERVFAIL', 'NXDOMAIN', 'REFUSED', 'FORMERR', 'NOTIMP'])

function rtColor(ms: number | null): string {
  if (ms === null) return '#a0aec0'
  if (ms > 200) return '#fc4343'
  if (ms > 50) return '#f59e0b'
  return '#22c55e'
}

export function Panel8Dns({ data, timing }: Props) {
  const rows = (data ?? []).slice(0, 50)
  const hasTiming = timing && timing.total > 0

  return (
    <div>
      {hasTiming && (
        <>
          {/* DNS latency + health summary — NOC가 먼저 보는 것 */}
          <div className="dns-stat-row">
            <div className="dns-stat"><span className="dns-stat-num">{timing.total}</span><span className="dns-stat-label">Queries</span></div>
            <div className="dns-stat"><span className="dns-stat-num" style={{ color: timing.unanswered ? '#fc4343' : '#22c55e' }}>{timing.unanswered}</span><span className="dns-stat-label">No response</span></div>
            <div className="dns-stat"><span className="dns-stat-num" style={{ color: timing.errors ? '#f59e0b' : '#22c55e' }}>{timing.errors}</span><span className="dns-stat-label">Errors (SERVFAIL/NX)</span></div>
            <div className="dns-stat"><span className="dns-stat-num">{timing.p50_ms}<small>ms</small></span><span className="dns-stat-label">p50</span></div>
            <div className="dns-stat"><span className="dns-stat-num" style={{ color: rtColor(timing.p95_ms) }}>{timing.p95_ms}<small>ms</small></span><span className="dns-stat-label">p95</span></div>
            <div className="dns-stat"><span className="dns-stat-num" style={{ color: rtColor(timing.max_ms) }}>{timing.max_ms}<small>ms</small></span><span className="dns-stat-label">max</span></div>
          </div>

          {(timing.unanswered_queries.length > 0 || timing.slowest.length > 0) && (
            <table className="mini-table full-width" style={{ marginBottom: 12 }}>
              <thead><tr><th>Query</th><th>Type</th><th>Rcode</th><th>Response time</th></tr></thead>
              <tbody>
                {timing.unanswered_queries.map((p, i) => (
                  <tr key={`u${i}`} className="row-error">
                    <td className="mono">{p.name}</td><td>{p.type}</td>
                    <td><span className="badge badge-err">NO RESPONSE</span></td>
                    <td className="mono">—</td>
                  </tr>
                ))}
                {timing.slowest.slice(0, 10).map((p, i) => (
                  <tr key={`s${i}`} className={p.rcode && RCODE_BAD.has(p.rcode) ? 'row-error' : ''}>
                    <td className="mono">{p.name}</td><td>{p.type}</td>
                    <td>{p.rcode && RCODE_BAD.has(p.rcode)
                      ? <span className="badge badge-err">{p.rcode}</span>
                      : <span className="badge badge-ok">{p.rcode}</span>}</td>
                    <td className="mono" style={{ color: rtColor(p.response_time_ms) }}>
                      {p.response_time_ms !== null ? `${p.response_time_ms} ms` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {/* Query inventory (unique domain/type/rcode) */}
      {rows.length === 0 ? (
        !hasTiming && <div className="no-data">No DNS queries</div>
      ) : (
        <table className="mini-table full-width">
          <thead><tr><th>Domain</th><th>Type</th><th>Response</th><th>Status</th></tr></thead>
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
      )}
    </div>
  )
}
