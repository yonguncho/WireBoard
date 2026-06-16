import { copyText } from '../toast'

interface Props {
  recommendations: string[]
  attackerIps: string[]
  victimIps: string[]
}

export function DefensePanel({ recommendations, attackerIps, victimIps }: Props) {
  return (
    <div className="defense-panel">
      <h3 className="defense-title">🛠 Recommended Actions</h3>

      {(attackerIps.length > 0 || victimIps.length > 0) && (
        <div className="defense-ips">
          {attackerIps.length > 0 && (
            <div className="defense-ip-group">
              <span className="defense-ip-label attacker-label">Event Source</span>
              {attackerIps.map(ip => (
                <span key={ip} className="ip-chip attacker copyable" title="Click to copy IP" onClick={() => copyText(ip)}>{ip}</span>
              ))}
            </div>
          )}
          {victimIps.length > 0 && (
            <div className="defense-ip-group">
              <span className="defense-ip-label victim-label">Target Host</span>
              {victimIps.map(ip => (
                <span key={ip} className="ip-chip victim copyable" title="Click to copy IP" onClick={() => copyText(ip)}>{ip}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {recommendations.length > 0 ? (
        <ol className="defense-list">
          {recommendations.map((r, i) => (
            <li key={i} className="defense-item">
              <span className="defense-num">{i + 1}</span>
              <span>{r}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="no-data">No recommendations</p>
      )}
    </div>
  )
}
