interface Props {
  recommendations: string[]
  attackerIps: string[]
  victimIps: string[]
}

export function DefensePanel({ recommendations, attackerIps, victimIps }: Props) {
  return (
    <div className="defense-panel">
      <h3 className="defense-title">🛡 방어 권고</h3>

      {(attackerIps.length > 0 || victimIps.length > 0) && (
        <div className="defense-ips">
          {attackerIps.length > 0 && (
            <div className="defense-ip-group">
              <span className="defense-ip-label attacker-label">공격 출발지</span>
              {attackerIps.map(ip => (
                <span key={ip} className="ip-chip attacker">{ip}</span>
              ))}
            </div>
          )}
          {victimIps.length > 0 && (
            <div className="defense-ip-group">
              <span className="defense-ip-label victim-label">공격 대상</span>
              {victimIps.map(ip => (
                <span key={ip} className="ip-chip victim">{ip}</span>
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
        <p className="no-data">권고 사항 없음</p>
      )}
    </div>
  )
}
