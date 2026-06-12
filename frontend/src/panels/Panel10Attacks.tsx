import { AttackEntry } from '../api'
import { copyText } from '../toast'

interface Props { data: AttackEntry[] }

const SEV_CLASS: Record<string, string> = {
  high: 'badge-err', medium: 'badge-warn', low: 'badge-ok', critical: 'badge-crit',
}

export function Panel10Attacks({ data }: Props) {
  const attacks = data ?? []
  if (!attacks.length) return <div className="no-attacks">✅ 탐지된 이벤트 없음</div>
  return (
    <div className="attacks-list">
      {attacks.map((a, i) => (
        <div key={i} className={`attack-card sev-${a.severity}`}>
          <div className="attack-header">
            <span className="attack-type">{a.attack_type}</span>
            <span className={`badge ${SEV_CLASS[a.severity] ?? 'badge-ok'}`}>{a.severity.toUpperCase()}</span>
            <span className="mitre-id">{a.mitre_id}</span>
            {a.src_ip && <span className="mono attack-ip copyable" title="클릭하여 IP 복사" onClick={() => copyText(a.src_ip!)}>{a.src_ip}</span>}
          </div>
          <div className="attack-desc">{a.description}</div>
        </div>
      ))}
    </div>
  )
}
