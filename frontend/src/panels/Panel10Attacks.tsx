import type { AttackEntry } from '../api'
import { Tooltip } from '../ui/Tooltip'

interface Props { data: AttackEntry[] }

const SEV_CLASS: Record<string, string> = {
  high: 'badge-err', medium: 'badge-warn', low: 'badge-ok', critical: 'badge-crit',
}

export function Panel10Attacks({ data }: Props) {
  const attacks = data ?? []
  if (!attacks.length) return <div className="no-attacks">✅ 탐지된 공격 없음</div>
  return (
    <div className="attacks-list">
      {attacks.map((a, i) => (
        <div key={i} className={`attack-card sev-${a.severity}`}>
          <div className="attack-header">
            <Tooltip term={a.attack_type}>
              <span className="attack-type">{a.attack_type}</span>
            </Tooltip>
            <span className={`badge ${SEV_CLASS[a.severity] ?? 'badge-ok'}`}>{a.severity.toUpperCase()}</span>
            <Tooltip term={a.mitre_id} position="bottom">
              <span className="mitre-id">{a.mitre_id}</span>
            </Tooltip>
            {a.src_ip && <span className="mono attack-ip">{a.src_ip}</span>}
          </div>
          <div className="attack-desc">{a.description}</div>
        </div>
      ))}
    </div>
  )
}
