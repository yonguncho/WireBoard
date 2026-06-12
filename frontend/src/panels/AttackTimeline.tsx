import type { AttackTimelineEntry } from '../api'
import { Tooltip } from '../ui/Tooltip'

interface Props {
  events: AttackTimelineEntry[]
  onSelect?: (event: AttackTimelineEntry) => void
}

const SEV_COLOR: Record<string, string> = {
  high:   '#fc4343',
  medium: '#f59e0b',
  low:    '#3b82f6',
}

const SEV_LABEL: Record<string, string> = {
  high:   'HIGH',
  medium: 'MED',
  low:    'LOW',
}

function fmtTs(ts: number) {
  if (ts === 0) return '—'
  return new Date(ts * 1000).toLocaleTimeString('ko-KR', { hour12: false })
}

export function AttackTimeline({ events, onSelect }: Props) {
  if (!events.length) {
    return <div className="no-data">탐지된 이벤트 없음</div>
  }

  return (
    <div className="attack-timeline">
      {events.map((e, i) => {
        const color = SEV_COLOR[e.severity] ?? '#718096'
        return (
          <div
            key={i}
            className="timeline-event"
            onClick={() => onSelect?.(e)}
            style={{ cursor: onSelect ? 'pointer' : 'default' }}
          >
            <div className="timeline-connector">
              <div className="timeline-dot" style={{ background: color }} />
              {i < events.length - 1 && <div className="timeline-line" />}
            </div>
            <div className="timeline-content">
              <div className="timeline-row1">
                <span className="timeline-ts">{fmtTs(e.ts)}</span>
                <span className="sev-badge" style={{ background: color + '22', color }}>
                  {SEV_LABEL[e.severity] ?? e.severity.toUpperCase()}
                </span>
                <Tooltip term={e.attack_type}>
                  <span className="timeline-type">{e.attack_type}</span>
                </Tooltip>
                {e.mitre_id && (
                  <Tooltip term={e.mitre_id} position="bottom">
                    <span className="mitre-tag">{e.mitre_id}</span>
                  </Tooltip>
                )}
              </div>
              {e.description && (
                <p className="timeline-desc">{e.description}</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
