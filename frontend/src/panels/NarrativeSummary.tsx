import { useState } from 'react'
import type { SummaryData } from '../api'

interface Props {
  data: SummaryData
}

const RISK_COLOR: Record<string, string> = {
  HIGH:   '#fc4343',
  MEDIUM: '#f59e0b',
  LOW:    '#3b82f6',
  CLEAN:  '#22c55e',
}

const RISK_LABEL: Record<string, string> = {
  HIGH:   '⚠ HIGH — 즉각 조치 필요',
  MEDIUM: '△ MEDIUM — 모니터링 강화',
  LOW:    '▷ LOW — 주의 필요',
  CLEAN:  '✓ CLEAN — 정상 트래픽',
}

export function NarrativeSummary({ data }: Props) {
  const [showExplain, setShowExplain] = useState<string | null>(null)
  const [showRecs, setShowRecs] = useState(false)
  const color = RISK_COLOR[data.risk_level] ?? '#a0aec0'

  return (
    <div className="narrative-card" style={{ borderLeft: `4px solid ${color}` }}>
      {/* 위험도 뱃지 + 헤드라인 */}
      <div className="narrative-header">
        <span className="risk-badge" style={{ background: color + '22', color }}>
          {RISK_LABEL[data.risk_level] ?? data.risk_level}
        </span>
        <h2 className="narrative-headline">{data.headline}</h2>
      </div>

      {/* 내러티브 문장 */}
      <p className="narrative-body" style={{ whiteSpace: 'pre-wrap' }}>{data.narrative}</p>

      {/* 공격자 / 피해자 IP */}
      {(data.attacker_ips.length > 0 || data.victim_ips.length > 0) && (
        <div className="ip-row">
          {data.attacker_ips.length > 0 && (
            <div className="ip-group">
              <span className="ip-group-label">🔴 공격 출발지</span>
              {data.attacker_ips.map(ip => (
                <span key={ip} className="ip-chip attacker">{ip}</span>
              ))}
            </div>
          )}
          {data.victim_ips.length > 0 && (
            <div className="ip-group">
              <span className="ip-group-label">🔵 공격 대상</span>
              {data.victim_ips.map(ip => (
                <span key={ip} className="ip-chip victim">{ip}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 공격 설명 토글 */}
      {Object.keys(data.attack_explanations).length > 0 && (
        <div className="explain-section">
          <div className="explain-chips">
            {Object.keys(data.attack_explanations).map(t => (
              <button
                key={t}
                className={`explain-chip${showExplain === t ? ' active' : ''}`}
                onClick={() => setShowExplain(showExplain === t ? null : t)}
              >
                ? {t}이란
              </button>
            ))}
          </div>
          {showExplain && data.attack_explanations[showExplain] && (
            <div className="explain-box">
              <strong>{showExplain}</strong>
              <p>{data.attack_explanations[showExplain]}</p>
            </div>
          )}
        </div>
      )}

      {/* 방어 권고 토글 */}
      {data.recommendations.length > 0 && (
        <div className="rec-section">
          <button
            className="rec-toggle"
            onClick={() => setShowRecs(v => !v)}
          >
            🛡 방어 권고 {data.recommendations.length}개 {showRecs ? '▲' : '▼'}
          </button>
          {showRecs && (
            <ul className="rec-list">
              {data.recommendations.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
