import { useEffect, useState } from 'react'

interface YaraMatch {
  rule: string
  description: string
  severity: string
  mitre: string
  session_id: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  matched_strings: string[]
}

interface Props { uploadId: string }

const SEV_COLOR: Record<string, string> = {
  critical: '#fc8181',
  high: '#f6ad55',
  medium: '#f6e05e',
  low: '#48bb78',
}

export function YaraPanel({ uploadId }: Props) {
  const [data, setData] = useState<{ available: boolean; match_count: number; matches: YaraMatch[] } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!uploadId) return
    fetch(`/api/yara/${uploadId}`)
      .then(r => { if (!r.ok) throw new Error(`YARA ${r.status}`); return r.json() })
      .then(setData)
      .catch(e => setError(String(e)))
  }, [uploadId])

  if (error) return <div className="no-data">YARA 로드 실패: {error}</div>
  if (!data) return <div className="no-data">YARA 스캔 중...</div>
  if (!data.available) return (
    <div className="no-data">
      yara-python 패키지가 설치되지 않아 YARA 탐지를 사용할 수 없습니다.<br/>
      <code>pip install yara-python</code>
    </div>
  )
  if (!data.matches.length) return <div className="no-data" style={{color: '#48bb78'}}>✓ YARA 매치 없음 — 알려진 악성 패턴 미탐지</div>

  return (
    <div>
      <div style={{ marginBottom: 8, fontWeight: 600, fontSize: 13 }}>
        {data.match_count}개 YARA 매치 발견
      </div>
      <table className="mini-table">
        <thead>
          <tr><th>룰</th><th>심각도</th><th>MITRE</th><th>세션</th><th>설명</th></tr>
        </thead>
        <tbody>
          {data.matches.map((m, i) => (
            <tr key={i}>
              <td style={{ fontWeight: 600, color: SEV_COLOR[m.severity] ?? '#e2e8f0' }}>{m.rule}</td>
              <td>
                <span className="severity-badge" style={{ background: SEV_COLOR[m.severity] ?? '#718096', color: '#1a1d23', padding: '1px 6px', borderRadius: 4, fontSize: 10, fontWeight: 700 }}>
                  {m.severity.toUpperCase()}
                </span>
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{m.mitre}</td>
              <td className="mono" style={{ fontSize: 11 }}>{m.src_ip}:{m.src_port} → {m.dst_ip}:{m.dst_port}</td>
              <td style={{ fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{m.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
