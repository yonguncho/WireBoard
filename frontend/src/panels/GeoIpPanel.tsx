import { useEffect, useState } from 'react'
import { PlotlyChart } from './PlotlyChart'

interface GeoEntry {
  ip: string
  country_name: string
  country_code: string
  role: string
  attack_type: string
}

interface Props {
  uploadId: string
}

export function GeoIpPanel({ uploadId }: Props) {
  const [entries, setEntries] = useState<GeoEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!uploadId) return
    fetch(`/api/geoip/${uploadId}`)
      .then(r => r.json())
      .then(d => setEntries(d.entries))
      .catch(e => setError(String(e)))
  }, [uploadId])

  if (error) return <div className="no-data">GeoIP 로드 실패: {error}</div>
  if (!entries) return <div className="no-data">GeoIP 로드 중...</div>
  if (!entries.length) return <div className="no-data">분석된 외부 IP 없음</div>

  // 국가별 집계
  const countryCount: Record<string, { code: string; count: number; attacker: boolean }> = {}
  for (const e of entries) {
    if (!countryCount[e.country_name]) {
      countryCount[e.country_name] = { code: e.country_code, count: 0, attacker: false }
    }
    countryCount[e.country_name].count++
    if (e.role === 'attacker') countryCount[e.country_name].attacker = true
  }
  const countries = Object.entries(countryCount).sort((a, b) => b[1].count - a[1].count)

  // choropleth 타입은 plotly-dist-min.d.ts에 없을 수 있으므로 any로 우회
  const choroplethData = [{
    type: 'choropleth' as const,
    locations: countries.map(([, v]) => v.code),
    z: countries.map(([, v]) => v.count),
    text: countries.map(([name]) => name),
    colorscale: 'Reds',
    colorbar: { title: { text: 'IP 수' } },
  }] as any[]

  const choroplethLayout = {
    geo: { showframe: false, showcoastlines: true, projection: { type: 'natural earth' } },
    margin: { t: 0, b: 0, l: 0, r: 0 },
  }

  return (
    <div>
      <PlotlyChart data={choroplethData} layout={choroplethLayout as any} height={260} />
      <table className="mini-table" style={{ marginTop: 8 }}>
        <thead>
          <tr><th>국가</th><th>IP 수</th><th>역할</th></tr>
        </thead>
        <tbody>
          {countries.slice(0, 15).map(([name, v]) => (
            <tr key={name} className={v.attacker ? 'row-error' : ''}>
              <td>{name}</td>
              <td>{v.count}</td>
              <td>{v.attacker ? '⚠ 공격자' : '외부'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: 8 }}>
        {entries.filter(e => e.role === 'attacker').map(e => (
          <span key={e.ip} className="chip chip-sessions" style={{ marginRight: 4, fontSize: 11 }}>
            {e.ip} ({e.country_code})
          </span>
        ))}
      </div>
    </div>
  )
}
