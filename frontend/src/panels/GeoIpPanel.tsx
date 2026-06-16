import { useEffect, useState } from 'react'
import { PlotlyChart } from './PlotlyChart'
import { getCaptureToken } from '../api'

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
    const token = getCaptureToken(uploadId)
    fetch(`/api/geoip/${uploadId}`, { headers: token ? { 'X-Upload-Token': token } : {} })
      .then(r => r.json())
      .then(d => setEntries(d.entries))
      .catch(e => setError(String(e)))
  }, [uploadId])

  if (error) return <div className="no-data">Failed to load GeoIP: {error}</div>
  if (!entries) return <div className="no-data">Loading GeoIP...</div>
  if (!entries.length) return <div className="no-data">No external IPs analyzed</div>

  // Aggregate by country
  const countryCount: Record<string, { code: string; count: number; attacker: boolean }> = {}
  for (const e of entries) {
    if (!countryCount[e.country_name]) {
      countryCount[e.country_name] = { code: e.country_code, count: 0, attacker: false }
    }
    countryCount[e.country_name].count++
    if (e.role === 'attacker') countryCount[e.country_name].attacker = true
  }
  const countries = Object.entries(countryCount).sort((a, b) => b[1].count - a[1].count)

  // The choropleth type may be missing from plotly-dist-min.d.ts, so cast through any
  const choroplethData = [{
    type: 'choropleth' as const,
    locations: countries.map(([, v]) => v.code),
    z: countries.map(([, v]) => v.count),
    text: countries.map(([name]) => name),
    colorscale: 'Reds',
    colorbar: { title: { text: 'IP Count' } },
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
          <tr><th>Country</th><th>IP Count</th><th>Role</th></tr>
        </thead>
        <tbody>
          {countries.slice(0, 15).map(([name, v]) => (
            <tr key={name} className={v.attacker ? 'row-error' : ''}>
              <td>{name}</td>
              <td>{v.count}</td>
              <td>{v.attacker ? '⚠ Event Source' : 'External'}</td>
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
