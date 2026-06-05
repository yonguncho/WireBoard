const BASE = ''

export async function uploadPcap(file: File): Promise<{ upload_id: string }> {
  const fd = new FormData()
  fd.append('file', file)
  const r = await fetch(`${BASE}/api/upload`, { method: 'POST', body: fd })
  if (!r.ok) throw new Error(`Upload failed: ${r.status}`)
  return r.json()
}

export async function analyzePcap(upload_id: string, target_ip?: string): Promise<Record<string, unknown>> {
  const body: Record<string, string> = { upload_id }
  if (target_ip) body.target_ip = target_ip
  const r = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`Analyze failed: ${r.status}`)
  return r.json()
}

export async function getPanels(upload_id: string): Promise<PanelData> {
  const r = await fetch(`${BASE}/api/panels/${upload_id}`)
  if (!r.ok) throw new Error(`Panels failed: ${r.status}`)
  return r.json()
}

export async function filterSessions(upload_id: string, query: string) {
  const r = await fetch(`${BASE}/api/filter`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ upload_id, query }),
  })
  if (!r.ok) throw new Error(`Filter failed: ${r.status}`)
  return r.json()
}

export interface PanelData {
  panel1_ip: { top_src: IpEntry[]; top_dst: IpEntry[] }
  panel2_protocol: { distribution: Record<string, number>; top_ports: PortEntry[] }
  panel3_timeline: { buckets: BucketEntry[] }
  panel4_http: { counts: Record<string, number>; groups: Record<string, number>; top_errors: ErrorEntry[] }
  panel5_anomalies: { rst_count: number; malformed_count: number; retransmit_count: number }
  panel6_ip_ranking: IpRankEntry[]
  panel7_tls: TlsEntry[]
  panel8_dns: DnsEntry[]
  panel9_conversations: ConvEntry[]
  panel10_attacks: AttackEntry[]
}

export interface IpEntry { ip: string; bytes: number }
export interface PortEntry { port: number; count: number }
export interface BucketEntry { ts: number; bytes: number }
export interface ErrorEntry { status: number; count: number; path?: string }
export interface IpRankEntry { ip: string; bytes: number; is_internal: boolean }
export interface TlsEntry { sni: string; version: string; dst_ip: string }
export interface DnsEntry { domain: string; type: string; response?: string; nxdomain: boolean }
export interface ConvEntry { src: string; dst: string; packets: number; bytes: number; duration_s: number }
export interface AttackEntry { attack_type: string; severity: string; mitre_id: string; description: string; src_ip?: string }
