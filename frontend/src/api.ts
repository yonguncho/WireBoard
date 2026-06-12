const BASE = ''

async function handleError(r: Response, label: string): Promise<never> {
  let msg = `${label} (${r.status})`
  try {
    const body = await r.json()
    const d = body.detail
    if (d?.message) msg = d.message
    else if (typeof d === 'string') msg = d
    if (d?.errors?.length) msg += '\n' + (d.errors as string[]).slice(0, 3).join('\n')
  } catch { /* ignore */ }
  throw new Error(msg)
}

function tokenHeader(token?: string): Record<string, string> {
  return token ? { 'X-Upload-Token': token } : {}
}

export async function uploadPcap(file: File): Promise<{ upload_id: string; capture_token: string; session_count: number; source_type: string; parse_warnings: string[] }> {
  const fd = new FormData()
  fd.append('file', file)
  const r = await fetch(`${BASE}/api/upload`, { method: 'POST', body: fd })
  if (!r.ok) return handleError(r, '파일 형식을 인식할 수 없습니다')
  return r.json()
}

export async function analyzePcap(upload_id: string, target_ip?: string, capture_token?: string): Promise<Record<string, unknown>> {
  const body: Record<string, string> = { upload_id }
  if (target_ip) body.target_ip = target_ip
  const r = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(capture_token) },
    body: JSON.stringify(body),
  })
  if (!r.ok) return handleError(r, '분석 실패')
  return r.json()
}

export async function getPanels(upload_id: string, capture_token?: string): Promise<PanelData> {
  const r = await fetch(`${BASE}/api/panels/${upload_id}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '패널 로드 실패')
  return r.json()
}

export async function addAnnotation(upload_id: string, start_ts: number, end_ts: number, comment: string, capture_token?: string) {
  const r = await fetch(`${BASE}/api/annotations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(capture_token) },
    body: JSON.stringify({ upload_id, start_ts, end_ts, comment }),
  })
  if (!r.ok) return handleError(r, '마커 저장 실패')
  return r.json()
}

export async function getDrilldown(upload_id: string, ip: string, capture_token?: string): Promise<DrilldownResult> {
  const r = await fetch(`${BASE}/api/drilldown/${upload_id}?ip=${encodeURIComponent(ip)}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '드릴다운 실패')
  return r.json()
}

export async function filterSessions(upload_id: string, query: string, capture_token?: string) {
  const r = await fetch(`${BASE}/api/filter`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(capture_token) },
    body: JSON.stringify({ upload_id, query }),
  })
  if (!r.ok) return handleError(r, '필터 실패')
  return r.json()
}

export interface PanelData {
  panel1_ip: { top_src: IpEntry[]; top_dst: IpEntry[] }
  panel2_protocol: { distribution: Record<string, number>; top_ports: PortEntry[] }
  panel3_timeline: { buckets: BucketEntry[] }
  panel4_http: { counts: Record<string, number>; groups: Record<string, number>; top_errors: ErrorEntry[] }
  panel5_anomalies: { rst_count: number; malformed_count: number; retransmit_count: number }
  panel6_ip_ranking: IpRankEntry[]
  panel7_tls: { entries: TlsEntry[]; no_meta_count: number }
  panel8_dns: DnsEntry[]
  panel9_conversations: ConvEntry[]
  panel10_attacks: AttackEntry[]
}

export interface IpEntry { ip: string; bytes: number; is_private?: boolean }
export interface PortEntry { port: number; count: number }
export interface BucketEntry { ts: number; bytes: number }
export interface ErrorEntry { status_code: number; count: number; path?: string }
export interface IpRankEntry { ip: string; bytes: number; is_internal: boolean }
export interface TlsEntry { sni: string; version: string; dst_ip: string }
export interface DnsEntry { domain: string; type: string; response?: string; nxdomain: boolean }
export interface ConvEntry { src: string; dst: string; packets: number; bytes: number; duration_s: number }
export interface AttackEntry { attack_type: string; severity: string; mitre_id: string; description: string; src_ip?: string }

export async function getSummary(upload_id: string, capture_token?: string): Promise<SummaryData> {
  const r = await fetch(`${BASE}/api/summary/${upload_id}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '요약 로드 실패')
  return r.json()
}

export interface SummaryData {
  headline: string
  narrative: string
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN'
  attacker_ips: string[]
  victim_ips: string[]
  recommendations: string[]
  attack_timeline: AttackTimelineEntry[]
  attack_explanations: Record<string, string>
}

export interface AttackTimelineEntry {
  ts: number
  attack_type: string
  severity: string
  mitre_id: string
  description: string
  src_ip?: string
}

export interface DrilldownSession {
  session_id: string; src_ip: string; dst_ip: string
  src_port: number; dst_port: number; protocol: string
  bytes_sent: number; bytes_recv: number; packet_count: number
  start_ts: number; end_ts: number; duration_s: number; rst: boolean
}
export interface DrilldownResult { ip: string; session_count: number; sessions: DrilldownSession[] }

export interface FlowPacket {
  ts: number; rel_ts: number; direction: 'fwd' | 'rev'
  proto: string; seq: number; ack: number; flags: string
  length: number; payload_len: number; payload_hex: string
}
export interface FlowSession {
  session_id: string; src_ip: string; dst_ip: string
  src_port: number; dst_port: number; protocol: string
  packet_count: number; bytes_sent: number; bytes_recv: number
  start_ts: number; end_ts: number; duration_s: number; rst: boolean
}
export interface FlowData {
  session: FlowSession
  packets: FlowPacket[]
  packet_count: number
  truncated: boolean
}

export interface StreamSegment {
  direction: 'fwd' | 'rev'
  ts: number; rel_ts: number
  length: number
  text: string
  flags: string
}
export interface StreamData {
  session_id: string
  src_ip: string; dst_ip: string
  src_port: number; dst_port: number
  protocol: string
  encoding: string
  fwd_bytes: number; rev_bytes: number
  segments: StreamSegment[]
  truncated: boolean
}

export async function getStream(upload_id: string, session_id: string, encoding = 'ascii', capture_token?: string): Promise<StreamData> {
  const r = await fetch(`${BASE}/api/stream/${upload_id}?session_id=${encodeURIComponent(session_id)}&encoding=${encoding}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '스트림 로드 실패')
  return r.json()
}

export async function getFlow(upload_id: string, session_id: string, capture_token?: string): Promise<FlowData> {
  const r = await fetch(`${BASE}/api/flow/${upload_id}?session_id=${encodeURIComponent(session_id)}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '흐름 로드 실패')
  return r.json()
}

export interface PacketEntry {
  no: number; ts: number; rel_ts: number
  src_ip: string; src_port: number
  dst_ip: string; dst_port: number
  proto: string; seq: number; ack: number; flags: string
  length: number; payload_len: number; payload_hex: string
  session_id: string
}
export interface PacketListData {
  total: number; total_unfiltered: number; truncated: boolean
  offset: number; limit: number
  packets: PacketEntry[]
}

export async function getPackets(upload_id: string, queryString: string, capture_token?: string): Promise<PacketListData> {
  const r = await fetch(`${BASE}/api/packets/${upload_id}?${queryString}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '패킷 목록 로드 실패')
  return r.json()
}

export async function exportJson(upload_id: string, capture_token?: string): Promise<void> {
  const r = await fetch(`${BASE}/api/export/${upload_id}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, 'JSON 내보내기 실패')
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `wireboard_${upload_id.slice(0, 8)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

export async function exportPdf(upload_id: string, capture_token?: string): Promise<void> {
  const r = await fetch(`${BASE}/api/export/${upload_id}/pdf`, {
    method: 'POST',
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, 'PDF 내보내기 실패')
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `wireboard_${upload_id.slice(0, 8)}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

export async function exportIoc(uploadId: string, capture_token?: string): Promise<Blob> {
  const r = await fetch(`${BASE}/api/export/${uploadId}/ioc`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, 'IOC 내보내기 실패')
  return r.blob()
}

export interface CompareSession {
  session_id: string
  src_ip: string; dst_ip: string
  src_port: number; dst_port: number
  protocol: string
  start_ts: number; end_ts: number
  bytes_sent: number; bytes_recv: number
  packet_count: number
  rst: boolean
}

export interface CompareResult {
  new_ips: string[]
  removed_ips: string[]
  common_ips: string[]
  new_ports: number[]
  traffic_delta_pct: number | null
  protocol_diff: Record<string, { a: number; b: number }>
  byte_ratio: { a_total: number; b_total: number }
  base_sessions: CompareSession[]
  compare_sessions: CompareSession[]
  base_session_total: number
  compare_session_total: number
}

export async function compareCaptures(
  base_upload_id: string,
  current_upload_id: string,
  base_token?: string,
  current_token?: string,
): Promise<CompareResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (base_token) headers['X-Upload-Token-Base'] = base_token
  if (current_token) headers['X-Upload-Token-Current'] = current_token
  const r = await fetch(`${BASE}/api/compare`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ base_upload_id, current_upload_id }),
  })
  if (!r.ok) return handleError(r, '비교 분석 실패')
  return r.json()
}

export interface Annotation {
  upload_id: string
  start_ts: number
  end_ts: number
  comment: string
}

export async function getAnnotations(upload_id: string, capture_token?: string): Promise<Annotation[]> {
  const r = await fetch(`${BASE}/api/annotations/${upload_id}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '어노테이션 로드 실패')
  return r.json()
}

export interface SessionHealth {
  session_id: string
  src_ip: string; dst_ip: string
  src_port: number; dst_port: number
  protocol: string
  duration_s: number
  packet_count: number
  bytes_sent: number; bytes_recv: number
  rst?: boolean
  handshake: string       // COMPLETE | REFUSED | TIMEOUT | HALF_OPEN | N/A
  rtt_ms: number | null
  retransmit_count: number
  retransmit_rate: number
  rst_type: string        // NONE | EARLY | LATE
  close_type: string      // NORMAL | RESET | TIMEOUT | N/A
  score: number
  status: string          // 정상 | 주의 | 이상
  issues: string[]
  root_cause: string
  recommendations: string[]
  failure_type: string    // none | connection_refused | no_response | path_issue | slow_response
  icmp_label?: string     // path_issue 시 ICMP 레이블 (ttl_expired | host_unreachable | ...)
  icmp_src_ip?: string    // path_issue 시 ICMP 응답을 보낸 라우터 IP
}

export interface NetworkHealthData {
  total_sessions: number
  healthy: number
  warning: number
  critical: number
  overall_score: number
  top_issues: { issue: string; count: number }[]
  failure_summary: Record<string, number>
  sessions: SessionHealth[]
}

export async function getNetworkHealth(upload_id: string, capture_token?: string): Promise<NetworkHealthData> {
  const r = await fetch(`${BASE}/api/health/${upload_id}`, {
    headers: tokenHeader(capture_token),
  })
  if (!r.ok) return handleError(r, '통신 상태 진단 실패')
  return r.json()
}
