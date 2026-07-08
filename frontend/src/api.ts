const BASE = ''

async function handleError(r: Response, label: string): Promise<never> {
  let msg = `${label} (${r.status})`
  try {
    const body = await r.json()
    const d = body.detail
    if (d?.message) msg = d.message
    else if (d?.msg) msg = d.msg
    else if (typeof d === 'string') msg = d
    if (d?.errors?.length) msg += '\n' + (d.errors as string[]).slice(0, 3).join('\n')
  } catch { /* ignore */ }
  throw new Error(msg)
}

const TOKEN_STORE_KEY = 'wb_capture_tokens'

function loadTokens(): Map<string, string> {
  try {
    const raw = sessionStorage.getItem(TOKEN_STORE_KEY)
    if (raw) return new Map(Object.entries(JSON.parse(raw) as Record<string, string>))
  } catch { /* ignore */ }
  return new Map()
}

const _tokens = loadTokens()

function persistTokens() {
  try {
    sessionStorage.setItem(TOKEN_STORE_KEY, JSON.stringify(Object.fromEntries(_tokens)))
  } catch { /* ignore */ }
}

export function setCaptureToken(upload_id: string, token: string) {
  _tokens.set(upload_id, token)
  persistTokens()
}

export function getCaptureToken(upload_id: string): string | undefined {
  return _tokens.get(upload_id)
}

function tokenHeader(upload_id?: string, override?: string): Record<string, string> {
  const token = override ?? (upload_id ? _tokens.get(upload_id) : undefined)
  return token ? { 'X-Upload-Token': token } : {}
}

export async function uploadPcap(file: File): Promise<{ upload_id: string; capture_token: string; session_count: number; source_type: string; parse_warnings: string[]; pcap_available?: boolean }> {
  const fd = new FormData()
  fd.append('file', file)
  const r = await fetch(`${BASE}/api/upload`, { method: 'POST', body: fd })
  if (!r.ok) return handleError(r, 'Unrecognized file format')
  const data = await r.json()
  if (data.upload_id && data.capture_token) setCaptureToken(data.upload_id, data.capture_token)
  return data
}

// ── Live capture (optional — requires Npcap + admin) ───────────────────────────
export interface CaptureIface { name: string; description: string; ip: string | null; mac: string | null; has_ip: boolean }
export interface CaptureCapability { available: boolean; message: string; admin_note: string }
export interface CaptureStatus {
  capture_id: string; running: boolean; stopped: boolean
  packet_count: number; elapsed: number; max_packets: number; max_seconds: number; bpf: string
}
export interface CaptureResult {
  upload_id: string; capture_token: string; source_type: string
  session_count: number; packet_count: number; parse_warnings: string[]; pcap_available: boolean
}
export interface CaptureStartBody {
  iface: string; src?: string; dst?: string; port?: number; host?: string
  max_packets?: number; max_seconds?: number
}

export async function getCaptureCapability(): Promise<CaptureCapability> {
  const r = await fetch(`${BASE}/api/capture/capability`)
  if (!r.ok) return handleError(r, 'Capability check failed')
  return r.json()
}
export async function getCaptureInterfaces(): Promise<CaptureIface[]> {
  const r = await fetch(`${BASE}/api/capture/interfaces`)
  if (!r.ok) return handleError(r, 'Interface list failed')
  return (await r.json()).interfaces
}
export async function startCapture(body: CaptureStartBody): Promise<{ capture_id: string; bpf: string; max_packets: number; max_seconds: number }> {
  const r = await fetch(`${BASE}/api/capture/start`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (!r.ok) return handleError(r, 'Capture start failed')
  return r.json()
}
export async function getCaptureStatus(id: string): Promise<CaptureStatus> {
  const r = await fetch(`${BASE}/api/capture/${id}/status`)
  if (!r.ok) return handleError(r, 'Capture status failed')
  return r.json()
}
export async function stopCapture(id: string): Promise<CaptureResult> {
  const r = await fetch(`${BASE}/api/capture/${id}/stop`, { method: 'POST' })
  if (!r.ok) return handleError(r, 'Capture stop failed')
  const data = await r.json()
  if (data.upload_id && data.capture_token) setCaptureToken(data.upload_id, data.capture_token)
  return data
}

export async function analyzePcap(upload_id: string, target_ip?: string, capture_token?: string): Promise<Record<string, unknown>> {
  const body: Record<string, string> = { upload_id }
  if (target_ip) body.target_ip = target_ip
  const r = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(upload_id, capture_token) },
    body: JSON.stringify(body),
  })
  if (!r.ok) return handleError(r, 'Analysis failed')
  return r.json()
}

export async function getPanels(upload_id: string, capture_token?: string): Promise<PanelData> {
  const r = await fetch(`${BASE}/api/panels/${upload_id}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load panels')
  return r.json()
}

export async function addAnnotation(upload_id: string, start_ts: number, end_ts: number, comment: string, capture_token?: string) {
  const r = await fetch(`${BASE}/api/annotations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(upload_id, capture_token) },
    body: JSON.stringify({ upload_id, start_ts, end_ts, comment }),
  })
  if (!r.ok) return handleError(r, 'Failed to save marker')
  return r.json()
}

export async function getDrilldown(upload_id: string, ip: string, capture_token?: string, peer?: string): Promise<DrilldownResult> {
  const q = new URLSearchParams({ ip })
  if (peer) q.set('peer', peer)
  const r = await fetch(`${BASE}/api/drilldown/${upload_id}?${q.toString()}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Drilldown failed')
  return r.json()
}

export async function filterSessions(upload_id: string, query: string, capture_token?: string) {
  const r = await fetch(`${BASE}/api/filter`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokenHeader(upload_id, capture_token) },
    body: JSON.stringify({ upload_id, query }),
  })
  if (!r.ok) return handleError(r, 'Filter failed')
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
  expert_info?: ExpertInfo
  dns_timing?: DnsTiming
  app_protocols?: Record<string, number>
  quic_sni_hosts?: { sni: string; dst: string; version: string }[]
}

export interface IpEntry { ip: string; bytes: number; is_private?: boolean }
export interface PortEntry { port: number; count: number }
export interface BucketEntry { ts: number; bytes: number; count?: number; rst?: number; no_reply?: number; errors?: number }
export interface ErrorEntry { status_code: number; count: number; path?: string }
export interface IpRankEntry { ip: string; bytes: number; is_internal: boolean }
export interface TlsEntry { sni: string; version: string; dst_ip: string }
export interface DnsEntry { domain: string; type: string; response?: string; nxdomain: boolean }

export interface DnsPair {
  name: string; type: string; rcode: string | null
  response_time_ms: number | null; answered: boolean; answers: string[]
}
export interface DnsTiming {
  total: number; answered: number; unanswered: number; errors: number
  rcode_dist: Record<string, number>
  avg_ms: number; p50_ms: number; p95_ms: number; max_ms: number
  slowest: DnsPair[]; unanswered_queries: DnsPair[]
}
export interface ConvEntry {
  src: string; dst: string; packets: number; bytes: number; duration_s: number
  sessions?: number; rst?: number; no_reply?: number; issue_rate?: number
}
export interface AttackEntry { attack_type: string; severity: string; mitre_id: string; description: string; src_ip?: string }

export async function getSummary(upload_id: string, capture_token?: string): Promise<SummaryData> {
  const r = await fetch(`${BASE}/api/summary/${upload_id}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load summary')
  return r.json()
}

export interface RiskFactor {
  factor: string
  detail: string
  points: number
}

export interface SummaryData {
  headline: string
  narrative: string
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN'
  risk_score?: number
  risk_factors?: RiskFactor[]
  diagnosis?: string[]
  key_findings?: string[]
  health_overview?: Record<string, unknown>
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
export interface DrilldownResult { ip: string; session_count: number; sessions: DrilldownSession[]; truncated: boolean }

export interface FlowPacket {
  ts: number; rel_ts: number; delta_ts?: number; direction: 'fwd' | 'rev'
  proto: string; seq: number; ack: number; flags: string
  length: number; payload_len: number; payload_hex: string
  window?: number; window_scaled?: number; ttl?: number
  expert?: string[]; expert_top?: string
}
export interface IpBadge { ttl: number; assumed_initial: number; estimated_hops: number }
export interface WScale { fwd: number; rev: number; fwd_factor: number; rev_factor: number }
export interface L2Info { src_mac: string; dst_mac: string; src_vendor: string | null; dst_vendor: string | null }
export interface FlowSession {
  session_id: string; src_ip: string; dst_ip: string
  src_port: number; dst_port: number; protocol: string
  packet_count: number; bytes_sent: number; bytes_recv: number
  start_ts: number; end_ts: number; duration_s: number; rst: boolean
  ip_badge?: IpBadge | null
  wscale?: WScale
  l2?: L2Info | null
  app_proto?: string | null
  quic_sni?: string | null
  quic_type?: string | null
}
export interface TlsAlert { level: string; description: string; code: number; from: string }
export interface TlsInfo {
  sni: string | null
  alpn: string | null
  ja4: string | null
  client_version: string | null
  negotiated_version: string | null
  chosen_cipher: string | null
  offered_ciphers: string[]
  offered_cipher_count: number
  handshake_stages?: string[]
  alerts?: TlsAlert[]
  handshake_complete?: boolean
}
export interface FlowData {
  session: FlowSession
  packets: FlowPacket[]
  packet_count: number
  truncated: boolean
  tls?: TlsInfo | null
  expert_summary?: Record<string, number>
  expert_worst?: string
}

export interface ExpertInfoItem { tag: string; count: number; description: string }
export interface ExpertInfo {
  totals: Record<string, number>
  by_severity: { error: ExpertInfoItem[]; warn: ExpertInfoItem[]; note: ExpertInfoItem[]; chat: ExpertInfoItem[] }
  flows_with_issues: number
  retransmission: number
  duplicate_ack: number
  zero_window: number
  out_of_order: number
  lost_segment: number
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
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load stream')
  return r.json()
}

export async function getFlow(upload_id: string, session_id: string, capture_token?: string): Promise<FlowData> {
  const r = await fetch(`${BASE}/api/flow/${upload_id}?session_id=${encodeURIComponent(session_id)}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load flow')
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
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load packet list')
  return r.json()
}

export async function exportJson(upload_id: string, capture_token?: string): Promise<void> {
  const r = await fetch(`${BASE}/api/export/${upload_id}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'JSON export failed')
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
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'PDF export failed')
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `wireboard_${upload_id.slice(0, 8)}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

export async function downloadConvertedPcap(upload_id: string, capture_token?: string): Promise<void> {
  const r = await fetch(`${BASE}/api/upload/${upload_id}/pcap`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'PCAP download failed')
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `converted_${upload_id.slice(0, 8)}.pcap`
  a.click()
  URL.revokeObjectURL(url)
}

export async function exportIoc(uploadId: string, capture_token?: string): Promise<Blob> {
  const r = await fetch(`${BASE}/api/export/${uploadId}/ioc`, {
    headers: tokenHeader(uploadId, capture_token),
  })
  if (!r.ok) return handleError(r, 'IOC export failed')
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

export interface ConversationDiff {
  key: string
  ip_a: string; ip_b: string
  port: number; protocol: string
  a_sessions: number; a_packets: number; a_bytes: number
  b_sessions: number; b_packets: number; b_bytes: number
  byte_delta: number
  status: 'both' | 'only_a' | 'only_b'
  change_type?: string
  a_fail?: number
  b_fail?: number
}

export interface CompareVerdict {
  verdict: 'SIMILAR' | 'DEGRADED' | 'IMPROVED' | 'DIFFERENT'
  headline: string
  traffic_delta_pct: number | null
  counts: Record<string, number>
  newly_failing: number
  recovered: number
  top_changes: ConversationDiff[]
}

export interface ConversationSummary {
  total: number
  both: number
  only_base: number
  only_compare: number
  changed: number
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
  conversations: ConversationDiff[]
  conversation_summary: ConversationSummary
  conversation_total: number
  verdict?: CompareVerdict
}

export async function compareCaptures(
  base_upload_id: string,
  current_upload_id: string,
  base_token?: string,
  current_token?: string,
): Promise<CompareResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const bt = base_token ?? _tokens.get(base_upload_id)
  const ct = current_token ?? _tokens.get(current_upload_id)
  if (bt) headers['X-Upload-Token-Base'] = bt
  if (ct) headers['X-Upload-Token-Current'] = ct
  const r = await fetch(`${BASE}/api/compare`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ base_upload_id, current_upload_id }),
  })
  if (!r.ok) return handleError(r, 'Comparison analysis failed')
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
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load annotations')
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
  status: string          // Healthy | Warning | Critical
  issues: string[]
  root_cause: string
  recommendations: string[]
  failure_type: string    // none | connection_refused | no_response | path_issue | slow_response
  icmp_label?: string     // ICMP label on path_issue (ttl_expired | host_unreachable | ...)
  icmp_src_ip?: string    // Router IP that sent the ICMP response on path_issue
  server_delay_ms?: number | null  // first request payload → first response payload
  bottleneck?: string     // none | network | server | application | indeterminate
}

export interface HealthVerdict {
  side: 'network' | 'application' | 'server' | 'none'
  headline: string
  counts: Record<string, number>
}

export interface CaptureQuality {
  tcp_sessions_with_packets: number
  handshake_not_captured: number
  packetless_sessions: number
  truncated_flows: number
  warnings: string[]
}

export interface NetworkHealthData {
  total_sessions: number
  healthy: number
  warning: number
  critical: number
  overall_score: number
  top_issues: { issue: string; count: number }[]
  failure_summary: Record<string, number>
  verdict?: HealthVerdict
  capture_quality?: CaptureQuality
  sessions: SessionHealth[]
}

export async function getNetworkHealth(upload_id: string, capture_token?: string): Promise<NetworkHealthData> {
  const r = await fetch(`${BASE}/api/health/${upload_id}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Connection health diagnostics failed')
  return r.json()
}

export interface HarTimings {
  blocked: number; dns: number; ssl: number; connect: number
  send: number; wait: number; receive: number
}
export interface HarEntry {
  session_id: string
  method: string; url: string; host: string
  status: number; mime: string
  start_offset_ms: number; total_ms: number; resp_size: number
  timings: HarTimings
}
export interface HarData {
  source_type: string
  count: number
  entries: HarEntry[]
  summary: {
    count: number; total_bytes: number; total_time_ms: number
    status_groups: Record<string, number>
    slowest: { url: string; host: string; total_ms: number; status: number }[]
  }
}

export async function getHar(upload_id: string, capture_token?: string): Promise<HarData> {
  const r = await fetch(`${BASE}/api/har/${upload_id}`, {
    headers: tokenHeader(upload_id, capture_token),
  })
  if (!r.ok) return handleError(r, 'Failed to load HAR analysis')
  return r.json()
}
