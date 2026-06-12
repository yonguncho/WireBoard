export interface FlowModel {
  fid: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: "TCP" | "UDP" | "ICMP" | "DNS" | "OTHER";
  start_ts: number;
  end_ts: number;
  bytes_total: number;
  packet_count: number;
  direction: "inbound" | "outbound" | "internal";
}

export interface SessionModel {
  session_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: "TCP" | "UDP" | "ICMP" | "DNS" | "OTHER";
  start_ts: number;
  end_ts: number;
  bytes_total: number;
  packet_count: number;
  confidence: "high" | "medium" | "low";
  source_type: "pcap" | "har" | "fortigate" | "tcpdump";
  note: string | null;
}

export interface AttackDetectionResult {
  attack_type: "DoS" | "DDoS" | "Beacon" | "PortScan" | "DataExfiltration" | "CommFailure";
  confidence: "high" | "medium" | "low";
  evidence: string[];
  mitre_id: string | null;
  mitre_name: string | null;
  sample_count: number;
}

export interface ReputationSourceResult {
  source: string;
  is_malicious: boolean;
  country_code: string | null;
  asn: string | null;
  org: string | null;
  is_risky_asn: boolean;
  note: string | null;
}

export interface ReputationResult {
  ip: string;
  is_malicious: boolean;
  sources: ReputationSourceResult[];
}

export interface UploadResponse {
  upload_id: string;
  source_type: string;
  session_count: number;
  parse_warnings: string[];
}

export interface AnalyzeRequest {
  upload_id: string;
  target_ip: string;
}

export interface AnalyzeResponse {
  target_ip: string;
  flows: FlowModel[];
  sessions: SessionModel[];
  reputation: Partial<ReputationResult>;
  attacks: AttackDetectionResult[];
  analysis_duration_ms: number;
}

export interface FilterTranslateRequest {
  query: string;
}

export interface FilterTranslateResponse {
  wireshark_filter: string | null;
  condition_filter: string | null;
  success: boolean;
  note: string | null;
}

export interface ExportRequest {
  upload_id: string;
  target_ip: string;
  format: "csv" | "excel" | "json" | "pdf" | "suricata" | "snort";
}
