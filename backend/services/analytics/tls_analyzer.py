"""TlsAnalyzer — Panel 7: TLS 핸드셰이크 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel


@dataclass
class TlsAnalysisResult:
    sni_counts: dict = field(default_factory=dict)
    ja4_fingerprints: list = field(default_factory=list)
    tls_versions: dict = field(default_factory=dict)
    cert_cns: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    port443_no_meta: int = 0  # TLS 메타데이터 없는 포트 443 세션 수
    handshake_ok: int = 0     # 핸드셰이크 수립 세션 수
    handshake_fail: int = 0   # 핸드셰이크 실패 세션 수 (alert/RST/무응답)


class TlsAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> TlsAnalysisResult:
        sni_counts: dict[str, int] = defaultdict(int)
        ja4_set: set[str] = set()
        version_counts: dict[str, int] = defaultdict(int)
        cert_cns: list[str] = []
        # (sni, version, dst_ip, handshake, fail_reason) → 세션 수 집계
        entry_counts: dict[tuple, int] = defaultdict(int)
        port443_no_meta = 0
        handshake_ok = 0
        handshake_fail = 0

        for s in sessions:
            # 포트 443 세션 중 TLS 메타데이터 없는 것 집계
            is_443 = s.dst_port == 443 or s.src_port == 443
            has_tls_meta = bool(s.meta and (s.meta.get("tls_sni") or s.meta.get("tls_version")))
            if is_443 and not has_tls_meta:
                port443_no_meta += 1

            if not s.meta:
                continue
            sni = s.meta.get("tls_sni")
            if sni:
                sni_counts[sni] += 1
            ja4 = s.meta.get("ja4")
            if ja4:
                ja4_set.add(ja4)
            ver = s.meta.get("tls_version")
            if ver:
                version_counts[ver] += 1
            cn = s.meta.get("cert_cn")
            if cn and cn not in cert_cns:
                cert_cns.append(cn)

            handshake = s.meta.get("tls_handshake") or ""
            if handshake == "complete":
                handshake_ok += 1
            elif handshake == "failed":
                handshake_fail += 1

            if sni or ver:
                key = (sni or "", ver or "", s.dst_ip, handshake,
                       s.meta.get("tls_fail_reason") or "")
                entry_counts[key] += 1

        # 실패 우선 → 세션 수 내림차순 (장애 트리아지: 안 맺어진 접속이 먼저 보이게)
        _status_rank = {"failed": 0, "incomplete": 1, "": 2, "complete": 3}
        entries = [
            {"sni": k[0], "version": k[1], "dst_ip": k[2],
             "handshake": k[3], "fail_reason": k[4], "count": c}
            for k, c in entry_counts.items()
        ]
        entries.sort(key=lambda e: (_status_rank.get(e["handshake"], 2), -e["count"], e["sni"]))

        return TlsAnalysisResult(
            sni_counts=dict(sni_counts),
            ja4_fingerprints=sorted(ja4_set),
            tls_versions=dict(version_counts),
            cert_cns=cert_cns,
            entries=entries,
            port443_no_meta=port443_no_meta,
            handshake_ok=handshake_ok,
            handshake_fail=handshake_fail,
        )
