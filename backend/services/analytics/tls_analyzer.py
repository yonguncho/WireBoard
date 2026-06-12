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


class TlsAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> TlsAnalysisResult:
        sni_counts: dict[str, int] = defaultdict(int)
        ja4_set: set[str] = set()
        version_counts: dict[str, int] = defaultdict(int)
        cert_cns: list[str] = []
        entries: list[dict] = []
        seen_entries: set[tuple] = set()
        port443_no_meta = 0

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
            if sni or ver:
                key = (sni or "", ver or "", s.dst_ip)
                if key not in seen_entries:
                    seen_entries.add(key)
                    entries.append({"sni": sni or "", "version": ver or "", "dst_ip": s.dst_ip})

        return TlsAnalysisResult(
            sni_counts=dict(sni_counts),
            ja4_fingerprints=sorted(ja4_set),
            tls_versions=dict(version_counts),
            cert_cns=cert_cns,
            entries=entries,
            port443_no_meta=port443_no_meta,
        )
