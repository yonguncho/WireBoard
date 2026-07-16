"""TlsEnricher — 파싱 직후 세션 meta에 TLS ClientHello(SNI) + 핸드셰이크 결과 주입.

업로드 시점에 1회 실행되어 Panel 7(TLS)·필터(tls)가 세션 상세 조회 없이
"어느 도메인으로 접속을 시도했고, TLS 세션이 정상 수립됐는지"를 집계할 수 있게 한다.

meta 주입 키:
  tls_sni          : ClientHello SNI (접속 시도 도메인)
  ja4              : 간소화 JA4 클라이언트 지문
  tls_version      : 협상 버전(없으면 ClientHello legacy 버전)
  tls_handshake    : "complete" | "failed" | "incomplete"
  tls_fail_reason  : failed 사유 — "fatal_alert:<desc>" | "rst_after_client_hello"
                     | "no_server_response" (failed일 때만)
"""
import logging

from services.payload_extractor.tls_extractor import TLSExtractor, scan_tls_records

logger = logging.getLogger(__name__)

# 방향별 재조립 상한 — 초기 핸드셰이크 레코드는 앞쪽에 위치 (flow.py와 동일)
_REASSEMBLY_CAP = 8192


def _reassemble(pkts, direction: str, cap: int = _REASSEMBLY_CAP) -> bytes:
    """한 방향(fwd/rev) payload를 시간순으로 이어붙여 TLS 레코드 재조립."""
    buf = bytearray()
    for p in pkts:
        if p.direction == direction and p.payload_hex:
            try:
                buf.extend(bytes.fromhex(p.payload_hex))
            except ValueError:
                continue
            if len(buf) >= cap:
                break
    return bytes(buf)


class TlsEnricher:
    def __init__(self) -> None:
        self._extractor = TLSExtractor()

    def enrich(self, sessions, packet_map: dict[str, list]) -> None:
        """TCP 세션에서 ClientHello를 찾아 meta를 채운다 (in-place, 멱등)."""
        for s in sessions:
            try:
                self._enrich_one(s, packet_map.get(s.session_id) or [])
            except Exception as exc:  # 개별 세션 실패가 업로드를 막지 않는다
                logger.debug("TLS enrich 실패 session=%s: %s", s.session_id, exc)

    def _enrich_one(self, s, pkts: list) -> None:
        if s.protocol != "TCP" or not pkts:
            return

        fwd = _reassemble(pkts, "fwd")
        rev = _reassemble(pkts, "rev")

        # ClientHello 방향 결정 — 보통 fwd(개시자)지만 중간 캡처는 뒤집힐 수 있음
        client, server = fwd, rev
        ch = self._extractor.extract(client)
        if not (ch.sni or ch.cipher_suites):
            ch_rev = self._extractor.extract(rev)
            if ch_rev.sni or ch_rev.cipher_suites:
                client, server = rev, fwd
                ch = ch_rev
            else:
                return  # ClientHello 없음 — TLS 세션 아님(또는 캡처에 미포함)

        meta = dict(s.meta or {})
        if ch.sni:
            meta["tls_sni"] = ch.sni
        if ch.ja4:
            meta["ja4"] = ch.ja4

        sh_cipher, sh_version = self._extractor.extract_server_hello(server)
        version = ch.negotiated_version or sh_version or ch.legacy_version
        if version:
            meta["tls_version"] = version

        # 핸드셰이크 단계·Alert 수집 (양방향) → 수립/실패 판정
        c_scan = scan_tls_records(client)
        s_scan = scan_tls_records(server)
        stages = c_scan["handshake"] + [h for h in s_scan["handshake"] if h not in c_scan["handshake"]]
        alerts = c_scan["alerts"] + s_scan["alerts"]

        fatal = next((a for a in alerts if a["level"] == "fatal"), None)
        # TLS 1.3은 ServerHello 이후 암호화되어 Finished가 안 보임 → ServerHello+cipher면 수립
        completed = "Finished" in stages or ("ServerHello" in stages and sh_cipher is not None)

        if fatal:
            status: str = "failed"
            reason: str | None = f"fatal_alert:{fatal['description']}"
        elif completed:
            status, reason = "complete", None
        elif "ServerHello" not in stages:
            # ClientHello를 보냈는데 서버 ServerHello가 없음 — 세션 미수립
            status = "failed"
            reason = "rst_after_client_hello" if s.rst else "no_server_response"
        else:
            # ServerHello는 있으나 완료 확증 없음 (캡처 절단 등) — 단정하지 않는다
            status, reason = "incomplete", None

        meta["tls_handshake"] = status
        if reason:
            meta["tls_fail_reason"] = reason
        else:
            meta.pop("tls_fail_reason", None)  # 멱등: 재실행 시 이전 사유 제거
        s.meta = meta
