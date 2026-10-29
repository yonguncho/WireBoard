"""sniffer2pcap 브라우저 E2E (Playwright, 수동 실행: python tools/e2e_sniffer2pcap_browser.py): 정적 서버로 페이지를 띄우고 실제 파일 업로드→다운로드, 대용량, 네트워크 0건 확인."""
import functools
import http.server
import json
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "web" / "sniffer2pcap"
HERE = Path(tempfile.mkdtemp(prefix="s2p_e2e_"))  # 산출물(스크린샷·대용량 입력)은 임시 폴더
CASES = ROOT / "tests" / "fixtures" / "sniffer2pcap"

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(TOOL))
http.server.SimpleHTTPRequestHandler.extensions_map[".js"] = "text/javascript"
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8791), handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# 대용량 입력: v6_abs 패킷 블록을 반복해 ~40MB 생성
big = HERE / "big_v6.txt"
if not big.exists():
    src = (CASES / "v6_abs.txt").read_text(encoding="utf-8").splitlines()
    body = [l for l in src if l and not l.startswith(("FGT", "interfaces", "filters")) and "packets" not in l]
    with big.open("w", encoding="utf-8", newline="\n") as f:
        f.write(src[0] + "\n")
        size = 0
        while size < 40 * 1024 * 1024:
            chunk = "\n".join(body) + "\n"
            f.write(chunk)
            size += len(chunk)

results = {}
with sync_playwright() as p:
    browser = p.chromium.launch()
    for width in (1280, 375):
        page = browser.new_page(viewport={"width": width, "height": 900}, accept_downloads=True)
        requests, console = [], []
        page.on("request", lambda r: requests.append(r.url))
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
        page.goto("http://127.0.0.1:8791/index.html")
        page.wait_for_load_state("networkidle")
        boot = len(requests)

        page.set_input_files("#file", str(CASES / "noisy_terminal_log.txt"))
        page.wait_for_selector("#results:not([hidden])", timeout=20000)
        status = page.inner_text("#status")
        links = page.eval_on_selector_all("#downloads a", "els => els.map(e => e.getAttribute('download'))")
        with page.expect_download() as dl:
            page.click("#downloads a >> nth=0")
        path = HERE / f"dl_{width}.pcap"
        dl.value.save_as(path)
        data = path.read_bytes()
        n, o = 0, 24
        while o < len(data):
            cap = struct.unpack_from("<I", data, o + 8)[0]
            o += 16 + cap
            n += 1
        summary_rows = page.inner_text("#summary-body")
        page.screenshot(path=str(HERE / f"shot_{width}.png"), full_page=True)
        overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")

        # 비-hex 로그 → 안내 메시지
        page.set_input_files("#file", str(CASES / "v4_headers_only.txt"))
        page.wait_for_selector("#status.error", timeout=20000)
        v4_msg = page.inner_text("#status")

        res = {
            "status": status, "links": links, "pcap_packets": n, "summary": summary_rows,
            "v4_message": v4_msg, "horizontal_overflow": overflow,
            "requests_after_load": requests[boot:], "console": [c for c in console if not c.startswith("log")],
        }
        if width == 1280:
            t0 = time.time()
            page.set_input_files("#file", str(big))
            page.wait_for_selector("#status.working", timeout=10000)
            # 변환 중에도 메인 스레드가 반응하는지 (Worker 가 일을 가져갔는지)
            lat = []
            while not page.query_selector("#status.ok"):
                t1 = time.time()
                page.evaluate("1+1")
                lat.append((time.time() - t1) * 1000)
                time.sleep(0.2)
                if time.time() - t0 > 180:
                    break
            res["main_thread_max_response_ms"] = round(max(lat)) if lat else None
            res["main_thread_samples"] = len(lat)
            res["big_file_mb"] = round(big.stat().st_size / 1048576, 1)
            res["big_seconds"] = round(time.time() - t0, 1)
            res["big_status"] = page.inner_text("#status")
            res["requests_total_after_load"] = requests[boot:]
        results[width] = res
        page.close()
    browser.close()
srv.shutdown()
print(json.dumps(results, indent=2, ensure_ascii=False))
