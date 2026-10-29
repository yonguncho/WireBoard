"""(수동 실행: python tools/e2e_llm_draft_http.py) 가짜 Ollama(/api/chat) 서버로 HTTP 경로 → /ai-draft API → PDF 까지 실측."""
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "tests" / "fixtures" / "sniffer2pcap" / "v6_abs.txt"
seen = []


class Fake(BaseHTTPRequestHandler):
    reply = None

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        seen.append(body)
        facts = body["messages"][1]["content"]
        content = json.dumps(Fake.reply)
        out = json.dumps({"message": {"role": "assistant", "content": content}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 11555), Fake)
threading.Thread(target=srv.serve_forever, daemon=True).start()

os.environ.update(WIREBOARD_LLM_ENABLED="1", WIREBOARD_LLM_URL="http://127.0.0.1:11555", WIREBOARD_LLM_MODEL="fake:1b")
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT / "backend")
from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

c = TestClient(main.app)
up = c.post("/api/upload", files={"file": ("fw.log", io.BytesIO(CASE.read_bytes()), "text/plain")}).json()
uid, tok = up["upload_id"], up["capture_token"]
H = {"X-Upload-Token": tok}
summ = c.get(f"/api/summary/{uid}", headers=H).json()
print("summary headline:", summ["headline"])

# 1차: 사실 JSON 에서 값만 베낀 정상 응답
facts = None
Fake.reply = {"executive_summary": {"text": "PLACEHOLDER", "finding_ids": ["S1"]},
              "incident_narrative": {"text": "PLACEHOLDER", "finding_ids": ["S1"]}}
r0 = c.get(f"/api/summary/{uid}/ai-draft", headers=H).json()
facts = json.loads(seen[-1]["messages"][1]["content"].split("\n", 1)[1])
s = facts["stats"]
p1 = facts["top_talkers"][0]
Fake.reply = {
    "executive_summary": {"text": f"The capture contains {s['sessions']} sessions and {s['total_traffic']} of traffic; "
                                  f"the overall risk level is {s['risk_level']}. No attack finding is present, so routine review is enough.",
                          "finding_ids": ["S1"]},
    "incident_narrative": {"text": f"The largest flow was from {p1['source']} to {p1['destination']} ({p1['traffic']}), "
                                   f"which may simply be normal application traffic.", "finding_ids": ["P1"]},
}
from services.narrative import llm_draft  # noqa: E402
llm_draft._CACHE.clear()
r1 = c.get(f"/api/summary/{uid}/ai-draft", headers=H).json()
print("first call (placeholder) sources:", [p["source"] for p in r0["paragraphs"]], r0["paragraphs"][0]["violations"])
print("grounded call:", json.dumps({k: r1[k] for k in ("available", "label", "model", "stats")}))
print("  sources:", [p["source"] for p in r1["paragraphs"]], [p["violations"] for p in r1["paragraphs"]])
print("  request used format schema:", isinstance(seen[-1].get("format"), dict), "stream:", seen[-1]["stream"])
print("  raw packets in prompt?:", "0x0000" in seen[-1]["messages"][1]["content"])

pdf = c.post(f"/api/export/{uid}/pdf", headers=H)
txt = pdf.content.decode("latin-1")
print("pdf status:", pdf.status_code, "has AI summary block:", "AI-generated draft - review required" in txt)

# 2차: 환각 응답 → 템플릿 대체, PDF 에서 블록 사라짐
Fake.reply["incident_narrative"]["text"] = f"{p1['source']} definitely exfiltrated 9.9 GB to 203.0.113.250."
Fake.reply["executive_summary"]["text"] += " Technique T1048 was used."
llm_draft._CACHE.clear()
r2 = c.get(f"/api/summary/{uid}/ai-draft", headers=H).json()
print("hallucinated call:", r2["stats"], [p["violations"] for p in r2["paragraphs"]])
pdf2 = c.post(f"/api/export/{uid}/pdf", headers=H).content.decode("latin-1")
print("pdf2 has AI block:", "AI-generated draft" in pdf2)

# 3차: 서버 꺼짐 → available False, PDF 정상
srv.shutdown()
srv.server_close()
llm_draft._CACHE.clear()
r3 = c.get(f"/api/summary/{uid}/ai-draft", headers=H).json()
pdf3 = c.post(f"/api/export/{uid}/pdf", headers=H)
print("model down:", r3, "pdf:", pdf3.status_code, "AI block:", "AI-generated" in pdf3.content.decode("latin-1"))
