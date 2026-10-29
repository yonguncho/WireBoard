"""로컬 LLM 문단 초안 평가 — 모델/프롬프트를 바꿀 때마다 돌려 비교표를 본다.

지표
- 검증 통과율: 전체 문단 중 llm_guard 를 통과한 비율
- 문단당 생성 시간: 케이스당 생성 시간 / 2 문단
- 템플릿 대체 비율: 1 - 통과율 (모델 미응답·파싱 실패 포함)

실행 (WireBoard 루트에서, 로컬 Ollama 가 떠 있어야 함)
  python eval/llm_draft/run_eval.py --model hermes3:8b
  python eval/llm_draft/run_eval.py --model qwen2.5:7b --api ollama --url http://127.0.0.1:11434
  python eval/llm_draft/run_eval.py --table          # 기록된 실행들의 비교표만 출력
결과는 eval/llm_draft/results.jsonl 에 누적, 문단 원문은 runs/<시각>_<모델>.json 에 저장.
"""
import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "backend"))

from services.narrative.llm_draft import (  # noqa: E402
    PROMPT_VERSION, LlmConfig, LlmUnavailable, call_model, generate_draft,
)

RESULTS = HERE / "results.jsonl"


def run(cfg: LlmConfig) -> dict:
    cases = sorted((HERE / "cases").glob("*.json"))
    total = passed = errors = 0
    gen_ms = []
    detail = []
    reasons: dict[str, int] = {}
    for path in cases:
        case = json.loads(path.read_text(encoding="utf-8"))
        t0 = time.perf_counter()
        raw_holder = {}

        def recording_caller(c, facts):
            raw_holder["raw"] = call_model(c, facts)
            return raw_holder["raw"]

        try:
            draft = generate_draft(case["facts"], case["templates"], cfg, caller=recording_caller)
        except LlmUnavailable as exc:
            errors += 1
            total += 2
            detail.append({"case": case["name"], "error": str(exc)})
            print(f"  {case['name']:<36} ERROR {exc}")
            continue
        ms = draft["stats"]["gen_ms"]
        gen_ms.append(ms)
        total += 2
        passed += draft["stats"]["passed"]
        for p in draft["paragraphs"]:
            for v in p["violations"]:
                key = v.split(":")[0]
                reasons[key] = reasons.get(key, 0) + 1
        detail.append({"case": case["name"], "gen_ms": ms, "raw_output": raw_holder.get("raw"),
                       "paragraphs": draft["paragraphs"]})
        marks = " ".join("PASS" if p["source"] == "llm" else "FAIL" for p in draft["paragraphs"])
        print(f"  {case['name']:<36} {marks}  {ms / 1000:6.1f}s  ({time.perf_counter() - t0:.1f}s wall)")

    summary = {
        "at": datetime.now().isoformat(timespec="seconds"),
        "model": cfg.model, "api": cfg.api, "prompt_version": PROMPT_VERSION,
        "cases": len(cases), "paragraphs": total, "passed": passed,
        "pass_rate": round(passed / total, 3) if total else 0.0,
        "template_rate": round(1 - passed / total, 3) if total else 0.0,
        "sec_per_paragraph": round(sum(gen_ms) / 1000 / (2 * len(gen_ms)), 1) if gen_ms else None,
        "errors": errors, "violation_reasons": reasons,
    }
    runs = HERE / "runs"
    runs.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (runs / f"{stamp}_{cfg.model.replace(':', '_').replace('/', '_')}.json").write_text(
        json.dumps({"summary": summary, "detail": detail}, indent=2, ensure_ascii=False), encoding="utf-8")
    with RESULTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")
    return summary


def rescore(run_file: Path) -> None:
    """저장된 모델 원문을 현재 검사기로 다시 채점 (모델 호출 없음) — 검사 규칙을 바꿨을 때 비교용."""
    data = json.loads(run_file.read_text(encoding="utf-8"))
    cases = {json.loads(p.read_text(encoding="utf-8"))["name"]: json.loads(p.read_text(encoding="utf-8"))
             for p in (HERE / "cases").glob("*.json")}
    cfg = LlmConfig(True, "replay", "", data["summary"]["model"], 0)
    total = passed = 0
    for d in data["detail"]:
        if not d.get("raw_output"):
            print(f"  {d['case']:<36} (원문 없음 — 건너뜀)")
            continue
        draft = generate_draft(cases[d["case"]]["facts"], cases[d["case"]]["templates"], cfg,
                               caller=lambda c, f, raw=d["raw_output"]: raw)
        total += 2
        passed += draft["stats"]["passed"]
        for p in draft["paragraphs"]:
            mark = "PASS" if p["source"] == "llm" else "FAIL " + " | ".join(p["violations"])
            print(f"  {d['case']:<36} {p['slot']:<20} {mark}")
    if total:
        print(f"rescore: {passed}/{total} 통과 ({passed / total:.0%}) — 저장 당시 {data['summary']['pass_rate']:.0%}")


def table() -> None:
    if not RESULTS.exists():
        print("no runs recorded yet")
        return
    rows = [json.loads(l) for l in RESULTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"\n{'when':<20} {'model':<22} {'prompt':<7} {'pass':>6} {'templ':>6} {'s/para':>7} {'err':>4}  top violation")
    for r in rows:
        top = max(r["violation_reasons"].items(), key=lambda kv: kv[1])[0] if r["violation_reasons"] else "-"
        spp = f"{r['sec_per_paragraph']:.1f}" if r["sec_per_paragraph"] is not None else "-"
        print(f"{r['at']:<20} {r['model']:<22} {r['prompt_version']:<7} {r['pass_rate']:>6.0%} "
              f"{r['template_rate']:>6.0%} {spp:>7} {r['errors']:>4}  {top}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--api", default="ollama", choices=["ollama", "openai"])
    ap.add_argument("--url")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--rescore", type=Path, help="runs/*.json 의 원문을 현재 검사기로 재채점")
    a = ap.parse_args()
    if a.rescore:
        rescore(a.rescore)
        return
    if a.table or not a.model:
        table()
        return
    url = a.url or ("http://127.0.0.1:8080" if a.api == "openai" else "http://127.0.0.1:11434")
    cfg = LlmConfig(True, a.api, url.rstrip("/"), a.model, a.timeout)
    print(f"eval model={cfg.model} api={cfg.api} prompt={PROMPT_VERSION}")
    s = run(cfg)
    print(json.dumps(s, indent=2, ensure_ascii=False))
    table()


if __name__ == "__main__":
    main()
