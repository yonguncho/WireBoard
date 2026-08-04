# -*- coding: utf-8 -*-
"""Traffic 탭 레이아웃 실측 — 카드 폭이 화면을 다 쓰는지 브라우저에서 직접 잰다.

추측으로 CSS 를 고치지 않기 위한 측정 도구. 각 카드의 실제 렌더 폭과
grid-template-columns 계산값, 테이블 가로 스크롤(잘림) 여부를 출력한다.
"""
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

PCAP = r"C:\AI_WORKPLACE\WireBoard\tools\wireboard_showcase.pcap"
BASE = "http://127.0.0.1:8764/"
OUT = Path(r"C:\AI_WORKPLACE\WireBoard\tools\_layout_shots")
OUT.mkdir(parents=True, exist_ok=True)
WIDTH = int(sys.argv[1]) if len(sys.argv) > 1 else 1920
TAB = sys.argv[2] if len(sys.argv) > 2 else "Traffic"


def wait_analyzed(pg, timeout=90):
    for _ in range(timeout):
        time.sleep(1)
        try:
            t = pg.inner_text("body")
        except Exception:
            continue
        if "Overview" in t and "Investigate" in t:
            return True
    return False


with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": WIDTH, "height": 1100})
    pg.goto(BASE, wait_until="networkidle", timeout=25000)
    time.sleep(1)
    pg.set_input_files("input[type=file]", PCAP)
    if not wait_analyzed(pg):
        print("!! analysis timeout")
        b.close()
        sys.exit(1)
    time.sleep(3)

    pg.click("button.layer-btn >> text=Investigate", timeout=8000)
    time.sleep(2)
    pg.click(f"button.sub-btn >> text={TAB}", timeout=8000)
    time.sleep(3)

    info = pg.evaluate(
        """() => {
      const grid = document.querySelector('.panel-grid');
      const gs = getComputedStyle(grid);
      const cards = [...document.querySelectorAll('.panel-grid .panel-card')].map(c => {
        const title = (c.querySelector('.panel-card-title')||{}).innerText || '(no title)';
        const body  = c.querySelector('.panel-card-body');
        const tbl   = c.querySelector('table');
        return {
          title: title.trim().slice(0, 40),
          cardW: Math.round(c.getBoundingClientRect().width),
          gridColumn: getComputedStyle(c).gridColumn,
          bodyClientW: body ? body.clientWidth : null,
          bodyScrollW: body ? body.scrollWidth : null,
          tableScrollW: tbl ? Math.round(tbl.scrollWidth) : null,
          tableClientW: tbl ? Math.round(tbl.clientWidth) : null,
        };
      });
      return {
        viewport: window.innerWidth,
        gridW: Math.round(grid.getBoundingClientRect().width),
        templateColumns: gs.gridTemplateColumns,
        cards,
      };
    }"""
    )

    print(f"=== viewport {info['viewport']}px / .panel-grid {info['gridW']}px ===")
    print(f"grid-template-columns: {info['templateColumns']}")
    ncols = len(info["templateColumns"].split())
    print(f"  -> 실제 생성된 컬럼 수: {ncols}")
    print()
    for c in info["cards"]:
        overflow = ""
        if c["tableScrollW"] and c["tableClientW"] and c["tableScrollW"] > c["tableClientW"] + 1:
            overflow = f"  <== 테이블 잘림! (내용 {c['tableScrollW']}px > 가용 {c['tableClientW']}px)"
        pct = round(c["cardW"] / info["gridW"] * 100)
        print(f"  [{c['cardW']:>5}px / {pct:>3}%]  col={c['gridColumn']:<10} {c['title']}{overflow}")

    pg.screenshot(path=str(OUT / f"{TAB.replace(chr(47),chr(95))}_{WIDTH}.png"), full_page=True)
    print(f"\nscreenshot: {OUT / f'{TAB}_{WIDTH}.png'}")
    b.close()
