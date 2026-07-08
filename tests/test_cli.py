# -*- coding: utf-8 -*-
"""헤드리스 CLI 모드 테스트 — analyze → JSON/PDF/stdout."""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from cli import run_cli, analyze_file


def _write_pcap(path: Path, num_ports: int = 100):
    from conftest import build_pcap_portscan
    path.write_bytes(build_pcap_portscan(num_ports=num_ports))


class TestCliBasics:
    def test_version(self, capsys):
        assert run_cli(["--version"]) == 0
        assert "WireBoard" in capsys.readouterr().out

    def test_help(self, capsys):
        assert run_cli(["--help"]) == 0
        assert "analyze" in capsys.readouterr().out

    def test_unknown_command(self, capsys):
        assert run_cli(["frobnicate"]) == 2

    def test_missing_file(self, capsys):
        assert run_cli(["analyze", "C:/no/such/file.pcap"]) == 2

    def test_unknown_option(self, tmp_path, capsys):
        f = tmp_path / "c.pcap"; _write_pcap(f)
        assert run_cli(["analyze", str(f), "--bogus", "x"]) == 2


class TestCliAnalyze:
    def test_analyze_stdout(self, tmp_path, capsys):
        f = tmp_path / "scan.pcap"; _write_pcap(f)
        rc = run_cli(["analyze", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Risk:" in out
        assert "Sessions:" in out

    def test_analyze_json_output(self, tmp_path):
        f = tmp_path / "scan.pcap"; _write_pcap(f)
        out = tmp_path / "r.json"
        rc = run_cli(["analyze", str(f), "--json", str(out)])
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["session_count"] >= 1
        assert data["risk_level"] in ("CLEAN", "LOW", "MEDIUM", "HIGH")
        assert "attacks" in data and "diagnostics" in data

    def test_analyze_pdf_output(self, tmp_path):
        f = tmp_path / "scan.pcap"; _write_pcap(f)
        out = tmp_path / "r.pdf"
        rc = run_cli(["analyze", str(f), "--pdf", str(out)])
        assert rc == 0
        assert out.read_bytes()[:4] == b"%PDF"

    def test_analyze_file_api(self, tmp_path):
        f = tmp_path / "scan.pcap"; _write_pcap(f)
        cap, sr, warnings = analyze_file(str(f), target="192.168.1.100")
        assert len(cap.sessions) >= 1
        assert sr.risk_level in ("CLEAN", "LOW", "MEDIUM", "HIGH")

    def test_analyze_target_filter(self, tmp_path):
        f = tmp_path / "scan.pcap"; _write_pcap(f)
        out = tmp_path / "r.json"
        rc = run_cli(["analyze", str(f), "--target", "192.168.1.100", "--json", str(out)])
        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8"))["target_ip"] == "192.168.1.100"
