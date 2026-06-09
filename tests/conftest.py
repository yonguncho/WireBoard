# -*- coding: utf-8 -*-
"""Shared fixtures and path setup for edge-case test suite."""
import os
import sys
import uuid

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))


def make_uuid() -> str:
    return str(uuid.uuid4())


def make_session(src_ip="1.2.3.4", dst_ip="5.6.7.8", **kwargs):
    from models.session import SessionModel
    defaults = dict(
        session_id=make_uuid(),
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=12345, dst_port=80,
        protocol="TCP",
        start_ts=1.0, end_ts=2.0,
        bytes_total=1000, packet_count=10,
    )
    defaults.update(kwargs)
    return SessionModel(**defaults)


def make_attack(attack_type="DoS", confidence="high", mitre_id="T1498.001"):
    from models.attack import AttackDetectionResult
    return AttackDetectionResult(
        attack_type=attack_type,
        confidence=confidence,
        evidence=["test evidence"],
        mitre_id=mitre_id,
    )


@pytest.fixture
def fastapi_client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


@pytest.fixture
def seeded_store(fastapi_client):
    """Returns (client, upload_id, target_ip) with a pre-seeded session store."""
    from store.session_store import SessionStore, ParsedCapture
    from dependencies import get_store
    target_ip = "1.2.3.4"
    upload_id = make_uuid()
    store = get_store()
    store.put(ParsedCapture(
        upload_id=upload_id,
        source_type="pcap",
        sessions=[make_session(src_ip=target_ip)],
    ))
    return fastapi_client, upload_id, target_ip
