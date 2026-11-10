"""Phase 3 tests for cyber-agents: PolicyEngine gating, F10 authenticated approvals, containment revert, and UI assets."""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.ecosystem_bridge import _ensure_ecosystem_paths, reset_policy_singletons
from daemon.models import Severity, ThreatEvent, ThreatStatus
from daemon.response import ResponsePipeline


def test_phase3_f10_auth_policy_freeze_and_provisional_revert(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CYBER_HARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CYBER_HARNESS_STEP_UP_PATH", str(tmp_path / "step_up.json"))
    monkeypatch.setenv("ECOSYSTEM_HMAC_SECRET", "cyber-agents-phase3-test-secret-0123456789abcdef")
    reset_policy_singletons()
    _ensure_ecosystem_paths()

    from ecosystem_auth.tokens import sign_request
    from ecosystem_policy import compute_totp

    db = Database(str(tmp_path / "aegissiem.db"))
    pipeline = ResponsePipeline(db=db)
    app = create_api(db, pipeline)

    threat_id = db.insert_threat(
        ThreatEvent(
            timestamp=datetime.utcnow(),
            router_name="edge-router",
            threat_type="ssh_brute_force",
            source_ip="198.51.100.42",
            severity=Severity.HIGH,
            raw_log="Failed password for root from 198.51.100.42",
            status=ThreatStatus.open,
        )
    )

    async def _exercise():
        async with TestClient(TestServer(app)) as client:
            # 1. Shared UI assets & policy state endpoint work
            r_state = await client.get("/api/policy/state")
            assert r_state.status == 200
            st = await r_state.json()
            assert st["mode"] == "normal"
            assert st["restrictions"] == "on"

            # (/ui/ asset serving is covered hermetically in tests/test_ui_assets.py;
            # asserting it here required a built appEcosystem dist/ next door.)

            # 2. F10: Unauthenticated block and approval endpoints reject with 401
            r_unauth_block = await client.post(f"/api/threats/{threat_id}/block", json={})
            assert r_unauth_block.status == 401

            chk_id = pipeline.approval_manager.create_checkpoint(
                profile_id=0,
                action="escalate_to_investigate",
                summary="Approve investigation?",
            )
            r_unauth_approve = await client.post(f"/api/approvals/{chk_id}/approve", json={})
            assert r_unauth_approve.status == 401
            r_unauth_deny = await client.post(f"/api/approvals/{chk_id}/deny", json={})
            assert r_unauth_deny.status == 401

            # 3. Enroll TOTP and approve with 6-digit TOTP step-up
            r_enroll = await client.post("/api/auth/step-up/totp/enroll", json={"operator_id": "admin"})
            assert r_enroll.status == 200
            secret = (await r_enroll.json())["secret"]

            code_1 = compute_totp(secret, timestamp=1_700_000_000)
            # Issue token directly at deterministic time or current clock
            live_code = compute_totp(secret)
            r_ok_approve = await client.post(
                f"/api/approvals/{chk_id}/approve",
                json={"operator_id": "admin", "totp_code": live_code},
            )
            assert r_ok_approve.status == 200
            assert db.get_approval(chk_id).status == "approved"

            # 4. Signed HMAC peer call blocks threat AND creates provisional containment checkpoint
            block_path = f"/api/threats/{threat_id}/block"
            block_body = {"reason": "peer containment"}
            headers = sign_request(
                "POST",
                block_path,
                "cyber-agents-phase3-test-secret-0123456789abcdef",
                body=block_body,
            )
            r_block = await client.post(block_path, json=block_body, headers=headers)
            assert r_block.status == 200
            assert len(db.get_blocked_ips()) == 1
            assert db.get_threat(threat_id).status == ThreatStatus.blocked

            # Pending approvals now include `confirm_provisional_block_ip`
            r_pending = await client.get("/api/approvals")
            assert r_pending.status == 200
            pending_list = await r_pending.json()
            prov = [a for a in pending_list if a["action"] == "confirm_provisional_block_ip"]
            assert len(prov) == 1
            prov_id = prov[0]["id"]

            # 5. Denying provisional containment automatically unblocks IP & reverts threat to open!
            deny_path = f"/api/approvals/{prov_id}/deny"
            deny_body = {"note": "false positive"}
            deny_headers = sign_request(
                "POST",
                deny_path,
                "cyber-agents-phase3-test-secret-0123456789abcdef",
                body=deny_body,
            )
            r_deny = await client.post(deny_path, json=deny_body, headers=deny_headers)
            assert r_deny.status == 200
            assert len(db.get_blocked_ips()) == 0
            assert db.get_threat(threat_id).status == ThreatStatus.open

            # 6. Engaging Freeze blocks subsequent mutating block calls until step-up Resume
            r_freeze = await client.post("/api/policy/freeze", json={"reason": "test freeze"})
            assert r_freeze.status == 200
            assert (await r_freeze.json())["frozen"] is True

            block_headers_2 = sign_request(
                "POST",
                block_path,
                "cyber-agents-phase3-test-secret-0123456789abcdef",
                body=block_body,
            )
            r_frozen_block = await client.post(block_path, json=block_body, headers=block_headers_2)
            assert r_frozen_block.status == 409
            assert len(db.get_blocked_ips()) == 0

            # Unauthenticated Resume fails with 401
            r_unauth_resume = await client.post("/api/policy/resume", json={})
            assert r_unauth_resume.status == 401

            # Signed peer/step-up Resume restores normal operation
            resume_path = "/api/policy/resume"
            resume_body = {"reason": "all clear"}
            resume_headers = sign_request(
                "POST",
                resume_path,
                "cyber-agents-phase3-test-secret-0123456789abcdef",
                body=resume_body,
            )
            r_resume = await client.post(resume_path, json=resume_body, headers=resume_headers)
            assert r_resume.status == 200
            assert (await r_resume.json())["frozen"] is False
            _ = code_1

    try:
        asyncio.run(_exercise())
    finally:
        db.close()
        reset_policy_singletons()
