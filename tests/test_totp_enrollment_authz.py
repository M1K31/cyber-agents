"""TOTP enrolment cannot be used to take over another operator's factor (CodeRabbit CA-T13, CA-T35)."""
from __future__ import annotations

import asyncio
import os
import time

from aiohttp.test_utils import TestClient, TestServer

from daemon.aegissiem_daemon import create_api
from daemon.db import Database
from daemon.response import ResponsePipeline

ENROLL = "/api/auth/step-up/totp/enroll"
VERIFY = "/api/auth/step-up/totp/verify"


def _run(eco_env, scenario):
    """Run ``scenario(client, h)`` against a fresh API; ``h`` has small helpers."""
    from ecosystem_auth.tokens import sign_request
    from ecosystem_policy import compute_totp

    db = Database(str(eco_env / "aegissiem.db"))
    app = create_api(db, ResponsePipeline(db=db))

    class H:
        @staticmethod
        async def enroll(client, operator_id, **extra):
            resp = await client.post(ENROLL, json={"operator_id": operator_id, **extra})
            return resp.status, await resp.json()

        @staticmethod
        async def enroll_as_peer(client, operator_id):
            body = {"operator_id": operator_id}
            headers = sign_request("POST", ENROLL, os.environ["ECOSYSTEM_HMAC_SECRET"], body=body)
            resp = await client.post(ENROLL, json=body, headers=headers)
            return resp.status, await resp.json()

        @staticmethod
        async def token(client, operator_id, secret, *, window=0):
            code = compute_totp(secret, timestamp=time.time() + 30 * window)
            resp = await client.post(VERIFY, json={"operator_id": operator_id, "totp_code": code})
            assert resp.status == 200, await resp.text()
            return (await resp.json())["step_up_token"]

        @staticmethod
        async def secret_still_valid(client, operator_id, secret):
            # Use the next time-step so an earlier verify in this window is not a replay.
            code = compute_totp(secret, timestamp=time.time() + 30)
            resp = await client.post(VERIFY, json={"operator_id": operator_id, "totp_code": code})
            return resp.status == 200

    async def _go():
        async with TestClient(TestServer(app)) as client:
            await scenario(client, H)

    try:
        asyncio.run(_go())
    finally:
        db.close()


def test_hmac_peer_cannot_rotate_an_enrolled_operator(eco_env):
    async def scenario(client, h):
        status, enrolled = await h.enroll(client, "admin")  # loopback bootstrap
        assert status == 200
        secret = enrolled["secret"]

        status, payload = await h.enroll_as_peer(client, "admin")

        assert status == 403
        assert "secret" not in payload
        assert await h.secret_still_valid(client, "admin", secret)

    _run(eco_env, scenario)


def test_other_operator_cannot_rotate_admin(eco_env):
    async def scenario(client, h):
        _, admin = await h.enroll(client, "admin")
        admin_token = await h.token(client, "admin", admin["secret"])
        status, bob = await h.enroll(client, "bob", step_up_token=admin_token)
        assert status == 200  # an operator may add a new operator
        bob_token = await h.token(client, "bob", bob["secret"])

        status, payload = await h.enroll(client, "admin", step_up_token=bob_token)

        assert status == 403
        assert "secret" not in payload
        assert await h.secret_still_valid(client, "admin", admin["secret"])

    _run(eco_env, scenario)


def test_operator_rotates_self_and_admin_rotates_others(eco_env):
    async def scenario(client, h):
        _, admin = await h.enroll(client, "admin")
        admin_token = await h.token(client, "admin", admin["secret"])
        _, bob = await h.enroll(client, "bob", step_up_token=admin_token)
        bob_token = await h.token(client, "bob", bob["secret"])

        status, rotated = await h.enroll(client, "bob", step_up_token=bob_token)
        assert status == 200
        assert rotated["secret"] != bob["secret"]

        status, recovered = await h.enroll(client, "bob", step_up_token=admin_token)
        assert status == 200
        assert recovered["secret"] != rotated["secret"]

    _run(eco_env, scenario)


def test_hmac_peer_cannot_create_the_admin_identity(eco_env):
    # Bootstrapped by someone other than "admin": the peer must not be able to
    # mint itself the admin identity, which carries the recovery privilege.
    async def scenario(client, h):
        status, _ = await h.enroll(client, "bob")
        assert status == 200

        status, payload = await h.enroll_as_peer(client, "admin")
        assert status == 403
        assert "secret" not in payload

        status, _ = await h.enroll_as_peer(client, "carol")
        assert status == 200  # adding an ordinary new operator is unchanged

    _run(eco_env, scenario)


def test_unauthenticated_enrolment_is_refused_once_bootstrapped(eco_env):
    async def scenario(client, h):
        await h.enroll(client, "bob")
        status, _ = await h.enroll(client, "admin")
        assert status == 403
        status, _ = await h.enroll(client, "bob")
        assert status == 401

    _run(eco_env, scenario)


def test_enrolment_fails_closed_without_store_wide_query(eco_env, monkeypatch):
    from ecosystem_policy import StepUpAuthenticator

    monkeypatch.delattr(StepUpAuthenticator, "has_any_enrolled_operator")

    async def scenario(client, h):
        # Without the store-wide query the daemon cannot prove the store is
        # empty, so it must not hand out an unauthenticated bootstrap secret.
        status, payload = await h.enroll(client, "admin")
        assert status == 403
        assert "secret" not in payload
        assert "has_any_enrolled_operator" in payload["detail"]

    _run(eco_env, scenario)
