"""AegisSIEM Daemon - Response pipeline and approval manager."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Any, Callable, Optional

from .db import Database
from .detection import check_escalation, escalate_profile
from .ecosystem_bridge import (
    _ensure_ecosystem_paths,
    get_approval_queue,
    get_policy_engine,
)
from .honeypot import HoneypotManager
from .models import (
    Approval,
    BlockedIP,
    EscalationLevel,
    ThreatEvent,
    ThreatStatus,
)
from .notifications import notify
from .recon import run_recon
from .router_ssh import block_ip, unblock_ip

logger = logging.getLogger(__name__)


def _unified_approval_key(db: Database, approval_id: int) -> str:
    raw_path = str(getattr(db, "db_path", "default"))
    scope = hashlib.sha256(raw_path.encode("utf-8")).hexdigest()[:10]
    return f"cyber-agents-{scope}-{approval_id}"


class ApprovalManager:
    """Manages human-in-the-loop approvals for escalation checkpoints and provisional containment."""

    def __init__(
        self,
        db: Database,
        *,
        policy_engine: Any = None,
        approval_queue: Any = None,
        revert_callback: Callable[[dict[str, Any]], Any] | None = None,
    ):
        self.db = db
        self.policy_engine = policy_engine or get_policy_engine()
        self.approval_queue = approval_queue or get_approval_queue(revert_callback=revert_callback)
        if revert_callback is not None:
            self.approval_queue._revert_cb = revert_callback

    def create_checkpoint(
        self,
        profile_id: int,
        action: str,
        summary: str,
        *,
        action_class: str = "investigate",
        target: dict[str, Any] | None = None,
        async_containment: bool = False,
        on_deny: str = "abort",
        revert_plan: dict[str, Any] | None = None,
        ttl_seconds: int | None = 3600,
    ) -> int:
        """Create an approval request for a given action.

        Args:
            profile_id: ID of the attacker profile (or 0 for perimeter threat containment).
            action: The action requiring approval (e.g., 'escalate_to_investigate', 'block_ip').
            summary: Human-readable summary of why approval is needed.

        Returns:
            Approval ID.
        """
        approval = Approval(
            profile_id=profile_id,
            action=action,
            status="pending",
            summary=summary,
            created_at=datetime.utcnow(),
        )
        approval_id = self.db.insert_approval(approval)
        state = self.policy_engine.export_state()
        self.approval_queue.request_approval(
            approval_id=_unified_approval_key(self.db, approval_id),
            requester_service="aegissiem_daemon",
            actor="aegissiem_daemon/response",
            action=action,
            action_class=action_class,
            target=target or {"profile_id": profile_id},
            summary=summary,
            policy_version=int(state.get("policy_version", 3)),
            mode=str(state.get("mode", "normal")),
            ttl_seconds=ttl_seconds,
            async_containment=async_containment,
            on_deny=on_deny,
            revert_plan=revert_plan,
        )
        logger.info("Created approval checkpoint #%d for profile %d: %s", approval_id, profile_id, action)
        return approval_id

    def approve(
        self,
        approval_id: int,
        *,
        step_up_token: str | None = None,
        resolved_by: str = "local-operator",
        auth_method: str = "totp",
        note: str = "",
    ) -> bool:
        """Approve a pending approval request.

        Returns True if the approval existed and was pending (and Freeze is not active).
        """
        if self.policy_engine.export_state().get("frozen"):
            logger.warning("Cannot approve #%d while Ecosystem Freeze is active", approval_id)
            return False

        approval = self.db.get_approval(approval_id)
        if not approval or approval.status != "pending":
            logger.warning("Cannot approve #%d: not found or not pending", approval_id)
            return False

        key = _unified_approval_key(self.db, approval_id)
        if self.approval_queue.get(key) is not None:
            self.approval_queue.approve(
                key,
                step_up_token=step_up_token,
                resolved_by=resolved_by,
                auth_method=auth_method,
                note=note,
                is_frozen_fn=lambda: bool(self.policy_engine.export_state().get("frozen")),
            )

        self.db.update_approval(approval_id, "approved")
        logger.info("Approval #%d approved by %s (%s)", approval_id, resolved_by, auth_method)
        return True

    def deny(
        self,
        approval_id: int,
        *,
        step_up_token: str | None = None,
        resolved_by: str = "local-operator",
        auth_method: str = "totp",
        note: str = "",
    ) -> bool:
        """Deny a pending approval request (and trigger automatic containment revert if applicable).

        Returns True if the approval existed and was pending.
        """
        approval = self.db.get_approval(approval_id)
        if not approval or approval.status != "pending":
            logger.warning("Cannot deny #%d: not found or not pending", approval_id)
            return False

        key = _unified_approval_key(self.db, approval_id)
        if self.approval_queue.get(key) is not None:
            self.approval_queue.deny(
                key,
                step_up_token=step_up_token,
                resolved_by=resolved_by,
                auth_method=auth_method,
                note=note,
            )

        self.db.update_approval(approval_id, "denied")
        logger.info("Approval #%d denied by %s (%s)", approval_id, resolved_by, auth_method)
        return True

    def expire_due(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Expire due provisional containment approvals and sync SQLite approval status."""
        expired = self.approval_queue.expire_due(now=now)
        raw_path = str(getattr(self.db, "db_path", "default"))
        prefix = f"cyber-agents-{hashlib.sha256(raw_path.encode('utf-8')).hexdigest()[:10]}-"
        for rec in expired:
            aid_str = str(rec.get("approval_id") or "")
            if aid_str.startswith(prefix) and aid_str[len(prefix) :].isdigit():
                self.db.update_approval(int(aid_str[len(prefix) :]), "expired")
        return expired


class ResponsePipeline:
    """Orchestrates threat response: notification, escalation, recon, honeypot, blocking."""

    def __init__(
        self,
        db: Database,
        honeypot_manager: Optional[HoneypotManager] = None,
        router_host: Optional[str] = None,
        router_user: str = "admin",
        router_key: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        imessage_recipient: Optional[str] = None,
        policy_engine: Any = None,
        approval_queue: Any = None,
    ):
        self.db = db
        self.honeypot = honeypot_manager
        # Monotonic honeypot-deployment lease: a revert only tears down the
        # deployment it owns, so an expiring old lease cannot stop a newer one.
        self._honeypot_lease = 0
        self._active_honeypot_lease = None
        self.router_host = router_host
        self.router_user = router_user
        self.router_key = router_key
        self.slack_webhook = slack_webhook
        self.imessage_recipient = imessage_recipient
        self.policy_engine = policy_engine or get_policy_engine()
        self.approval_manager = ApprovalManager(
            db,
            policy_engine=self.policy_engine,
            approval_queue=approval_queue,
            revert_callback=self._revert_provisional_containment,
        )

    def _decide(self, action: str, action_class: str, target: dict[str, Any], rationale: str = "") -> Any:
        _ensure_ecosystem_paths()
        from ecosystem_policy import ActionRequest

        return self.policy_engine.decide(
            ActionRequest(
                actor="aegissiem_daemon/response",
                action=action,
                action_class=action_class,
                target=target,
                rationale=rationale,
            )
        )

    def _revert_provisional_containment(self, record: dict[str, Any]) -> None:
        """Revert a provisional block or honeypot deployment when its async containment checkpoint is denied or expires."""
        plan = record.get("revert_plan") or {}
        # Honeypot provisional teardown: tear the listeners back down so a
        # denied/expired lease is a real revert, not a silent no-op.
        if plan.get("teardown_honeypot"):
            lease_id = plan.get("lease_id")
            if lease_id is not None and lease_id != self._active_honeypot_lease:
                logger.warning(
                    "Skipping honeypot teardown for stale lease %s (active lease=%s); a newer deployment is live",
                    lease_id, self._active_honeypot_lease,
                )
                return
            logger.info("Reverting provisional honeypot deployment (level=%s, lease=%s)", plan.get("level"), lease_id)
            if self.honeypot is None:
                logger.warning("Honeypot teardown requested but no honeypot manager is configured")
                return
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                logger.warning("Could not schedule honeypot teardown: no running event loop")
                return
            if loop.is_running():
                loop.create_task(self.honeypot.stop_all())
                self._active_honeypot_lease = None
            return
        ip = plan.get("unblock_ip") or (record.get("target") or {}).get("blocked_ip")
        threat_id = plan.get("threat_id") or (record.get("target") or {}).get("threat_id")
        if not ip:
            return
        logger.info("Reverting provisional containment block for IP %s (threat=%s)", ip, threat_id)
        self.db.unblock_ip(str(ip))
        if threat_id is not None:
            try:
                self.db.update_threat_status(int(threat_id), ThreatStatus.open)
            except Exception:
                pass
        if self.router_host:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.create_task(unblock_ip(str(ip), self.router_host, self.router_user, self.router_key))
            except RuntimeError:
                pass

    async def handle_threat(self, threat: ThreatEvent):
        """Process a new threat through the full response pipeline.

        Steps:
        1. Insert threat into database
        2. Send notifications
        3. Check escalation level
        4. Run recon for source IP (policy-gated passive lookup)
        5. Deploy honeypots if needed (policy-gated containment)
        """
        # 1. Insert into database
        threat_id = self.db.insert_threat(threat)
        threat.id = threat_id
        logger.info("Threat #%d recorded: %s from %s", threat_id, threat.threat_type, threat.source_ip)

        # 2. Notify
        notify(
            threat,
            slack_webhook=self.slack_webhook,
            imessage_recipient=self.imessage_recipient,
        )

        # 3. Check escalation
        if threat.source_ip:
            profile = self.db.get_profile_by_ip(threat.source_ip)
            if profile:
                level = check_escalation(self.db, threat.source_ip)

                # If at PROFILED checkpoint, create approval
                if level == EscalationLevel.PROFILED:
                    self.approval_manager.create_checkpoint(
                        profile_id=profile.id,
                        action="escalate_to_investigate",
                        summary=f"Profile {threat.source_ip} reached PROFILED level with "
                                f"{profile.total_attempts} attempts. Approve escalation to INVESTIGATE?",
                        action_class="investigate",
                        target={"profile_id": profile.id, "source_ip": threat.source_ip},
                    )

                # 5. Deploy honeypots based on escalation (policy-checked)
                if self.honeypot and level:
                    hp_decision = self._decide(
                        action="deploy_honeypot",
                        action_class="contain",
                        target={"local_service": "honeypot", "level": getattr(level, "value", str(level))},
                        rationale=f"Escalation level {level} for {threat.source_ip}",
                    )
                    if hp_decision.result in ("allow", "allow_and_notify"):
                        await self.honeypot.deploy_for_level(level)
                        # Every deployment claims a new lease, so an earlier lease's
                        # revert can no longer tear down this newer deployment — even
                        # when this one is a plain allow with no async-approval lease.
                        self._honeypot_lease += 1
                        lease_id = self._honeypot_lease
                        self._active_honeypot_lease = lease_id
                        # Provisional containment: when the policy allowed this only
                        # under an async-approval lease, record a checkpoint with the
                        # TTL/revert plan so it is reviewed and can expire, rather than
                        # deploying listeners that linger unapproved.
                        if getattr(hp_decision, "async_approval", False):
                            try:
                                self.approval_manager.create_checkpoint(
                                    profile_id=profile.id if profile and profile.id else 0,
                                    action="confirm_provisional_honeypot",
                                    summary=(
                                        f"Provisional honeypot deployment active for level "
                                        f"{getattr(level, 'value', level)} ({threat.source_ip}). "
                                        f"Deny or allow TTL expiry to tear it down."
                                    ),
                                    action_class="contain",
                                    target={"local_service": "honeypot", "level": getattr(level, "value", str(level)), "source_ip": threat.source_ip},
                                    async_containment=True,
                                    on_deny=hp_decision.on_deny or "revert",
                                    revert_plan={"teardown_honeypot": True, "level": getattr(level, "value", str(level)), "lease_id": lease_id},
                                    ttl_seconds=hp_decision.ttl_seconds or 86400,
                                )
                            except Exception as exc:
                                # Checkpoint storage failed: there is no TTL-backed
                                # revert, so do not leave listeners up unapproved.
                                logger.error("Honeypot checkpoint creation failed (%r); tearing down provisional deployment", exc)
                                try:
                                    await self.honeypot.stop_all()
                                finally:
                                    self._active_honeypot_lease = None
                    else:
                        logger.info("Honeypot deployment held by PolicyEngine (%s): %s", hp_decision.result, hp_decision.reason)

        # 4. Run passive recon (policy-checked external passive lookup)
        if threat.source_ip:
            recon_decision = self._decide(
                action="whois",
                action_class="observe",
                target={"external_ip": threat.source_ip, "kind": "external_ip"},
                rationale=f"Passive WHOIS/ASN enrichment for {threat.source_ip}",
            )
            if recon_decision.result in ("allow", "allow_and_notify"):
                try:
                    await run_recon(self.db, threat.source_ip)
                except Exception as e:
                    logger.warning("Recon failed for %s: %s", threat.source_ip, e)

    async def block_threat(self, threat_id: int) -> str:
        """Block the source IP of a threat on the router, gated by PolicyEngine.

        Returns one of: "blocked" (applied), "pending_approval" (checkpoint created,
        awaiting operator step-up), "denied" (policy denied), or "failed" (not found
        or the router rejected the block).
        """
        threat = self.db.get_threat(threat_id)
        if not threat or not threat.source_ip:
            logger.warning("Cannot block threat #%d: not found or no source IP", threat_id)
            return "failed"

        decision = self._decide(
            action="block_ip",
            action_class="contain",
            target={
                "router": self.router_host or "unmanaged",
                "blocked_ip": threat.source_ip,
                "threat_id": threat_id,
            },
            rationale=f"Block {threat.threat_type} from {threat.source_ip}",
        )
        if decision.result == "deny":
            logger.warning("Block of threat #%d (%s) denied by PolicyEngine: %s", threat_id, threat.source_ip, decision.reason)
            return "denied"
        if decision.result == "require_approval":
            # Dedupe: the auto-block loop retries an open threat every 60s, so only
            # create a checkpoint if this threat has no pending block_ip approval.
            # Match the exact summary delimiter ("threat #<id> (") so threat #1
            # is not treated as pending because threat #15 has a checkpoint.
            marker = f"threat #{threat_id} ("
            already_pending = any(
                a.action == "block_ip" and marker in (a.summary or "")
                for a in self.db.get_pending_approvals()
            )
            if not already_pending:
                profile = self.db.get_profile_by_ip(threat.source_ip)
                self.approval_manager.create_checkpoint(
                    profile_id=profile.id if profile and profile.id else 0,
                    action="block_ip",
                    summary=f"Approve blocking {threat.source_ip} for threat #{threat_id} ({threat.threat_type})?",
                    action_class="contain",
                    target={"blocked_ip": threat.source_ip, "threat_id": threat_id},
                )
            return "pending_approval"

        if not self.router_host:
            logger.warning("No router configured for blocking")
            blocked = BlockedIP(ip=threat.source_ip, router_name="unmanaged", blocked_by="auto")
            self.db.insert_blocked_ip(blocked)
            self.db.update_threat_status(threat_id, ThreatStatus.blocked)
            success = True
        else:
            success = await block_ip(
                threat.source_ip,
                self.router_host,
                self.router_user,
                self.router_key,
            )
            if success:
                blocked = BlockedIP(
                    ip=threat.source_ip,
                    router_name=self.router_host,
                    blocked_by="auto",
                )
                self.db.insert_blocked_ip(blocked)
                self.db.update_threat_status(threat_id, ThreatStatus.blocked)
                logger.info("Blocked threat #%d: %s", threat_id, threat.source_ip)
            else:
                logger.error("Failed to block threat #%d: %s", threat_id, threat.source_ip)

        if success and decision.async_approval:
            profile = self.db.get_profile_by_ip(threat.source_ip)
            self.approval_manager.create_checkpoint(
                profile_id=profile.id if profile and profile.id else 0,
                action="confirm_provisional_block_ip",
                summary=(
                    f"Provisional perimeter block active for {threat.source_ip} (threat #{threat_id}). "
                    f"Deny or allow TTL expiry to automatically unblock."
                ),
                action_class="contain",
                target={"blocked_ip": threat.source_ip, "threat_id": threat_id},
                async_containment=True,
                on_deny=decision.on_deny or "revert",
                revert_plan={"unblock_ip": threat.source_ip, "threat_id": threat_id},
                ttl_seconds=decision.ttl_seconds or 86400,
            )

        return "blocked" if success else "failed"

    async def unblock(self, ip: str) -> bool:
        """Unblock an IP address."""
        self.db.unblock_ip(ip)

        if self.router_host:
            return await unblock_ip(ip, self.router_host, self.router_user, self.router_key)
        return True

    async def auto_block_loop(self):
        """Background loop: check for threats past their auto-block deadline and expire provisional containment leases every 60s."""
        logger.info("Auto-block loop started")
        while True:
            try:
                self.approval_manager.expire_due()
                if not self.policy_engine.export_state().get("frozen"):
                    past_deadline = self.db.get_open_threats_past_deadline()
                    for threat in past_deadline:
                        if threat.id:
                            logger.info("Auto-blocking threat #%d (%s)", threat.id, threat.source_ip)
                            await self.block_threat(threat.id)
            except Exception as e:
                logger.error("Auto-block loop error: %s", e)

            await asyncio.sleep(60)
