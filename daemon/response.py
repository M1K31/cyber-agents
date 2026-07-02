"""AegisSIEM Daemon - Response pipeline and approval manager."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from .db import Database
from .detection import check_escalation, escalate_profile
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


class ApprovalManager:
    """Manages human-in-the-loop approvals for escalation checkpoints."""

    def __init__(self, db: Database):
        self.db = db

    def create_checkpoint(self, profile_id: int, action: str, summary: str) -> int:
        """Create an approval request for a given action.

        Args:
            profile_id: ID of the attacker profile.
            action: The action requiring approval (e.g., 'escalate_to_investigate').
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
        logger.info("Created approval checkpoint #%d for profile %d: %s", approval_id, profile_id, action)
        return approval_id

    def approve(self, approval_id: int) -> bool:
        """Approve a pending approval request.

        Returns True if the approval existed and was pending.
        """
        approval = self.db.get_approval(approval_id)
        if not approval or approval.status != "pending":
            logger.warning("Cannot approve #%d: not found or not pending", approval_id)
            return False

        self.db.update_approval(approval_id, "approved")
        logger.info("Approval #%d approved", approval_id)
        return True

    def deny(self, approval_id: int) -> bool:
        """Deny a pending approval request.

        Returns True if the approval existed and was pending.
        """
        approval = self.db.get_approval(approval_id)
        if not approval or approval.status != "pending":
            logger.warning("Cannot deny #%d: not found or not pending", approval_id)
            return False

        self.db.update_approval(approval_id, "denied")
        logger.info("Approval #%d denied", approval_id)
        return True


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
    ):
        self.db = db
        self.honeypot = honeypot_manager
        self.router_host = router_host
        self.router_user = router_user
        self.router_key = router_key
        self.slack_webhook = slack_webhook
        self.imessage_recipient = imessage_recipient
        self.approval_manager = ApprovalManager(db)

    async def handle_threat(self, threat: ThreatEvent):
        """Process a new threat through the full response pipeline.

        Steps:
        1. Insert threat into database
        2. Send notifications
        3. Check escalation level
        4. Run recon for source IP
        5. Deploy honeypots if needed
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
                    )

                # 5. Deploy honeypots based on escalation
                if self.honeypot and level:
                    await self.honeypot.deploy_for_level(level)

        # 4. Run recon (async, non-blocking for private IPs)
        if threat.source_ip:
            try:
                await run_recon(self.db, threat.source_ip)
            except Exception as e:
                logger.warning("Recon failed for %s: %s", threat.source_ip, e)

    async def block_threat(self, threat_id: int) -> bool:
        """Block the source IP of a threat on the router.

        Returns True if blocking was successful.
        """
        threat = self.db.get_threat(threat_id)
        if not threat or not threat.source_ip:
            logger.warning("Cannot block threat #%d: not found or no source IP", threat_id)
            return False

        if not self.router_host:
            logger.warning("No router configured for blocking")
            # Still record the block in db
            blocked = BlockedIP(ip=threat.source_ip, router_name="unmanaged", blocked_by="auto")
            self.db.insert_blocked_ip(blocked)
            self.db.update_threat_status(threat_id, ThreatStatus.blocked)
            return True

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

        return success

    async def unblock(self, ip: str) -> bool:
        """Unblock an IP address."""
        self.db.unblock_ip(ip)

        if self.router_host:
            return await unblock_ip(ip, self.router_host, self.router_user, self.router_key)
        return True

    async def auto_block_loop(self):
        """Background loop: check for threats past their auto-block deadline every 60s."""
        logger.info("Auto-block loop started")
        while True:
            try:
                past_deadline = self.db.get_open_threats_past_deadline()
                for threat in past_deadline:
                    if threat.id:
                        logger.info("Auto-blocking threat #%d (%s)", threat.id, threat.source_ip)
                        await self.block_threat(threat.id)
            except Exception as e:
                logger.error("Auto-block loop error: %s", e)

            await asyncio.sleep(60)
