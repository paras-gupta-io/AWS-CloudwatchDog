"""
CloudWatchDog — Lambda Remediator Engine
=========================================
Automated security-group drift detection and remediation.

Monitors EventBridge events sourced from CloudTrail for
`AuthorizeSecurityGroupIngress` API calls. When a rule exposes
port 22 (SSH) or port 3389 (RDP) to the public internet
(0.0.0.0/0 or ::/0), the offending rule is immediately revoked
and a Slack notification is dispatched.

Environment Variables:
    SLACK_WEBHOOK_URL          — Slack Incoming Webhook endpoint.
    ENABLE_SLACK_NOTIFICATIONS — "true" (default) to send alerts.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger("CloudWatchDog")
logger.setLevel(logging.INFO)

DANGEROUS_PORTS: set[int] = {22, 3389}
PUBLIC_CIDRS: set[str] = {"0.0.0.0/0", "::/0"}

SLACK_WEBHOOK_URL: str = os.environ.get("SLACK_WEBHOOK_URL", "")
ENABLE_SLACK: bool = os.environ.get(
    "ENABLE_SLACK_NOTIFICATIONS", "true"
).lower() == "true"


# ---------------------------------------------------------------------------
# Event Parsing
# ---------------------------------------------------------------------------


def extract_event_details(event: dict[str, Any]) -> dict[str, Any]:
    """Extract security-relevant fields from a CloudTrail event payload.

    Handles events delivered both *raw* (EventBridge wrapping) and
    pre-unwrapped (direct ``detail`` dict).

    Returns a dict with keys:
        event_name, group_id, ip_permissions, user_identity,
        source_ip, aws_region, account_id
    """
    detail: dict[str, Any] = event.get("detail", event)

    request_params = detail.get("requestParameters", {})
    user_identity = detail.get("userIdentity", {})

    return {
        "event_name": detail.get("eventName", ""),
        "group_id": request_params.get("groupId", ""),
        "ip_permissions": request_params.get("ipPermissions", {}).get(
            "items", []
        ),
        "user_identity": {
            "type": user_identity.get("type", "Unknown"),
            "arn": user_identity.get("arn", "Unknown"),
            "principal_id": user_identity.get("principalId", "Unknown"),
            "account_id": user_identity.get("accountId", "Unknown"),
        },
        "source_ip": detail.get("sourceIPAddress", "Unknown"),
        "aws_region": detail.get("awsRegion", "Unknown"),
        "account_id": detail.get("recipientAccountId", "Unknown"),
    }


# ---------------------------------------------------------------------------
# Threat Detection
# ---------------------------------------------------------------------------


def find_noncompliant_rules(
    ip_permissions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Identify ingress rules that expose dangerous ports to the public internet.

    Returns a list of ``IpPermission`` dicts suitable for passing directly
    to ``revoke_security_group_ingress``.
    """
    violations: list[dict[str, Any]] = []

    for perm in ip_permissions:
        from_port: int = perm.get("fromPort", 0)
        to_port: int = perm.get("toPort", 0)
        protocol: str = str(perm.get("ipProtocol", "")).lower()

        # Skip if protocol is not tcp/udp/all (-1) — ICMP etc. don't
        # expose SSH/RDP.
        if protocol not in ("tcp", "udp", "-1", "all"):
            continue

        # Check whether the port range overlaps with any dangerous port.
        port_overlap = any(
            from_port <= p <= to_port for p in DANGEROUS_PORTS
        )
        # Protocol "-1" means *all traffic* — always dangerous with public CIDR.
        if protocol in ("-1", "all"):
            port_overlap = True

        if not port_overlap:
            continue

        # Collect public CIDR ranges attached to this permission.
        public_ipv4 = [
            r for r in perm.get("ipRanges", {}).get("items", [])
            if r.get("cidrIp") in PUBLIC_CIDRS
        ]
        public_ipv6 = [
            r for r in perm.get("ipv6Ranges", {}).get("items", [])
            if r.get("cidrIpv6") in PUBLIC_CIDRS
        ]

        if not public_ipv4 and not public_ipv6:
            continue

        # Build the revocation payload — mirrors the AWS IpPermission shape.
        violation: dict[str, Any] = {
            "IpProtocol": perm.get("ipProtocol", "tcp"),
            "FromPort": from_port,
            "ToPort": to_port,
        }
        if public_ipv4:
            violation["IpRanges"] = [
                {"CidrIp": r["cidrIp"]} for r in public_ipv4
            ]
        if public_ipv6:
            violation["Ipv6Ranges"] = [
                {"CidrIpv6": r["cidrIpv6"]} for r in public_ipv6
            ]
        violations.append(violation)

    return violations


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


def revoke_rules(
    ec2_client: Any,
    group_id: str,
    violations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Revoke non-compliant security-group ingress rules.

    Returns a list of result dicts per violation with ``status`` and
    optionally ``error``.
    """
    results: list[dict[str, Any]] = []
    for rule in violations:
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[rule],
            )
            results.append({"rule": rule, "status": "REVOKED"})
            logger.info(
                "Revoked rule on %s: ports %s-%s (%s)",
                group_id,
                rule.get("FromPort"),
                rule.get("ToPort"),
                rule.get("IpProtocol"),
            )
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            error_msg = exc.response["Error"]["Message"]
            results.append(
                {"rule": rule, "status": "FAILED", "error": f"{error_code}: {error_msg}"}
            )
            logger.error(
                "Failed to revoke rule on %s: %s — %s",
                group_id,
                error_code,
                error_msg,
            )
    return results


# ---------------------------------------------------------------------------
# Slack Notification
# ---------------------------------------------------------------------------


def build_slack_payload(
    group_id: str,
    user_identity: dict[str, str],
    violations: list[dict[str, Any]],
    results: list[dict[str, Any]],
    region: str,
    account_id: str,
) -> dict[str, Any]:
    """Build a rich, Markdown-formatted Slack message payload."""
    revoked_count = sum(1 for r in results if r["status"] == "REVOKED")
    failed_count = sum(1 for r in results if r["status"] == "FAILED")

    status_emoji = "✅" if failed_count == 0 else "⚠️"
    status_text = (
        "REMEDIATION SUCCESSFUL"
        if failed_count == 0
        else f"PARTIAL REMEDIATION ({failed_count} failure(s))"
    )

    rule_lines = []
    for v in violations:
        ports = f"{v.get('FromPort', '*')}-{v.get('ToPort', '*')}"
        cidrs = ", ".join(
            [r.get("CidrIp", "") for r in v.get("IpRanges", [])]
            + [r.get("CidrIpv6", "") for r in v.get("Ipv6Ranges", [])]
        )
        rule_lines.append(f"• `{v.get('IpProtocol')}` ports `{ports}` → `{cidrs}`")

    rules_block = "\n".join(rule_lines) if rule_lines else "_No rules parsed_"

    text = (
        f"{status_emoji} *CloudWatchDog — {status_text}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Security Group:* `{group_id}`\n"
        f"*Region:* `{region}` | *Account:* `{account_id}`\n"
        f"*Offending User:* `{user_identity.get('arn', 'Unknown')}`\n"
        f"*User Type:* `{user_identity.get('type', 'Unknown')}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"*Rules Revoked:* {revoked_count} | *Failed:* {failed_count}\n"
        f"{rules_block}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"_Automated by CloudWatchDog 🐕_"
    )

    return {"text": text}


def send_slack_notification(payload: dict[str, Any]) -> bool:
    """POST a JSON payload to the configured Slack webhook.

    Returns True on success, False on failure (non-fatal — remediation
    should never fail because of a notification issue).
    """
    if not ENABLE_SLACK or not SLACK_WEBHOOK_URL:
        logger.info("Slack notifications disabled or webhook URL not set.")
        return False

    try:
        req = Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            logger.info("Slack notification sent — HTTP %s", resp.status)
            return True
    except (URLError, OSError) as exc:
        logger.warning("Slack notification failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------


def lambda_handler(
    event: dict[str, Any],
    context: Any = None,
    ec2_client: Any = None,
) -> dict[str, Any]:
    """AWS Lambda entry-point.

    Parameters
    ----------
    event : dict
        EventBridge event wrapping a CloudTrail ``AuthorizeSecurityGroupIngress``
        API call.
    context : object, optional
        Lambda runtime context (unused but required by the runtime contract).
    ec2_client : object, optional
        Injectable ``boto3`` EC2 client — primarily for unit-test dependency
        injection. If ``None``, a real client is created.

    Returns
    -------
    dict
        Execution summary including detected violations and remediation results.
    """
    logger.info("CloudWatchDog invoked — raw event: %s", json.dumps(event))

    details = extract_event_details(event)

    # Guard: only process AuthorizeSecurityGroupIngress events.
    if details["event_name"] != "AuthorizeSecurityGroupIngress":
        logger.info(
            "Ignoring event '%s' — not a security-group ingress change.",
            details["event_name"],
        )
        return {"action": "IGNORED", "reason": "irrelevant_event"}

    group_id = details["group_id"]
    if not group_id:
        logger.warning("No groupId found in event — skipping.")
        return {"action": "SKIPPED", "reason": "missing_group_id"}

    violations = find_noncompliant_rules(details["ip_permissions"])
    if not violations:
        logger.info(
            "No public SSH/RDP exposure detected on %s — no action taken.",
            group_id,
        )
        return {
            "action": "COMPLIANT",
            "group_id": group_id,
            "violations": 0,
        }

    logger.warning(
        "DRIFT DETECTED — %d non-compliant rule(s) on %s. Remediating…",
        len(violations),
        group_id,
    )

    # Use injected client or create a real one.
    if ec2_client is None:
        ec2_client = boto3.client("ec2")

    results = revoke_rules(ec2_client, group_id, violations)

    # Notify via Slack (best-effort — never block remediation).
    slack_payload = build_slack_payload(
        group_id=group_id,
        user_identity=details["user_identity"],
        violations=violations,
        results=results,
        region=details["aws_region"],
        account_id=details["account_id"],
    )
    send_slack_notification(slack_payload)

    return {
        "action": "REMEDIATED",
        "group_id": group_id,
        "violations_found": len(violations),
        "results": results,
    }
