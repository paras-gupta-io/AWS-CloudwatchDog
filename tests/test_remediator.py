"""
CloudWatchDog — Test Suite
===========================
Local unit tests for the Lambda Remediator engine.

Verifies event parsing, violation detection, remediation dispatch, and Slack
notification logic using ``pytest`` and ``unittest.mock`` — **zero AWS
credentials required**.

Usage:
    pytest tests/ -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure `src/` is importable regardless of working directory.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from lambda_remediator import (  # noqa: E402
    build_slack_payload,
    extract_event_details,
    find_noncompliant_rules,
    lambda_handler,
    revoke_rules,
)

# ---------------------------------------------------------------------------
# Fixtures — Load mock CloudTrail events
# ---------------------------------------------------------------------------

MOCK_EVENTS_PATH = Path(__file__).resolve().parent / "mock_events.json"


@pytest.fixture(scope="session")
def mock_events() -> dict[str, Any]:
    """Load all mock events from the JSON fixture file."""
    with open(MOCK_EVENTS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def malicious_ssh_event(mock_events: dict) -> dict:
    return mock_events["malicious_ssh_event"]


@pytest.fixture
def safe_internal_event(mock_events: dict) -> dict:
    return mock_events["safe_internal_event"]


@pytest.fixture
def malicious_rdp_event(mock_events: dict) -> dict:
    return mock_events["malicious_rdp_event"]


@pytest.fixture
def mock_ec2_client() -> MagicMock:
    """Create a mock EC2 client that accepts revoke_security_group_ingress."""
    client = MagicMock()
    client.revoke_security_group_ingress.return_value = {"Return": True}
    return client


# ===================================================================
# 1. Event Parsing Tests
# ===================================================================


class TestExtractEventDetails:
    """Validate parsing of CloudTrail event payloads."""

    def test_extracts_group_id(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert details["group_id"] == "sg-0abc123def456789a"

    def test_extracts_event_name(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert details["event_name"] == "AuthorizeSecurityGroupIngress"

    def test_extracts_user_identity_arn(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert "rogue-developer" in details["user_identity"]["arn"]

    def test_extracts_user_identity_type(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert details["user_identity"]["type"] == "IAMUser"

    def test_extracts_ip_permissions(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert len(details["ip_permissions"]) == 1
        assert details["ip_permissions"][0]["fromPort"] == 22

    def test_extracts_region(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert details["aws_region"] == "us-east-1"

    def test_extracts_account_id(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        assert details["account_id"] == "123456789012"

    def test_handles_assumed_role_identity(self, safe_internal_event: dict) -> None:
        details = extract_event_details(safe_internal_event)
        assert details["user_identity"]["type"] == "AssumedRole"
        assert "DevOpsRole" in details["user_identity"]["arn"]


# ===================================================================
# 2. Threat Detection Tests
# ===================================================================


class TestFindNoncompliantRules:
    """Ensure violations are correctly identified."""

    def test_detects_public_ssh(self, malicious_ssh_event: dict) -> None:
        details = extract_event_details(malicious_ssh_event)
        violations = find_noncompliant_rules(details["ip_permissions"])
        assert len(violations) == 1
        assert violations[0]["FromPort"] == 22
        assert violations[0]["ToPort"] == 22
        assert violations[0]["IpRanges"][0]["CidrIp"] == "0.0.0.0/0"

    def test_detects_public_rdp(self, malicious_rdp_event: dict) -> None:
        details = extract_event_details(malicious_rdp_event)
        violations = find_noncompliant_rules(details["ip_permissions"])
        assert len(violations) == 1
        assert violations[0]["FromPort"] == 3389
        # Should capture both IPv4 and IPv6 public CIDRs.
        assert any(
            r.get("CidrIp") == "0.0.0.0/0"
            for r in violations[0].get("IpRanges", [])
        )
        assert any(
            r.get("CidrIpv6") == "::/0"
            for r in violations[0].get("Ipv6Ranges", [])
        )

    def test_ignores_private_cidr(self, safe_internal_event: dict) -> None:
        details = extract_event_details(safe_internal_event)
        violations = find_noncompliant_rules(details["ip_permissions"])
        assert len(violations) == 0

    def test_ignores_safe_port(self) -> None:
        """Port 443 open to 0.0.0.0/0 is allowed (not SSH/RDP)."""
        permissions = [
            {
                "ipProtocol": "tcp",
                "fromPort": 443,
                "toPort": 443,
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                },
                "ipv6Ranges": {"items": []},
            }
        ]
        violations = find_noncompliant_rules(permissions)
        assert len(violations) == 0

    def test_detects_port_range_spanning_ssh(self) -> None:
        """A range like 1-1024 covering port 22 is still a violation."""
        permissions = [
            {
                "ipProtocol": "tcp",
                "fromPort": 1,
                "toPort": 1024,
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                },
                "ipv6Ranges": {"items": []},
            }
        ]
        violations = find_noncompliant_rules(permissions)
        assert len(violations) == 1

    def test_detects_all_traffic_protocol(self) -> None:
        """Protocol -1 (all traffic) with public CIDR is always dangerous."""
        permissions = [
            {
                "ipProtocol": "-1",
                "fromPort": 0,
                "toPort": 65535,
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                },
                "ipv6Ranges": {"items": []},
            }
        ]
        violations = find_noncompliant_rules(permissions)
        assert len(violations) == 1


# ===================================================================
# 3. Remediation Tests
# ===================================================================


class TestRevokeRules:
    """Verify that violations are correctly dispatched to EC2 for revocation."""

    def test_revokes_single_violation(self, mock_ec2_client: MagicMock) -> None:
        violations = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        results = revoke_rules(mock_ec2_client, "sg-test123", violations)
        assert len(results) == 1
        assert results[0]["status"] == "REVOKED"
        mock_ec2_client.revoke_security_group_ingress.assert_called_once_with(
            GroupId="sg-test123",
            IpPermissions=[violations[0]],
        )

    def test_handles_client_error(self, mock_ec2_client: MagicMock) -> None:
        """Gracefully handle an AWS API error during revocation."""
        from botocore.exceptions import ClientError

        mock_ec2_client.revoke_security_group_ingress.side_effect = ClientError(
            {"Error": {"Code": "InvalidPermission.NotFound", "Message": "Rule not found"}},
            "RevokeSecurityGroupIngress",
        )
        violations = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        results = revoke_rules(mock_ec2_client, "sg-test123", violations)
        assert len(results) == 1
        assert results[0]["status"] == "FAILED"
        assert "InvalidPermission.NotFound" in results[0]["error"]

    def test_revokes_multiple_violations(self, mock_ec2_client: MagicMock) -> None:
        violations = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ]
        results = revoke_rules(mock_ec2_client, "sg-multi", violations)
        assert len(results) == 2
        assert all(r["status"] == "REVOKED" for r in results)
        assert mock_ec2_client.revoke_security_group_ingress.call_count == 2


# ===================================================================
# 4. Slack Notification Tests
# ===================================================================


class TestSlackPayload:
    """Verify the Slack message is well-formed Markdown."""

    def test_payload_contains_group_id(self) -> None:
        payload = build_slack_payload(
            group_id="sg-abc123",
            user_identity={"arn": "arn:aws:iam::123:user/test", "type": "IAMUser"},
            violations=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            results=[{"status": "REVOKED"}],
            region="us-east-1",
            account_id="123456789012",
        )
        assert "sg-abc123" in payload["text"]

    def test_payload_contains_user_arn(self) -> None:
        payload = build_slack_payload(
            group_id="sg-abc123",
            user_identity={"arn": "arn:aws:iam::123:user/rogue", "type": "IAMUser"},
            violations=[],
            results=[],
            region="us-east-1",
            account_id="123456789012",
        )
        assert "rogue" in payload["text"]

    def test_payload_shows_success_on_full_revocation(self) -> None:
        payload = build_slack_payload(
            group_id="sg-abc123",
            user_identity={"arn": "arn:aws:iam::123:user/test", "type": "IAMUser"},
            violations=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            results=[{"status": "REVOKED"}],
            region="us-east-1",
            account_id="123456789012",
        )
        assert "REMEDIATION SUCCESSFUL" in payload["text"]

    def test_payload_shows_partial_on_failure(self) -> None:
        payload = build_slack_payload(
            group_id="sg-abc123",
            user_identity={"arn": "arn:aws:iam::123:user/test", "type": "IAMUser"},
            violations=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            results=[{"status": "FAILED"}],
            region="us-east-1",
            account_id="123456789012",
        )
        assert "PARTIAL REMEDIATION" in payload["text"]


# ===================================================================
# 5. Integration Tests — Full Lambda Handler
# ===================================================================


class TestLambdaHandler:
    """End-to-end handler invocation with mocked AWS clients."""

    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "false"})
    def test_remediates_malicious_ssh(
        self,
        malicious_ssh_event: dict,
        mock_ec2_client: MagicMock,
    ) -> None:
        result = lambda_handler(
            malicious_ssh_event, context=None, ec2_client=mock_ec2_client
        )
        assert result["action"] == "REMEDIATED"
        assert result["group_id"] == "sg-0abc123def456789a"
        assert result["violations_found"] == 1
        mock_ec2_client.revoke_security_group_ingress.assert_called_once()

    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "false"})
    def test_ignores_safe_event(
        self,
        safe_internal_event: dict,
        mock_ec2_client: MagicMock,
    ) -> None:
        result = lambda_handler(
            safe_internal_event, context=None, ec2_client=mock_ec2_client
        )
        assert result["action"] == "COMPLIANT"
        assert result["violations"] == 0
        mock_ec2_client.revoke_security_group_ingress.assert_not_called()

    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "false"})
    def test_remediates_malicious_rdp(
        self,
        malicious_rdp_event: dict,
        mock_ec2_client: MagicMock,
    ) -> None:
        result = lambda_handler(
            malicious_rdp_event, context=None, ec2_client=mock_ec2_client
        )
        assert result["action"] == "REMEDIATED"
        assert result["violations_found"] == 1

    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "false"})
    def test_ignores_irrelevant_event(self, mock_ec2_client: MagicMock) -> None:
        """Events that aren't AuthorizeSecurityGroupIngress should be skipped."""
        event = {
            "detail": {
                "eventName": "RunInstances",
                "requestParameters": {},
                "userIdentity": {},
            }
        }
        result = lambda_handler(event, context=None, ec2_client=mock_ec2_client)
        assert result["action"] == "IGNORED"
        mock_ec2_client.revoke_security_group_ingress.assert_not_called()

    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "false"})
    def test_skips_event_without_group_id(self, mock_ec2_client: MagicMock) -> None:
        event = {
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {},
                "userIdentity": {},
            }
        }
        result = lambda_handler(event, context=None, ec2_client=mock_ec2_client)
        assert result["action"] == "SKIPPED"

    @patch("lambda_remediator.send_slack_notification")
    @patch.dict(os.environ, {"ENABLE_SLACK_NOTIFICATIONS": "true"})
    def test_calls_slack_on_remediation(
        self,
        mock_slack: MagicMock,
        malicious_ssh_event: dict,
        mock_ec2_client: MagicMock,
    ) -> None:
        mock_slack.return_value = True
        lambda_handler(
            malicious_ssh_event, context=None, ec2_client=mock_ec2_client
        )
        mock_slack.assert_called_once()
        payload = mock_slack.call_args[0][0]
        assert "sg-0abc123def456789a" in payload["text"]
