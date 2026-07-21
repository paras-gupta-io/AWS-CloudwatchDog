<div align="center">

# 🐕 CloudWatchDog

### Infrastructure Configuration Drift Detection & Automated Security Remediation

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.12-844FBA?style=for-the-badge&logo=terraform&logoColor=white)](https://terraform.io)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20EventBridge%20%7C%20S3-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Tests](https://img.shields.io/badge/Tests-27%20Passed-22c55e?style=for-the-badge&logo=pytest&logoColor=white)](#test-coverage)
[![Live](https://img.shields.io/badge/Live-awsjourney.space-06b6d4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://awsjourney.space)

<br>

*A serverless AWS security engine that detects and auto-remediates dangerous security-group modifications in real time — zero human intervention required.*

[**View Live Site →**](https://awsjourney.space) &nbsp;&nbsp;•&nbsp;&nbsp; [Architecture](#-architecture) &nbsp;&nbsp;•&nbsp;&nbsp; [Features](#-key-features) &nbsp;&nbsp;•&nbsp;&nbsp; [Quick Start](#-getting-started)

<br>

</div>

---

## 🔴 Problem Statement

In enterprise AWS environments, security-group misconfigurations are one of the **most common attack vectors**. A single engineer opening SSH (port 22) or RDP (port 3389) to `0.0.0.0/0` can expose critical infrastructure to the public internet within seconds.

Manual detection via periodic audits is too slow. By the time a misconfiguration is caught, **the damage window has already opened.**

> **CloudWatchDog eliminates that window entirely.**

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              AWS Account                                     │
│                                                                              │
│  ┌─────────────┐     ┌─────────────────┐     ┌────────────────────────┐     │
│  │  CloudTrail  │────▶│  EventBridge     │────▶│  Lambda Remediator    │     │
│  │  (API Logs)  │     │  (Filtered Rule) │     │  (Python/Boto3)       │     │
│  └─────────────┘     └─────────────────┘     └──────┬─────┬───────────┘     │
│                                                      │     │                 │
│                         ┌────────────────────────────┘     │                 │
│                         │            ┌─────────────────────┘                 │
│                         ▼            ▼                                       │
│               ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│               │   EC2 API    │  │   DynamoDB   │  │  Slack Webhook    │     │
│               │  (Revoke)    │  │  (Audit Log) │  │  (Alert Team)    │     │
│               └──────────────┘  └──────────────┘  └───────────────────┘     │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Portfolio Site: S3 → CloudFront → Route53 (awsjourney.space)       │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Pipeline Flow

| Step | Service | Action |
|:---:|---|---|
| **1** | **CloudTrail** | Continuously logs all AWS API calls across the account |
| **2** | **EventBridge** | Filters for `AuthorizeSecurityGroupIngress` events from `ec2.amazonaws.com` |
| **3** | **Lambda** | Parses `ipPermissions` — checks if port 22/3389 is exposed to `0.0.0.0/0` or `::/0` |
| **4** | **EC2 API** | Calls `revoke_security_group_ingress` to strip the non-compliant rule immediately |
| **5** | **DynamoDB** | Persists remediation events for audit trail and compliance reporting |
| **6** | **Slack** | Dispatches a Markdown-formatted alert with user identity, SG ID, and status |

---

## 🌐 Live Deployment

The project is fully deployed and accessible at **[https://awsjourney.space](https://awsjourney.space)**.

<details>
<summary><b>📋 Deployed Resources (click to expand)</b></summary>

| Resource | Service | Identifier |
|---|---|---|
| Remediation Engine | AWS Lambda | `cloudwatchdog-remediator-prod` |
| Event Filter | EventBridge | `cloudwatchdog-sg-ingress-monitor-prod` |
| Execution Role | IAM | `cloudwatchdog-lambda-exec-prod` |
| Audit Logs | DynamoDB | `cloudwatchdog-drift-logs-prod` |
| Execution Logs | CloudWatch | `/aws/lambda/cloudwatchdog-remediator-prod` |
| Documentation | S3 + CloudFront | `awsjourney.space` (HTTPS via ACM) |
| DNS | Route53 | A + AAAA records, `www` redirect |

</details>

---

## ⚡ Key Features

<table>
<tr>
<td width="50%">

### 🛡️ Security Engine
- **Real-time detection** — triggers within seconds
- **Surgical remediation** — revokes only the bad rule
- **Dual-stack** — catches IPv4 & IPv6 public CIDRs
- **Port-range aware** — `1-1024` overlapping SSH? Caught.
- **All-traffic detection** — protocol `-1` flagged

</td>
<td width="50%">

### 🏛️ Enterprise Grade
- **Least-privilege IAM** — exactly 3 permissions
- **DynamoDB audit trail** — full compliance logging
- **Slack notifications** — Markdown-formatted alerts
- **Graceful failure** — Slack errors never block remediation
- **27 unit tests** — zero AWS credentials needed

</td>
</tr>
</table>

---

## 📁 Repository Structure

```
CloudWatchDog/
├── 🏗️ terraform/
│   ├── main.tf              # IAM, Lambda, EventBridge, DynamoDB
│   ├── static_site.tf       # S3, CloudFront, ACM, Route53
│   ├── variables.tf         # 11 configurable inputs with validation
│   └── outputs.tf           # Resource ARNs and identifiers
├── ⚙️ src/
│   ├── __init__.py
│   └── lambda_remediator.py # Core remediation engine (Boto3)
├── 🧪 tests/
│   ├── __init__.py
│   ├── mock_events.json     # 3 realistic CloudTrail event fixtures
│   └── test_remediator.py   # 27 unit & integration tests
├── 🌐 docs/
│   ├── index.html           # Portfolio documentation page
│   ├── styles.css           # Dark theme with glassmorphism
│   └── error.html           # Custom 404 page
└── 📄 README.md
```

---

## 🚀 Getting Started

### Prerequisites

```
Python 3.10+    Terraform >= 1.5    AWS CLI v2
```

### Local Development & Testing

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/CloudWatchDog.git
cd CloudWatchDog

# Install test dependencies
pip install pytest boto3 botocore

# Run the full test suite — NO AWS credentials required
pytest tests/ -v
```

### Deploy to AWS

```bash
cd terraform

# Initialize Terraform providers
terraform init

# Preview the deployment plan
terraform plan

# Deploy everything (Lambda + EventBridge + S3 + CloudFront + Route53)
terraform apply
```

### Upload Documentation Site

```bash
# Sync docs to S3
aws s3 sync docs/ s3://YOUR-BUCKET-NAME --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation --distribution-id YOUR_DIST_ID --paths "/*"
```

---

## ⚙️ Configuration

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | Target AWS region |
| `project_name` | `cloudwatchdog` | Resource naming prefix |
| `environment` | `prod` | Environment tag (`dev` / `staging` / `prod`) |
| `lambda_timeout` | `30` | Lambda timeout (seconds) |
| `lambda_memory_size` | `128` | Lambda memory (MB) |
| `slack_webhook_url` | `""` | Slack webhook endpoint |
| `enable_slack_notifications` | `true` | Toggle Slack alerts |
| `log_retention_days` | `90` | CloudWatch log retention |
| `domain_name` | `awsjourney.space` | Documentation site domain |
| `route53_zone_id` | — | Route53 Hosted Zone ID |

---

## 🧪 Test Coverage

```
tests/test_remediator.py  ·  27 passed  ·  0 failed  ·  0 skipped
```

| Test Class | # | Validates |
|---|:---:|---|
| `TestExtractEventDetails` | 8 | CloudTrail event parsing, IAMUser & AssumedRole identities |
| `TestFindNoncompliantRules` | 6 | SSH/RDP detection, private CIDR passthrough, port ranges, all-traffic |
| `TestRevokeRules` | 3 | EC2 API dispatch, error handling, multi-rule revocation |
| `TestSlackPayload` | 4 | Markdown formatting, success/failure status rendering |
| `TestLambdaHandler` | 6 | End-to-end: malicious events remediated, safe events ignored |

---

## 🔒 Security Design

| Decision | Rationale |
|---|---|
| **Least-privilege IAM** | Exactly 3 permissions — `RevokeSecurityGroupIngress`, `DescribeSecurityGroups`, `CloudWatch Logs` |
| **Region-locked** | EC2 permissions conditioned on `aws:RequestedRegion` |
| **Log group scoping** | CloudWatch Logs scoped to function's own ARN |
| **Sensitive variables** | Slack webhook URL marked `sensitive` in Terraform |
| **Non-blocking alerts** | Slack failures never prevent remediation |
| **S3 OAC** | Docs bucket is private — only CloudFront reads via Origin Access Control |
| **HTTPS enforced** | HTTP → HTTPS redirect with TLS 1.2 minimum |

---

## 🛠️ Technologies

<div align="center">

| Compute | Events | Storage | Network | Security | Testing | IaC |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Lambda | EventBridge | S3 | CloudFront | IAM | pytest | Terraform |
| Python 3.12 | CloudTrail | DynamoDB | Route53 | ACM | unittest.mock | HCL |
| Boto3 | | | | OAC | Botocore | |

</div>

---

## 📝 Resume Bullet Points

> **Cloud Security Automation Engineer — CloudWatchDog**
>
> - Architected and deployed a **serverless security remediation pipeline** using AWS Lambda, EventBridge, CloudTrail, S3, DynamoDB, CloudFront, and Terraform that detects and auto-revokes unauthorized public SSH/RDP access within seconds of misconfiguration.
> - Built a modular Python/Boto3 engine with dependency-injectable architecture, enabling **27 unit tests** to run locally with zero AWS credentials via `pytest` and `unittest.mock`.
> - Authored production-grade **Terraform IaC** (20+ resources) following the Principle of Least Privilege, with IAM policies scoped to three specific EC2/CloudWatch permissions and region-conditioned access.
> - Implemented dual-stack threat detection (IPv4/IPv6) with port-range awareness, catching broad CIDR rules (`0.0.0.0/0`, `::/0`) across exact ports, wide ranges, and all-traffic protocols.
> - Deployed a **premium portfolio documentation site** on S3 + CloudFront with ACM HTTPS, Route53 DNS, and Origin Access Control — live at [awsjourney.space](https://awsjourney.space).
> - Integrated environment-variable-driven **Slack webhook notifications** with Markdown-formatted audit reports and **DynamoDB-backed audit logging** for compliance tracking.

---

<div align="center">

**Built for the cloud, by a Cloud Engineer.**

[![Website](https://img.shields.io/badge/awsjourney.space-Visit%20Site-06b6d4?style=flat-square&logo=googlechrome&logoColor=white)](https://awsjourney.space)

</div>
