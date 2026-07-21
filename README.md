AWS Journey / CloudWatchDog 🛡️

An automated, event-driven DevSecOps & Cloud Security Remediation Engine built on AWS. 
This project continuously monitors AWS infrastructure for security configuration drift 
(e.g., public S3 buckets, unrestricted Security Groups) and automatically remediates non-compliant resources in real-time.


🏗️ Architecture Overview

The platform uses a serverless, event-driven workflow to achieve near-instantaneous security enforcement:


[ AWS Config / CloudTrail ] 
            │
            ▼
   [ Amazon EventBridge ] ──────(Triggers Event)──────► [ AWS Lambda (Remediator) ]
                                                                │
                                            ┌───────────────────┴───────────────────┐
                                            ▼                                       ▼
                                [ Auto-Remediates Resource ]            [ Logs Drift & Remediation ]
                                   (S3, Security Group)                             │
                                                                                    ▼
                                                                           [ Amazon DynamoDB ]
                                                                                    │
                                                                                    ▼
                                                                           [ CloudFront + S3 ]
                                                                           (awsjourney.space UI)


✨ Key Features

Real-time Drift Detection: Integrates with Amazon EventBridge and AWS CloudTrail to capture configuration changes as soon as they happen.

Automated Remediation: AWS Lambda functions automatically revert non-compliant changes (e.g., blocking public access on S3, revoking SSH 0.0.0.0/0 in Security Groups).

Audit Trail & Logging: Every drift event and remediation action is stored in Amazon DynamoDB for compliance auditing and analytics.

Documentation & Dashboard Web UI: Static UI hosted via Amazon S3 and distributed globally through Amazon CloudFront at awsjourney.space.

Infrastructure as Code (IaC): Fully provisioned and managed using Terraform.


🛠️ Tech Stack

Cloud Provider: AWS (Amazon Web Services)

Compute & Automation: AWS Lambda, Amazon EventBridge

Database: Amazon DynamoDB

Hosting & CDN: Amazon S3, Amazon CloudFront

IaC & Deployment: Terraform, AWS CLI

Frontend: HTML5 / Modern CSS


📁 Repository Structure


Plaintext
CloudWatchDog/
├── docs/                      # Static documentation assets & web UI (awsjourney.space)
│   ├── index.html
│   └── ...
├── terraform/                 # Infrastructure as Code
│   ├── main.tf                # Main Terraform configuration
│   ├── static_site.tf         # S3 bucket & CloudFront setup
│   ├── database.tf            # DynamoDB schema & provisioning
│   ├── outputs.tf             # Infrastructure outputs
│   └── variables.tf           # Terraform input variables
└── README.md



🚀 Getting Started


Prerequisites


AWS CLI configured with proper credentials.

Terraform (v1.x or later).

PowerShell / Bash terminal.

1. Provision Infrastructure
   
Bash
cd terraform
terraform init
terraform plan
terraform apply

2. Deploy Web UI
   
  (awsjourney.space)
Upload the static assets to your S3 bucket and invalidate the CloudFront cache:


PowerShell


# Sync docs to S3
aws s3 sync ./docs s3://awsjourney-space-docs-paras --delete

# Invalidate CloudFront distribution

aws cloudfront create-invalidation --distribution-id E8QFTUY4G2R9B --paths "/*"


🌐 Live Site

Domain: [https://awsjourney.space](https://awsjourney.space)
                                                                           
