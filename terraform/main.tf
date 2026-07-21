# =============================================================================
# CloudWatchDog — Core Infrastructure
# Infrastructure Configuration Drift & Automated Security Remediation
# =============================================================================
#
# Architecture:
#   CloudTrail → EventBridge (filtered rule) → Lambda (remediation)
#                                                └→ Slack (notification)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        Environment = var.environment
        ManagedBy   = "Terraform"
        Purpose     = "SecurityRemediation"
      },
      var.tags,
    )
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# IAM Role — Lambda Execution (Principle of Least Privilege)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })
}

resource "aws_iam_role_policy" "remediator_permissions" {
  name = "${var.project_name}-remediator-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # EC2 — Scoped to security-group remediation only
      {
        Sid    = "SecurityGroupRemediation"
        Effect = "Allow"
        Action = [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeSecurityGroups",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      # CloudWatch Logs — Scoped to this function's log group
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.remediator.arn}:*"
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/${var.project_name}-remediator-${var.environment}"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Lambda Function — Remediator Engine
# ---------------------------------------------------------------------------

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/lambda_remediator.zip"
}

resource "aws_lambda_function" "remediator" {
  function_name    = "${var.project_name}-remediator-${var.environment}"
  description      = "CloudWatchDog: Auto-revokes public SSH/RDP security-group rules"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_remediator.lambda_handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL          = var.slack_webhook_url
      ENABLE_SLACK_NOTIFICATIONS = tostring(var.enable_slack_notifications)
    }
  }

  depends_on = [
    aws_iam_role_policy.remediator_permissions,
    aws_cloudwatch_log_group.remediator,
  ]
}

# ---------------------------------------------------------------------------
# EventBridge Rule — CloudTrail SecurityGroup Ingress Monitor
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "sg_ingress_monitor" {
  name        = "${var.project_name}-sg-ingress-monitor-${var.environment}"
  description = "Captures AuthorizeSecurityGroupIngress API calls via CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "invoke_remediator" {
  rule      = aws_cloudwatch_event_rule.sg_ingress_monitor.name
  target_id = "${var.project_name}-lambda-target"
  arn       = aws_lambda_function.remediator.arn
}

# ---------------------------------------------------------------------------
# Lambda Permission — Allow EventBridge to invoke the function
# ---------------------------------------------------------------------------

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_ingress_monitor.arn
}
