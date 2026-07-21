# =============================================================================
# CloudWatchDog — Configurable Variables
# Infrastructure Configuration Drift & Automated Security Remediation
# =============================================================================

variable "aws_region" {
  description = "AWS region to deploy CloudWatchDog resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project identifier used for resource naming and tagging"
  type        = string
  default     = "cloudwatchdog"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "lambda_runtime" {
  description = "Python runtime version for the Lambda function"
  type        = string
  default     = "python3.12"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_memory_size" {
  description = "Lambda function memory allocation in MB"
  type        = number
  default     = 128
}

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL for remediation notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_slack_notifications" {
  description = "Toggle Slack notification delivery"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "domain_name" {
  description = "Domain name for the documentation site"
  type        = string
  default     = "awsjourney.space"
}

variable "route53_zone_id" {
  description = "Route53 Hosted Zone ID for the domain"
  type        = string
  default     = "Z08756462VZTTWZ0DIJPR"
}

variable "tags" {
  description = "Additional resource tags merged with default project tags"
  type        = map(string)
  default     = {}
}
