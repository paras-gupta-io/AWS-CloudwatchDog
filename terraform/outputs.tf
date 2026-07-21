# =============================================================================
# CloudWatchDog — Outputs
# Infrastructure Configuration Drift & Automated Security Remediation
# =============================================================================

output "lambda_function_arn" {
  description = "ARN of the CloudWatchDog remediation Lambda function"
  value       = aws_lambda_function.remediator.arn
}

output "lambda_function_name" {
  description = "Name of the deployed Lambda function"
  value       = aws_lambda_function.remediator.function_name
}

output "lambda_role_arn" {
  description = "ARN of the IAM execution role attached to the Lambda"
  value       = aws_iam_role.lambda_exec.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule monitoring SecurityGroup changes"
  value       = aws_cloudwatch_event_rule.sg_ingress_monitor.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for Lambda execution logs"
  value       = aws_cloudwatch_log_group.remediator.name
}

# ---------------------------------------------------------------------------
# Static Documentation Site Outputs
# ---------------------------------------------------------------------------

output "docs_site_url" {
  description = "URL of the documentation site"
  value       = "https://${var.domain_name}"
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (use for cache invalidation)"
  value       = aws_cloudfront_distribution.docs_site.id
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.docs_site.domain_name
}

output "s3_docs_bucket" {
  description = "S3 bucket name for documentation site files"
  value       = aws_s3_bucket.docs_site.id
}

