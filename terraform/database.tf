# =============================================================================
# CloudWatchDog — DynamoDB Table
# =============================================================================

resource "aws_dynamodb_table" "drift_logs" {
  name         = "cloudwatchdog-drift-logs-prod"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "EventId"
  range_key    = "Timestamp"

  attribute {
    name = "EventId"
    type = "S"
  }

  attribute {
    name = "Timestamp"
    type = "S"
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "AuditLogs"
  }
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.drift_logs.name
}

output "dynamodb_table_arn" {
  value = aws_dynamodb_table.drift_logs.arn
}
