variable "name_prefix" { type = string }
variable "aws_region"  { type = string }
variable "alb_suffix"  { type = string }
variable "alert_email" { type = string }
variable "tags"        { type = map(string) }

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "api_task_down" {
  alarm_name          = "${var.name_prefix}-api-task-down"
  alarm_description   = "platform-api has no running tasks"
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  dimensions          = { ClusterName = var.name_prefix, ServiceName = "platform-api" }
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "breaching"
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.name_prefix}-alb-5xx-high"
  alarm_description   = "ALB returning too many 5xx errors"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  dimensions          = { LoadBalancer = var.alb_suffix }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name_prefix}-rds-cpu-high"
  alarm_description   = "RDS CPU over 80%"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  dimensions          = { DBInstanceIdentifier = "${var.name_prefix}-db" }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "missing"
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.name_prefix}-rds-storage-low"
  alarm_description   = "RDS free storage below 2GB"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  dimensions          = { DBInstanceIdentifier = "${var.name_prefix}-db" }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 1
  threshold           = 2147483648
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "missing"
  tags                = var.tags
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.name_prefix
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text", x = 0, y = 0, width = 24, height = 1
        properties = { markdown = "# CAI Platform — Operations Dashboard" }
      },
      {
        type = "metric", x = 0, y = 1, width = 8, height = 6
        properties = {
          title  = "ECS — Running Tasks", region = var.aws_region
          metrics = [["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", var.name_prefix, "ServiceName", "platform-api"]]
          period = 60, stat = "Average", view = "timeSeries"
          annotations = { horizontal = [{ value = 1, label = "Min healthy", color = "#d13212" }] }
        }
      },
      {
        type = "metric", x = 8, y = 1, width = 8, height = 6
        properties = {
          title = "ALB — Request Count", region = var.aws_region
          metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_suffix]]
          period = 300, stat = "Sum", view = "timeSeries"
          annotations = { horizontal = [] }
        }
      },
      {
        type = "metric", x = 16, y = 1, width = 8, height = 6
        properties = {
          title = "RDS — CPU Utilization", region = var.aws_region
          metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", "${var.name_prefix}-db"]]
          period = 300, stat = "Average", view = "timeSeries"
          annotations = { horizontal = [{ value = 80, label = "80% threshold", color = "#ff7f0e" }] }
        }
      },
      {
        type = "alarm", x = 0, y = 7, width = 24, height = 4
        properties = {
          title = "Alarm Status"
          alarms = [
            aws_cloudwatch_metric_alarm.api_task_down.arn,
            aws_cloudwatch_metric_alarm.alb_5xx.arn,
            aws_cloudwatch_metric_alarm.rds_cpu.arn,
            aws_cloudwatch_metric_alarm.rds_storage.arn
          ]
        }
      }
    ]
  })
}

output "dashboard_name" { value = aws_cloudwatch_dashboard.main.dashboard_name }
output "sns_topic_arn"  { value = aws_sns_topic.alerts.arn }
