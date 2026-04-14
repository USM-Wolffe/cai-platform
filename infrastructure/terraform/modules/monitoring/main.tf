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

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.name_prefix
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text", x = 0, y = 0, width = 24, height = 1
        properties = { markdown = "# CAI Platform — Operations Dashboard" }
      },
      {
        type = "metric", x = 0, y = 1, width = 12, height = 6
        properties = {
          title   = "ECS — Running Tasks", region = var.aws_region
          metrics = [["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", var.name_prefix, "ServiceName", "platform-api"]]
          period  = 60, stat = "Average", view = "timeSeries"
          annotations = { horizontal = [{ value = 1, label = "Min healthy", color = "#d13212" }] }
        }
      },
      {
        type = "metric", x = 12, y = 1, width = 12, height = 6
        properties = {
          title   = "ALB — Request Count", region = var.aws_region
          metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_suffix]]
          period  = 300, stat = "Sum", view = "timeSeries"
          annotations = { horizontal = [] }
        }
      },
      {
        type = "alarm", x = 0, y = 7, width = 24, height = 4
        properties = {
          title  = "Alarm Status"
          alarms = [
            aws_cloudwatch_metric_alarm.api_task_down.arn,
            aws_cloudwatch_metric_alarm.alb_5xx.arn
          ]
        }
      }
    ]
  })
}

output "dashboard_name" { value = aws_cloudwatch_dashboard.main.dashboard_name }
output "sns_topic_arn"  { value = aws_sns_topic.alerts.arn }
