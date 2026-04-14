output "alb_dns" {
  description = "Public DNS of the Application Load Balancer"
  value       = module.alb.alb_dns
}

output "ecr_platform_api_uri" {
  description = "ECR URI for platform-api"
  value       = module.ecr.platform_api_uri
}

output "ecr_platform_ui_uri" {
  description = "ECR URI for platform-ui"
  value       = module.ecr.platform_ui_uri
}


output "cloudwatch_dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${module.monitoring.dashboard_name}"
}
