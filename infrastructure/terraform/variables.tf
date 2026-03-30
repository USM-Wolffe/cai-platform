variable "name_prefix" {
  description = "Prefix for all resource names (e.g. 'cai-platform'). Change per deployment target."
  type        = string
  default     = "cai-platform"
}

variable "environment" {
  description = "Deployment environment: prod or staging"
  type        = string
  validation {
    condition     = contains(["prod", "staging"], var.environment)
    error_message = "environment must be 'prod' or 'staging'."
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "ecr_image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "api_desired_count" {
  description = "Number of platform-api ECS tasks to run"
  type        = number
  default     = 1
}

variable "ui_desired_count" {
  description = "Number of platform-ui ECS tasks to run"
  type        = number
  default     = 1
}

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
}

variable "s3_bucket" {
  description = "S3 bucket for workspaces and reference data (must exist or be created by this module)"
  type        = string
}
