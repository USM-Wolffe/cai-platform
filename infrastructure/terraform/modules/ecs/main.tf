variable "name_prefix"            { type = string }
variable "environment"            { type = string }
variable "aws_region"             { type = string }
variable "alb_dns"                { type = string }
variable "ecr_api_uri"            { type = string }
variable "ecr_ui_uri"             { type = string }
variable "ecr_image_tag"          { type = string }
variable "execution_role_arn"     { type = string }
variable "task_role_arn"          { type = string }
variable "subnet_ids"             { type = list(string) }
variable "security_group_id"      { type = string }
variable "alb_api_tg_arn"         { type = string }
variable "alb_ui_tg_arn"          { type = string }
variable "alb_api_staging_tg_arn" { type = string }
variable "alb_ui_staging_tg_arn"  { type = string }
variable "s3_bucket"              { type = string }
variable "api_desired_count"      { type = number }
variable "ui_desired_count"       { type = number }
variable "tags"                   { type = map(string) }

locals {
  is_prod    = var.environment == "prod"
  svc_suffix = local.is_prod ? "" : "-${var.environment}"
  log_prefix = local.is_prod ? "ecs" : var.environment
}

resource "aws_ecs_cluster" "main" {
  name = var.name_prefix
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/${var.name_prefix}-api"
  retention_in_days = 30
  tags              = var.tags
}

# ------------------------------------------------------------------
# platform-api  (prod)
# ------------------------------------------------------------------
resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name_prefix}-api${local.svc_suffix}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 2048
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name      = "platform-api"
    image     = "${var.ecr_api_uri}:${var.ecr_image_tag}"
    essential = true
    portMappings = [{ containerPort = 8000, hostPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "PLATFORM_API_HOST", value = "0.0.0.0" },
      { name = "PLATFORM_API_PORT", value = "8000" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.main.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = local.log_prefix
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 15
    }
  }])
}

resource "aws_ecs_service" "api" {
  name            = "platform-api${local.svc_suffix}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = var.alb_api_tg_arn
    container_name   = "platform-api"
    container_port   = 8000
  }

  tags = var.tags
}

# ------------------------------------------------------------------
# platform-api  (staging) — desired_count=0; CI scales up during deploy
# ------------------------------------------------------------------
resource "aws_ecs_task_definition" "api_staging" {
  family                   = "${var.name_prefix}-api-staging"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 2048
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name      = "platform-api"
    image     = "${var.ecr_api_uri}:${var.ecr_image_tag}"
    essential = true
    portMappings = [{ containerPort = 8000, hostPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "PLATFORM_API_HOST", value = "0.0.0.0" },
      { name = "PLATFORM_API_PORT", value = "8000" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.main.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "staging"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 15
    }
  }])
}

resource "aws_ecs_service" "api_staging" {
  name            = "platform-api-staging"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api_staging.arn
  desired_count   = 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = var.alb_api_staging_tg_arn
    container_name   = "platform-api"
    container_port   = 8000
  }

  tags = var.tags
}

# ------------------------------------------------------------------
# platform-ui  (prod)
# ------------------------------------------------------------------
resource "aws_ecs_task_definition" "ui" {
  family                   = "${var.name_prefix}-ui${local.svc_suffix}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name      = "platform-ui"
    image     = "${var.ecr_ui_uri}:${var.ecr_image_tag}"
    essential = true
    portMappings = [{ containerPort = 8501, hostPort = 8501, protocol = "tcp" }]
    environment = [
      { name = "PLATFORM_API_BASE_URL", value = "http://${var.alb_dns}" },
      { name = "CAI_MODEL",             value = "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" },
      { name = "CAI_AGENT_TYPE",        value = "egs-analist" },
      { name = "WATCHGUARD_S3_BUCKET",  value = var.s3_bucket },
      { name = "WATCHGUARD_S3_REGION",  value = var.aws_region }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.main.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "${local.log_prefix}-ui"
      }
    }
  }])
}

resource "aws_ecs_service" "ui" {
  name            = "platform-ui${local.svc_suffix}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.ui.arn
  desired_count   = var.ui_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = var.alb_ui_tg_arn
    container_name   = "platform-ui"
    container_port   = 8501
  }

  tags = var.tags
}

# ------------------------------------------------------------------
# platform-ui  (staging) — desired_count=0; CI scales up during deploy
# ------------------------------------------------------------------
resource "aws_ecs_task_definition" "ui_staging" {
  family                   = "${var.name_prefix}-ui-staging"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name      = "platform-ui"
    image     = "${var.ecr_ui_uri}:${var.ecr_image_tag}"
    essential = true
    portMappings = [{ containerPort = 8501, hostPort = 8501, protocol = "tcp" }]
    environment = [
      { name = "PLATFORM_API_BASE_URL", value = "http://${var.alb_dns}/staging" },
      { name = "CAI_MODEL",             value = "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" },
      { name = "CAI_AGENT_TYPE",        value = "egs-analist" },
      { name = "WATCHGUARD_S3_BUCKET",  value = var.s3_bucket },
      { name = "WATCHGUARD_S3_REGION",  value = var.aws_region }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.main.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "staging-ui"
      }
    }
  }])
}

resource "aws_ecs_service" "ui_staging" {
  name            = "platform-ui-staging"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.ui_staging.arn
  desired_count   = 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = var.alb_ui_staging_tg_arn
    container_name   = "platform-ui"
    container_port   = 8501
  }

  tags = var.tags
}
