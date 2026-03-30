provider "aws" {
  region = var.aws_region
}

locals {
  name_prefix = var.name_prefix
  is_prod     = var.environment == "prod"
  tags = {
    Project     = var.name_prefix
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ------------------------------------------------------------------
# Data sources: existing resources (VPC, subnets, security groups)
# ------------------------------------------------------------------
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "ecs" {
  name        = "${local.name_prefix}-ecs"
  description = "ECS tasks — allow inbound on API (8000) and UI (8501) ports"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "platform-api"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "platform-ui (Streamlit)"
    from_port   = 8501
    to_port     = 8501
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# ------------------------------------------------------------------
# Modules
# ------------------------------------------------------------------
module "iam" {
  source      = "./modules/iam"
  name_prefix = local.name_prefix
  s3_bucket   = var.s3_bucket
  tags        = local.tags
}

module "ecr" {
  source      = "./modules/ecr"
  name_prefix = local.name_prefix
  tags        = local.tags
}

module "s3" {
  source      = "./modules/s3"
  bucket_name = var.s3_bucket
  tags        = local.tags
}

module "rds" {
  source      = "./modules/rds"
  name_prefix = local.name_prefix
  subnet_ids  = data.aws_subnets.default.ids
  vpc_id      = data.aws_vpc.default.id
  environment = var.environment
  tags        = local.tags
}

module "alb" {
  source      = "./modules/alb"
  name_prefix = local.name_prefix
  subnet_ids  = data.aws_subnets.default.ids
  vpc_id      = data.aws_vpc.default.id
  tags        = local.tags
}

module "ecs" {
  source              = "./modules/ecs"
  name_prefix         = local.name_prefix
  environment         = var.environment
  aws_region          = var.aws_region
  alb_dns             = module.alb.alb_dns
  ecr_api_uri         = module.ecr.platform_api_uri
  ecr_ui_uri          = module.ecr.platform_ui_uri
  ecr_image_tag       = var.ecr_image_tag
  execution_role_arn  = module.iam.execution_role_arn
  task_role_arn       = module.iam.task_role_arn
  subnet_ids          = data.aws_subnets.default.ids
  security_group_id   = aws_security_group.ecs.id
  alb_api_tg_arn      = module.alb.api_target_group_arn
  alb_ui_tg_arn       = module.alb.ui_target_group_arn
  db_secret_arn       = module.rds.secret_arn
  s3_bucket           = var.s3_bucket
  api_desired_count   = var.api_desired_count
  ui_desired_count    = var.ui_desired_count
  tags                = local.tags
}

module "monitoring" {
  source      = "./modules/monitoring"
  name_prefix = local.name_prefix
  aws_region  = var.aws_region
  alb_suffix  = module.alb.alb_suffix
  alert_email = var.alert_email
  tags        = local.tags
}
