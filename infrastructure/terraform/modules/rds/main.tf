variable "name_prefix" { type = string }
variable "subnet_ids"  { type = list(string) }
variable "vpc_id"      { type = string }
variable "environment" { type = string }
variable "tags"        { type = map(string) }

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-rds-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${var.name_prefix}/db-credentials"
  description = "RDS credentials for cai-platform"
  tags        = var.tags
}

resource "aws_db_instance" "main" {
  identifier              = "${var.name_prefix}-db"
  engine                  = "postgres"
  engine_version          = "16"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  db_name                 = "caiplatform"
  username                = "caiplatform"
  # Password managed via Secrets Manager — set via aws_secretsmanager_secret_version
  manage_master_user_password = true
  db_subnet_group_name    = aws_db_subnet_group.main.name
  publicly_accessible     = false
  skip_final_snapshot     = var.environment != "prod"
  backup_retention_period = 1  # Free tier max; upgrade to 7 in paid tier
  storage_encrypted       = true
  tags                    = var.tags
}

output "endpoint"   { value = aws_db_instance.main.endpoint }
output "secret_arn" { value = aws_db_instance.main.master_user_secret[0].secret_arn }
