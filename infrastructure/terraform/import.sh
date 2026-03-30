#!/usr/bin/env bash
# Run this ONCE after `terraform init` to import existing AWS resources into state.
# Usage: cd infrastructure/terraform && bash import.sh

set -euo pipefail

VAR_FILE="environments/prod/terraform.tfvars"

echo "=== Importing existing AWS resources into Terraform state ==="

# Security group (now managed by Terraform — import the existing one)
terraform import -var-file="$VAR_FILE" \
  aws_security_group.ecs \
  sg-0354bbb0e4cc5c8a2

terraform import -var-file="$VAR_FILE" \
  module.ecr.aws_ecr_repository.platform_api \
  cai-platform/platform-api

terraform import -var-file="$VAR_FILE" \
  module.ecr.aws_ecr_repository.platform_ui \
  cai-platform/platform-ui

terraform import -var-file="$VAR_FILE" \
  module.s3.aws_s3_bucket.main \
  egslatam-cai-dev

terraform import -var-file="$VAR_FILE" \
  module.rds.aws_db_instance.main \
  cai-platform-db

terraform import -var-file="$VAR_FILE" \
  module.ecs.aws_ecs_cluster.main \
  cai-platform

terraform import -var-file="$VAR_FILE" \
  module.ecs.aws_ecs_service.api \
  cai-platform/platform-api

terraform import -var-file="$VAR_FILE" \
  module.ecs.aws_ecs_service.ui \
  cai-platform/platform-ui

terraform import -var-file="$VAR_FILE" \
  module.iam.aws_iam_role.execution \
  cai-platform-ecs-execution-role

terraform import -var-file="$VAR_FILE" \
  module.iam.aws_iam_role.task \
  cai-platform-ecs-task-role

terraform import -var-file="$VAR_FILE" \
  module.iam.aws_iam_user.github_ci \
  github-ci

echo ""
echo "=== Import complete. Run 'terraform plan' to review drift ==="
