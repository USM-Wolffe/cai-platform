variable "name_prefix" { type = string }
variable "s3_bucket"   { type = string }
variable "tags"        { type = map(string) }

# ECS Execution Role (pull images, read secrets, write logs)
resource "aws_iam_role" "execution" {
  name = "${var.name_prefix}-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_base" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "execution_secrets" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

# ECS Task Role (Bedrock + S3 access at runtime)
resource "aws_iam_role" "task" {
  name = "${var.name_prefix}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "task_bedrock_s3" {
  name = "bedrock-s3-access"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"]
        Resource = [
          "arn:aws:s3:::${var.s3_bucket}",
          "arn:aws:s3:::${var.s3_bucket}/*"
        ]
      }
    ]
  })
}

# GitHub CI user policy
resource "aws_iam_user" "github_ci" {
  name = "github-ci"
  tags = var.tags
}

resource "aws_iam_policy" "github_ci" {
  name        = "${var.name_prefix}-github-ci"
  description = "Permisos mínimos para GitHub Actions CI/CD de cai-platform"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRRepos"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage", "ecr:PutImage", "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories", "ecr:ListImages", "ecr:DescribeImages"
        ]
        Resource = [
          "arn:aws:ecr:*:*:repository/${var.name_prefix}/platform-api",
          "arn:aws:ecr:*:*:repository/${var.name_prefix}/platform-ui"
        ]
      },
      {
        Sid    = "ECSDeployApi"
        Effect = "Allow"
        Action = [
          "ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition",
          "ecs:UpdateService", "ecs:DescribeServices", "ecs:ListServices"
        ]
        Resource = "*"
      },
      {
        Sid    = "PassRoles"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.execution.arn,
          aws_iam_role.task.arn
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "github_ci" {
  user       = aws_iam_user.github_ci.name
  policy_arn = aws_iam_policy.github_ci.arn
}

output "execution_role_arn" { value = aws_iam_role.execution.arn }
output "task_role_arn"      { value = aws_iam_role.task.arn }
