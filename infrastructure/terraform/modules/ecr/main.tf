variable "name_prefix" { type = string }
variable "tags"        { type = map(string) }

resource "aws_ecr_repository" "platform_api" {
  name                 = "${var.name_prefix}/platform-api"
  image_tag_mutability = "MUTABLE"
  tags                 = var.tags
}

resource "aws_ecr_repository" "platform_ui" {
  name                 = "${var.name_prefix}/platform-ui"
  image_tag_mutability = "MUTABLE"
  tags                 = var.tags
}

resource "aws_ecr_lifecycle_policy" "platform_api" {
  repository = aws_ecr_repository.platform_api.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 1 day"
        selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 1 }
        action       = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 5 tagged images"
        selection    = { tagStatus = "tagged", tagPrefixList = ["v", "latest"], countType = "imageCountMoreThan", countNumber = 5 }
        action       = { type = "expire" }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "platform_ui" {
  repository = aws_ecr_repository.platform_ui.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged after 1 day"
        selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 1 }
        action       = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 5 tagged"
        selection    = { tagStatus = "tagged", tagPrefixList = ["v", "latest"], countType = "imageCountMoreThan", countNumber = 5 }
        action       = { type = "expire" }
      }
    ]
  })
}

output "platform_api_uri" { value = aws_ecr_repository.platform_api.repository_url }
output "platform_ui_uri"  { value = aws_ecr_repository.platform_ui.repository_url }
