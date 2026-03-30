variable "bucket_name" { type = string }
variable "tags"        { type = map(string) }

resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_public_access_block" "main" {
  bucket                  = aws_s3_bucket.main.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    id     = "expire-staging-after-14-days"
    status = "Enabled"
    filter {
      tag {
        key   = "lifecycle"
        value = "staging"
      }
    }
    expiration {
      days = 14
    }
  }
}

output "bucket_name" { value = aws_s3_bucket.main.bucket }
output "bucket_arn"  { value = aws_s3_bucket.main.arn }
