terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # IMPORTANT: The backend block does NOT support variables — these values must be
  # edited directly when deploying to a different AWS account or region.
  # Per-account checklist:
  #   1. bucket         → S3 bucket en la cuenta destino (debe existir antes de terraform init)
  #   2. region         → región del bucket de estado
  #   3. dynamodb_table → tabla DynamoDB para locks (debe existir: make tf-locks-table)
  backend "s3" {
    bucket         = "egslatam-cai-dev"
    key            = "terraform/cai-platform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "cai-platform-tf-locks"
    encrypt        = true
  }
}
