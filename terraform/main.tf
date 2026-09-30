# main.tf
#
# OPTIONAL: Provisions a small, deliberately misconfigured AWS sandbox
# so the scanner can be run with --live against real findings instead
# of mock data.
#
# ⚠️  WARNING: This intentionally creates INSECURE resources (public
# bucket, open security group). Only run this in a disposable/sandbox
# AWS account, never in production. Destroy immediately after testing:
#     terraform destroy
#
# Usage:
#   terraform init
#   terraform apply
#   cd ../scanner && python main.py --live
#   cd ../terraform && terraform destroy

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# --- Intentionally public S3 bucket (for S3-001 finding) ---
resource "aws_s3_bucket" "public_demo" {
  bucket = "misconfig-triage-demo-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "public_demo" {
  bucket                  = aws_s3_bucket.public_demo.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public_demo" {
  depends_on = [aws_s3_bucket_ownership_controls.public_demo]
  bucket     = aws_s3_bucket.public_demo.id
  acl        = "public-read"
}

resource "aws_s3_bucket_ownership_controls" "public_demo" {
  bucket = aws_s3_bucket.public_demo.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# --- Intentionally open security group (for SG-001 finding) ---
resource "aws_security_group" "open_ssh_demo" {
  name        = "misconfig-triage-demo-sg"
  description = "Demo SG with SSH open to the world — DO NOT use in production"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Unencrypted EBS volume (for EBS-001 finding) ---
resource "aws_ebs_volume" "unencrypted_demo" {
  availability_zone = "us-east-1a"
  size               = 8
  encrypted          = false
}

resource "random_id" "suffix" {
  byte_length = 4
}

output "bucket_name" {
  value = aws_s3_bucket.public_demo.id
}

output "security_group_id" {
  value = aws_security_group.open_ssh_demo.id
}
