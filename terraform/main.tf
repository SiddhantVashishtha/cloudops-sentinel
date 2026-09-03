terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = "terraform-deployer"
}

# --- Networking: a minimal VPC just for this test environment ---

resource "aws_vpc" "sentinel_test" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_name}-vpc"
    Purpose = "CloudOps Sentinel demo environment"
  }
}

resource "aws_subnet" "sentinel_test" {
  vpc_id                  = aws_vpc.sentinel_test.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-subnet"
  }
}

resource "aws_internet_gateway" "sentinel_test" {
  vpc_id = aws_vpc.sentinel_test.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_route_table" "sentinel_test" {
  vpc_id = aws_vpc.sentinel_test.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sentinel_test.id
  }

  tags = {
    Name = "${var.project_name}-rt"
  }
}

resource "aws_route_table_association" "sentinel_test" {
  subnet_id      = aws_subnet.sentinel_test.id
  route_table_id = aws_route_table.sentinel_test.id
}

# --- Security Group: INTENTIONALLY misconfigured ---
# SSH is open to 0.0.0.0/0 on purpose, so Sentinel has a real finding
# to detect. This is the demo's "bug" — fixed later in the walkthrough.

resource "aws_security_group" "sentinel_test" {
  name        = "${var.project_name}-sg"
  description = "Intentionally permissive SG for CloudOps Sentinel demo"
  vpc_id      = aws_vpc.sentinel_test.id

    ingress {
    description = "SSH restricted to trusted CIDR (FIXED - was 0.0.0.0/0)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-sg"
  }
}

# --- EC2 instance ---

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "sentinel_test" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.sentinel_test.id
  vpc_security_group_ids = [aws_security_group.sentinel_test.id]

  tags = {
    Name = "${var.project_name}-instance"
  }
}

# --- S3 bucket ---
# Bucket name includes account ID + random suffix to guarantee global uniqueness.

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "sentinel_test" {
  bucket = "${var.project_name}-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "${var.project_name}-bucket"
  }
}