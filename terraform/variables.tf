variable "aws_region" {
  description = "AWS region to deploy the test environment into."
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Prefix used to name and tag all resources created by this test environment."
  type        = string
  default     = "sentinel-test"
}

variable "instance_type" {
  description = "EC2 instance type. Keep this free-tier eligible."
  type        = string
  default     = "t3.micro"
}