output "instance_id" {
  description = "ID of the test EC2 instance."
  value       = aws_instance.sentinel_test.id
}

output "instance_public_ip" {
  description = "Public IP of the test EC2 instance."
  value       = aws_instance.sentinel_test.public_ip
}

output "security_group_id" {
  description = "ID of the intentionally permissive security group."
  value       = aws_security_group.sentinel_test.id
}

output "s3_bucket_name" {
  description = "Name of the test S3 bucket."
  value       = aws_s3_bucket.sentinel_test.bucket
}