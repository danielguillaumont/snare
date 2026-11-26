output "public_ip" {
  value = aws_eip.main.public_ip
}

output "api_url" {
  value = "https://${local.hosts.api}"
}

output "dashboard_url" {
  value = "https://${local.hosts.app}"
}

output "callback_url" {
  value = "https://${local.hosts.callback}"
}

output "callback_zone" {
  value = local.hosts.zone
}

output "instance_id" {
  description = "For aws ssm start-session --target <id>."
  value       = aws_instance.snare.id
}
