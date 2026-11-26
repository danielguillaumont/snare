variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "domain" {
  description = "Base name for the service, inside the Route 53 zone (for example snare.example.com). Creates api., app., t., ns. and the delegated cb. zone under it."
  type        = string
}

variable "route53_zone_id" {
  description = "ID of the existing public hosted zone that contains var.domain."
  type        = string
}

variable "acme_email" {
  description = "Contact address Caddy registers with Let's Encrypt."
  type        = string
}

variable "image" {
  description = "Snare container image. Pin a digest in production (image@sha256:...)."
  type        = string
  default     = "ghcr.io/danielguillaumont/snare:0.4.0"
}

variable "instance_type" {
  description = "Graviton instance type. SQLite on one node; t4g.small is plenty for design partners."
  type        = string
  default     = "t4g.small"
}

variable "data_volume_gb" {
  description = "Size of the encrypted EBS volume holding the database and ACME state."
  type        = number
  default     = 20
}

variable "ssm_prefix" {
  description = "SSM Parameter Store path holding the secrets (SNARE_KEY, SNARE_ADMIN_KEY, SNARE_SEAL_KEY). Created out of band by scripts/put-secrets.sh so they never enter Terraform state."
  type        = string
  default     = "/snare/prod"
}

variable "snapshot_retain_days" {
  description = "Daily EBS snapshots of the data volume, kept this many days."
  type        = number
  default     = 14
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for container logs."
  type        = number
  default     = 30
}
