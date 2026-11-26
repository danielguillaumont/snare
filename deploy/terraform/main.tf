locals {
  hosts = {
    api      = "api.${var.domain}"
    app      = "app.${var.domain}"
    callback = "t.${var.domain}"
    ns       = "ns.${var.domain}"
    zone     = "cb.${var.domain}"
  }
}

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_cloudwatch_log_group" "snare" {
  name              = "/snare/${var.domain}"
  retention_in_days = var.log_retention_days
}

resource "aws_eip" "main" {
  domain = "vpc"
  tags   = { Name = "snare" }
}

# Database and ACME state live on their own volume so the instance can be replaced (new AMI,
# changed user data) without losing tenants, tokens or certificates.
resource "aws_ebs_volume" "data" {
  availability_zone = aws_subnet.public.availability_zone
  size              = var.data_volume_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "snare-data", SnareBackup = "daily" }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "snare" {
  ami                         = data.aws_ssm_parameter.al2023_arm64.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.snare.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region         = var.region
    image          = var.image
    ssm_prefix     = var.ssm_prefix
    log_group      = aws_cloudwatch_log_group.snare.name
    acme_email     = var.acme_email
    answer_ip      = aws_eip.main.public_ip
    api_host       = local.hosts.api
    app_host       = local.hosts.app
    callback_host  = local.hosts.callback
    zone           = local.hosts.zone
    data_volume_id = aws_ebs_volume.data.id
    caddyfile      = file("${path.module}/../Caddyfile")
  })

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # containers can't reach IMDS
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
  }

  tags = { Name = "snare" }

  lifecycle {
    ignore_changes = [ami] # AMI updates are a deliberate replace, not a side effect of plan
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.snare.id
}

resource "aws_eip_association" "main" {
  allocation_id = aws_eip.main.id
  instance_id   = aws_instance.snare.id
}

resource "aws_dlm_lifecycle_policy" "data" {
  description        = "snare data volume, daily"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { SnareBackup = "daily" }
    schedule {
      name      = "daily"
      copy_tags = true
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["04:00"]
      }
      retain_rule {
        count = var.snapshot_retain_days
      }
    }
  }
}
