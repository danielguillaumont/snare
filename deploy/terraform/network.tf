data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.40.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "snare" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.40.0.0/26"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false # the Elastic IP is the only public address
  tags                    = { Name = "snare-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Inbound: TLS (and HTTP for ACME + redirect) and DNS. No SSH: access is SSM Session Manager.
resource "aws_security_group" "snare" {
  name_prefix = "snare-"
  description = "Snare: HTTPS, HTTP (ACME), DNS"
  vpc_id      = aws_vpc.main.id
  lifecycle {
    create_before_destroy = true
  }
}

locals {
  ingress = {
    http    = { port = 80, proto = "tcp" }
    https   = { port = 443, proto = "tcp" }
    dns_udp = { port = 53, proto = "udp" }
    dns_tcp = { port = 53, proto = "tcp" }
  }
}

resource "aws_vpc_security_group_ingress_rule" "in" {
  for_each          = local.ingress
  security_group_id = aws_security_group.snare.id
  description       = each.key
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = each.value.proto
  from_port         = each.value.port
  to_port           = each.value.port
}

# Outbound is open: tenant sinks are customer-chosen HTTPS endpoints, plus ACME, the image
# registry and AWS APIs. The application enforces the SSRF policy (internal/egress); IMDS is
# unreachable from containers because the hop limit is 1.
resource "aws_vpc_security_group_egress_rule" "out" {
  security_group_id = aws_security_group.snare.id
  description       = "all outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
