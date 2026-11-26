resource "aws_route53_record" "service" {
  for_each = toset(["api", "app", "callback", "ns"])
  zone_id  = var.route53_zone_id
  name     = local.hosts[each.key]
  type     = "A"
  ttl      = 300
  records  = [aws_eip.main.public_ip]
}

# Delegate the callback zone to Snare's own DNS listener: any lookup of <token>.cb.<domain>
# reaches the instance, which is how DNS canaries fire even when HTTP egress is blocked.
resource "aws_route53_record" "callback_zone_ns" {
  zone_id = var.route53_zone_id
  name    = local.hosts.zone
  type    = "NS"
  ttl     = 300
  records = ["${local.hosts.ns}."]
}

# Only Let's Encrypt may issue for the service names.
resource "aws_route53_record" "caa" {
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "CAA"
  ttl     = 3600
  records = ["0 issue \"letsencrypt.org\""]
}
