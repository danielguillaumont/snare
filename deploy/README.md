# Deploying Snare (M4)

**Status: written and validated in CI, not yet applied.** The design and its reasoning are in
[docs/M4-saas.md](../docs/M4-saas.md#deployment-iac).

The deployment is one AWS node (SQLite). Caddy terminates TLS for three hostnames, and Snare
answers DNS for the callback zone itself.

| Name | Serves |
|---|---|
| `t.<domain>` | Callback HTTP: canary URLs, honey-credential base URLs |
| `api.<domain>` | Admin API (operator and tenant keys) |
| `app.<domain>` | Read-only dashboard |
| `cb.<domain>` | Zone NS-delegated to the instance, for DNS canaries |

## What you need

- An AWS account, and a Route 53 public hosted zone that contains `<domain>`.
- Terraform ≥ 1.9, the AWS CLI, `openssl`, `curl` and `jq`.
- A published image. Tagging `vX.Y.Z` runs `.github/workflows/release.yml`, which pushes
  `ghcr.io/danielguillaumont/snare:X.Y.Z`. Pin it by digest in `image`.
- From v0.4.1, release images are signed keylessly and carry an SBOM. Check one before
  deploying it:

  ```bash
  cosign verify ghcr.io/danielguillaumont/snare:X.Y.Z     --certificate-identity-regexp '^https://github.com/danielguillaumont/snare/.github/workflows/release.yml@refs/tags/v'     --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

Expected cost at the defaults: one t4g.small instance, 36 GB gp3 across the two volumes, an
Elastic IP, and snapshots. Check current pricing for your region before applying.

## Steps

```bash
export AWS_REGION=us-east-1
scripts/put-secrets.sh /snare/prod          # creates SNARE_KEY, SNARE_ADMIN_KEY, SNARE_SEAL_KEY; never overwrites

cd deploy/terraform
cat > terraform.tfvars <<'EOF'
domain          = "snare.example.com"
route53_zone_id = "Z0123456789EXAMPLE"
acme_email      = "security@example.com"
image           = "ghcr.io/danielguillaumont/snare:0.4.0"
EOF
terraform init
terraform plan -out plan.tfplan             # read it
terraform apply plan.tfplan
```

Boot takes a few minutes: package install, image pull, then ACME certificates. Then:

```bash
export SNARE_API=$(terraform output -raw api_url)
export SNARE_ADMIN_KEY=$(aws ssm get-parameter --with-decryption --name /snare/prod/SNARE_ADMIN_KEY --query Parameter.Value --output text)
../../scripts/smoke.sh                      # must print PASS
```

M4's "deployed with IaC" criterion is met when `smoke.sh` passes against a stack built by
`terraform apply` from a clean account.

## Operating it

- **Shell:** `aws ssm start-session --target $(terraform output -raw instance_id)`. There is
  no SSH.
- **Logs:** CloudWatch Logs group `/snare/<domain>`, streams `snare` and `caddy`. The boot
  script logs to `/var/log/snare-bootstrap.log`.
- **Upgrade:** change `image` and apply. The instance is replaced, and the data volume is
  reattached with tenants, tokens and certificates intact.
- **Backups:** DLM takes daily snapshots of the data volume (14 kept by default). The volume
  has `prevent_destroy`, so `terraform destroy` stops at the data on purpose.
- **Key rotation:** deliberately manual.
  - Rotating `SNARE_KEY` invalidates every minted token.
  - Rotating `SNARE_SEAL_KEY` requires re-creating every tenant sink.
  - `SNARE_ADMIN_KEY` can rotate freely. Secrets are read at boot, so update the parameter
    and then run `terraform apply -replace=aws_instance.snare`.
