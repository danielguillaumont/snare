#!/usr/bin/env bash
# Create the service secrets in SSM Parameter Store (SecureString), out of band from Terraform
# so they never appear in plan output or state.
#
#   AWS_REGION=us-east-1 scripts/put-secrets.sh [/snare/prod]
#
# Existing parameters are left alone. Rotating SNARE_KEY invalidates every minted token and
# rotating SNARE_SEAL_KEY makes every stored sink unreadable, so this script never overwrites;
# rotation is a deliberate, manual step.
set -euo pipefail
prefix=${1:-/snare/prod}
: "${AWS_REGION:?set AWS_REGION}"

umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

put() { # put <name> <hex bytes>
  local name=$prefix/$1
  if aws ssm get-parameter --name "$name" >/dev/null 2>&1; then
    echo "exists, kept: $name"
    return
  fi
  openssl rand -hex "$2" | tr -d '\n' >"$tmp/v"
  # file:// keeps the value out of the process list and shell history.
  aws ssm put-parameter --name "$name" --type SecureString --value "file://$tmp/v" >/dev/null
  echo "created: $name"
}

put SNARE_KEY 32
put SNARE_ADMIN_KEY 24
put SNARE_SEAL_KEY 32
echo "Read the operator key when you need it:"
echo "  aws ssm get-parameter --with-decryption --name $prefix/SNARE_ADMIN_KEY --query Parameter.Value --output text"
