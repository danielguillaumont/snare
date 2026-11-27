#!/usr/bin/env bash
# Builds static snare binaries for every release target into dist/, plus SHA256SUMS.
# Used by .github/workflows/release.yml on a tag, and by CI (with VERSION=ci) on every PR so
# a broken target fails before a release does (docs/M4f-distribution.md section 1).
#
#   VERSION=0.9.0 scripts/build-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."
version=${VERSION:?set VERSION}
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
rm -rf dist && mkdir -p dist
for t in $targets; do
  os=${t%/*} arch=${t#*/}
  name="snare_${version}_${os}_${arch}"
  exe=snare; [ "$os" = windows ] && exe=snare.exe
  mkdir -p "dist/$name"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X github.com/danielguillaumont/snare/internal/alert.ProductVersion=$version" \
    -o "dist/$name/$exe" ./cmd/snare
  cp LICENSE README.md "dist/$name/"
  if [ "$os" = windows ]; then
    (cd dist && zip -qr "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "dist/$name"
done
(cd dist && sha256sum ./*.tar.gz ./*.zip | sed 's# \./# #' > SHA256SUMS)
cat dist/SHA256SUMS
