#!/usr/bin/env bash
# Two-minute local demo. Kept for old links: it now runs `snare demo`, which needs nothing
# but Go and works the same on Windows, macOS and Linux.
#
#   scripts/demo.sh            # then open http://127.0.0.1:18090 and paste the printed key
set -euo pipefail
cd "$(dirname "$0")/.."
exec go run ./cmd/snare demo "$@"
