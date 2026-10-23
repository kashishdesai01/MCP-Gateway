#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .local/bin
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=darwin-11.0-arm64 ;;
  Darwin-x86_64) platform=darwin-10.9-amd64 ;;
  Linux-x86_64) platform=linux-amd64 ;;
  Linux-aarch64) platform=linux-arm64 ;;
  *) echo 'Use Docker Compose for this platform.'; exit 1 ;;
esac
curl -fL "https://binaries.cockroachdb.com/cockroach-v25.2.4.${platform}.tgz" -o .local/cockroach.tgz
tar -xzf .local/cockroach.tgz -C .local/bin --strip-components=1
.local/bin/cockroach version
