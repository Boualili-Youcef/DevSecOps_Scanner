#!/usr/bin/env bash
set -euo pipefail

# Version et empreinte vérifiées auprès de la publication officielle GitHub.
version="0.76.1"
empreinte="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"

mkdir -p .tools
curl -fsSL --retry 2 --max-time 300 \
  "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-64bit.tar.gz" \
  -o .tools/trivy.tar.gz

echo "${empreinte}  .tools/trivy.tar.gz" | sha256sum --check --strict
tar -xzf .tools/trivy.tar.gz -C .tools trivy
.tools/trivy --version
