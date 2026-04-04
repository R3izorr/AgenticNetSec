#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE_NAME="${AGENTIC_SANDBOX_IMAGE:-agenticnetsec-forensics-sandbox}"

docker build -t "${IMAGE_NAME}" -f "${PROJECT_ROOT}/backend/sandbox/Dockerfile" "${PROJECT_ROOT}"
