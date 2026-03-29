#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 /path/to/file.pcap [extra tshark args...]" >&2
  exit 1
fi

PCAP_PATH="$(realpath "$1")"
shift

IMAGE_NAME="${AGENTIC_SANDBOX_IMAGE:-agenticnetsec-forensics-sandbox}"
PCAP_DIR="$(dirname "${PCAP_PATH}")"
PCAP_FILE="$(basename "${PCAP_PATH}")"

docker run --rm \
  -v "${PCAP_DIR}:/case:ro" \
  "${IMAGE_NAME}" \
  tshark -r "/case/${PCAP_FILE}" "$@"
