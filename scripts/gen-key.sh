#!/usr/bin/env bash
# Generates a new AES-256 master key and stores it as the
# model-encryption-key Secret. The key is
# generated with the already-built producer image so the script has no
# local Python dependency, and it is never written to a file on disk.
set -euo pipefail

NAMESPACE="${NAMESPACE:-confidential-models}"
PRODUCER_TAG="model-pipeline-producer:local"

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "Generating a new master key with ${PRODUCER_TAG}..."
KEY="$(docker run --rm "${PRODUCER_TAG}" keygen)"

kubectl -n "${NAMESPACE}" create secret generic model-encryption-key \
    --from-literal=encryption-key="${KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "Secret model-encryption-key created/updated in namespace ${NAMESPACE}."
