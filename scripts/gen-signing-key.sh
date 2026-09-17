#!/usr/bin/env bash
# Generates a new Ed25519 signing key pair and stores it as the
# model-signing-key Secret (private half) and the model-signing-public-key
# ConfigMap (public half). The pair is generated with the already-built
# producer image so the script has no local Python dependency, and the
# private key is never written to a file on disk: `signing-keygen` prints
# both PEMs to stdout, and the split into private/public happens entirely
# in shell variables.
set -euo pipefail

NAMESPACE="${NAMESPACE:-confidential-models}"
PRODUCER_TAG="model-pipeline-producer:local"

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "Generating a new Ed25519 signing key pair with ${PRODUCER_TAG}..."
KEYPAIR="$(docker run --rm "${PRODUCER_TAG}" signing-keygen)"

PRIVATE_KEY="$(awk '/^# private key/{flag=1;next}/^# public key/{flag=0}flag' <<<"${KEYPAIR}")"
PUBLIC_KEY="$(awk '/^# public key/{flag=1;next}flag' <<<"${KEYPAIR}")"

kubectl -n "${NAMESPACE}" create secret generic model-signing-key \
    --from-literal=signing-key.pem="${PRIVATE_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "${NAMESPACE}" create configmap model-signing-public-key \
    --from-literal=public-key.pem="${PUBLIC_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "Secret model-signing-key and ConfigMap model-signing-public-key created/updated in namespace ${NAMESPACE}."

FINGERPRINT="$(docker run --rm -i --entrypoint python "${PRODUCER_TAG}" -c "
import sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from model_pipeline.signing import public_key_fingerprint
print(public_key_fingerprint(load_pem_public_key(sys.stdin.buffer.read())))
" <<<"${PUBLIC_KEY}")"

echo "Public key fingerprint: ${FINGERPRINT}"
