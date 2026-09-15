#!/usr/bin/env bash
# End-to-end, reproducible walkthrough of the pipeline on minikube: builds
# both images, provisions the namespace and Secrets, runs the producer Job
# to publish an encrypted model, then runs the consumer Pod to decrypt and
# load it. Requires HF_TOKEN to be set in the environment (a token with
# write access to the target Hugging Face repo).
#
# The target repo and version are the ones baked into k8s/producer-job.yaml
# and k8s/consumer-pod.yaml. The producer refuses to overwrite a version
# that already exists, so re-running this script against a version already
# published under that repo fails at the producer step; bump MODEL_VERSION
# in both manifests (or point MODEL_REPO_ID at your own repo) to reproduce
# the demo from scratch.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-confidential-models}"

if [ -z "${HF_TOKEN:-}" ]; then
    echo "HF_TOKEN must be set (a Hugging Face token with write access to the target repo)." >&2
    exit 1
fi

if ! minikube status >/dev/null 2>&1; then
    echo "Starting minikube..."
    minikube start --memory=4096
fi

echo "== Building images =="
"${REPO_ROOT}/scripts/build-images.sh"

echo "== Provisioning namespace and service account =="
kubectl apply -f "${REPO_ROOT}/k8s/namespace.yaml"
kubectl apply -f "${REPO_ROOT}/k8s/serviceaccount.yaml"

echo "== Provisioning secrets =="
"${REPO_ROOT}/scripts/gen-key.sh"
kubectl -n "${NAMESPACE}" create secret generic hf-credentials \
    --from-literal=hf-token="${HF_TOKEN}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "== Running the producer job =="
kubectl -n "${NAMESPACE}" delete job model-producer --ignore-not-found
kubectl apply -f "${REPO_ROOT}/k8s/producer-job.yaml"
if ! kubectl -n "${NAMESPACE}" wait --for=condition=complete --timeout=300s job/model-producer; then
    echo "producer job did not complete; last logs:" >&2
    kubectl -n "${NAMESPACE}" logs job/model-producer >&2 || true
    exit 1
fi
kubectl -n "${NAMESPACE}" logs job/model-producer

echo "== Running the consumer pod =="
kubectl -n "${NAMESPACE}" delete pod model-consumer --ignore-not-found
kubectl apply -f "${REPO_ROOT}/k8s/consumer-pod.yaml"
kubectl -n "${NAMESPACE}" wait --for=condition=ready --timeout=60s pod/model-consumer || true
kubectl -n "${NAMESPACE}" wait --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s pod/model-consumer
kubectl -n "${NAMESPACE}" logs pod/model-consumer

echo "== Demo complete: model published, decrypted, and loaded. =="
