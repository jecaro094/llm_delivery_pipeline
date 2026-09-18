#!/usr/bin/env bash
# Removes the Kubernetes objects scripts/demo.sh creates: the producer Job,
# the consumer Pod, and both Secrets. Idempotent -- safe to run when nothing
# exists -- and never touches anything outside the confidential-models
# namespace. Pass --all to also delete the namespace itself.
set -euo pipefail

usage() {
    echo "Usage: $0 [--all]" >&2
    echo "  --all   also delete the confidential-models namespace itself" >&2
}

DELETE_NAMESPACE=false

while [ $# -gt 0 ]; do
    case "$1" in
        --all)
            DELETE_NAMESPACE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

NAMESPACE="${NAMESPACE:-confidential-models}"

if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not found; nothing to clean up." >&2
    exit 0
fi

if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    echo "namespace ${NAMESPACE} does not exist; nothing to clean up."
    exit 0
fi

if [ "${DELETE_NAMESPACE}" = true ]; then
    echo "== Deleting namespace ${NAMESPACE} =="
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found
    exit 0
fi

echo "== Deleting workloads and secrets in ${NAMESPACE} =="
kubectl -n "${NAMESPACE}" delete job model-producer --ignore-not-found
kubectl -n "${NAMESPACE}" delete pod model-consumer --ignore-not-found
kubectl -n "${NAMESPACE}" delete secret model-encryption-key --ignore-not-found
kubectl -n "${NAMESPACE}" delete secret hf-credentials --ignore-not-found
