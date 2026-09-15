#!/usr/bin/env bash
# Builds the producer and consumer images and, when minikube is running,
# loads them into its node so k8s manifests can use them with
# imagePullPolicy: IfNotPresent and no registry (see PLAN.md, decision #2).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCER_TAG="model-pipeline-producer:local"
CONSUMER_TAG="model-pipeline-consumer:local"

echo "Building ${PRODUCER_TAG}..."
docker build -f "${REPO_ROOT}/docker/Dockerfile.producer" -t "${PRODUCER_TAG}" "${REPO_ROOT}"

echo "Building ${CONSUMER_TAG}..."
docker build -f "${REPO_ROOT}/docker/Dockerfile.consumer" -t "${CONSUMER_TAG}" "${REPO_ROOT}"

if command -v minikube >/dev/null 2>&1 && minikube status >/dev/null 2>&1; then
    echo "minikube is running, loading images into its node..."
    minikube image load "${PRODUCER_TAG}"
    minikube image load "${CONSUMER_TAG}"
else
    echo "minikube not running, skipping image load (images remain in the local docker daemon)."
fi
