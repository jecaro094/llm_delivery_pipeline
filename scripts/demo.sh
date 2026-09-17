#!/usr/bin/env bash
# End-to-end, reproducible walkthrough of the pipeline on minikube: builds
# both images, provisions the namespace and Secrets, runs the producer Job
# to publish an encrypted model, then runs the consumer Pod to decrypt and
# load it. Requires HF_TOKEN to be set in the environment (a token with
# write access to the target Hugging Face repo).
#
# --producer-only and --consumer-only run just one side of the pipeline
# against the cluster, for debugging one side without waiting on the other:
# --producer-only publishes an artifact and stops before touching the
# consumer Pod; --consumer-only decrypts an already-published artifact and
# skips everything producer-specific (HF_TOKEN, the hf-credentials Secret,
# and regenerating the encryption-key Secret, which must stay the one the
# targeted artifact was actually encrypted with).
#
# The producer refuses to overwrite a version that already exists (artifact
# versions are immutable, see PLAN.md, decision 7). Rather than let that
# surface as a Kubernetes Job stuck retrying until kubectl's wait times out,
# this script checks the target version against the target repo itself
# (`model_pipeline produce/consume --check-only`, run locally via the
# already-built producer/consumer image, before anything is applied to the
# cluster) and prompts on this terminal for a different version when there
# is a conflict. Pass --version (or set MODEL_VERSION) / --repo (or
# MODEL_REPO_ID) to skip that prompt for a version/repo you already know is
# free. Neither k8s manifest is modified on disk: the resolved version/repo
# is applied in-memory via `kubectl set env --local` before `kubectl apply`.
set -euo pipefail

usage() {
    echo "Usage: $0 [--version VERSION] [--repo REPO] [--producer-only|--consumer-only]" >&2
    echo "  --version VERSION  publish/consume this artifact version (default: MODEL_VERSION env, else the value baked into the k8s manifests)" >&2
    echo "  --repo REPO        target this Hugging Face repo (default: MODEL_REPO_ID env, else the value baked into the k8s manifests)" >&2
    echo "  --producer-only    publish the artifact and stop; skip the consumer Pod" >&2
    echo "  --consumer-only    decrypt an already-published artifact; skip HF_TOKEN, hf-credentials, and regenerating the encryption key" >&2
}

VERSION_OVERRIDE="${MODEL_VERSION:-}"
REPO_OVERRIDE="${MODEL_REPO_ID:-}"
MODE="both"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION_OVERRIDE="${2:?--version requires a value}"
            shift 2
            ;;
        --repo)
            REPO_OVERRIDE="${2:?--repo requires a value}"
            shift 2
            ;;
        --producer-only)
            MODE="producer"
            shift
            ;;
        --consumer-only)
            MODE="consumer"
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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-confidential-models}"
PRODUCER_TAG="model-pipeline-producer:local" # must match scripts/build-images.sh
CONSUMER_TAG="model-pipeline-consumer:local" # must match scripts/build-images.sh

# Fails fast with a specific, actionable message when a required tool is
# missing or unreachable, instead of letting the script die deep inside a
# `kubectl wait`/`docker run` call with a much less obvious error. Anyone
# without Docker/minikube should use Option 1/2 in the README instead of
# this script.
check_prerequisites() {
    local missing=()
    command -v docker >/dev/null 2>&1 || missing+=("docker (CLI not found)")
    if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
        missing+=("docker (installed, but the daemon is not running/reachable)")
    fi
    command -v minikube >/dev/null 2>&1 || missing+=("minikube")
    command -v kubectl >/dev/null 2>&1 || missing+=("kubectl")

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "This script needs Docker, minikube, and kubectl. Missing/unavailable:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        echo >&2
        echo "See the README's 'Testing this locally' section for options that don't" >&2
        echo "need Kubernetes (Option 1: pytest only; Option 2: the CLI directly" >&2
        echo "against Hugging Face Hub)." >&2
        exit 1
    fi
}

check_prerequisites

if [ "${MODE}" != "consumer" ] && [ -z "${HF_TOKEN:-}" ]; then
    echo "HF_TOKEN must be set (a Hugging Face token with write access to the target repo)." >&2
    exit 1
fi

# Applies a k8s manifest as-is, or with MODEL_VERSION/MODEL_REPO_ID patched
# in-memory first when an override was requested, without touching the file
# on disk.
apply_manifest() {
    local file="$1"
    if [ -z "${VERSION_OVERRIDE}" ] && [ -z "${REPO_OVERRIDE}" ]; then
        kubectl apply -f "${file}"
        return
    fi

    local set_args=()
    [ -n "${VERSION_OVERRIDE}" ] && set_args+=("MODEL_VERSION=${VERSION_OVERRIDE}")
    [ -n "${REPO_OVERRIDE}" ] && set_args+=("MODEL_REPO_ID=${REPO_OVERRIDE}")
    kubectl set env --local -f "${file}" "${set_args[@]}" -o yaml | kubectl apply -f -
}

# Prints the effective value of the named env var for a k8s manifest file,
# after applying the current VERSION_OVERRIDE/REPO_OVERRIDE (if any)
# in-memory -- without touching the file on disk or contacting the cluster.
manifest_env() {
    local file="$1" name="$2"
    if [ -z "${VERSION_OVERRIDE}" ] && [ -z "${REPO_OVERRIDE}" ]; then
        kubectl set env --local -f "${file}" --list | sed -n "s/^${name}=//p"
        return
    fi

    local set_args=()
    [ -n "${VERSION_OVERRIDE}" ] && set_args+=("MODEL_VERSION=${VERSION_OVERRIDE}")
    [ -n "${REPO_OVERRIDE}" ] && set_args+=("MODEL_REPO_ID=${REPO_OVERRIDE}")
    kubectl set env --local -f "${file}" "${set_args[@]}" --list | sed -n "s/^${name}=//p"
}

if ! minikube status >/dev/null 2>&1; then
    echo "Starting minikube..."
    minikube start --memory=4096
fi

echo "== Building images =="
"${REPO_ROOT}/scripts/build-images.sh"

echo "== Checking target version availability =="
# Resolves the version conflict *before* creating anything in the cluster,
# using the just-built producer/consumer image locally (no cluster, no
# HF_TOKEN needed: this only lists what is already published). Without this,
# a conflict only surfaces once the Job/Pod is running, and looks like the
# script hanging until kubectl's wait times out (see the header comment
# above). --consumer-only checks the opposite direction (the version must
# already exist) via the consumer image instead of the producer one.
MANIFEST_FOR_VERSION="${REPO_ROOT}/k8s/producer-job.yaml"
[ "${MODE}" = "consumer" ] && MANIFEST_FOR_VERSION="${REPO_ROOT}/k8s/consumer-pod.yaml"
TARGET_REPO="$(manifest_env "${MANIFEST_FOR_VERSION}" MODEL_REPO_ID)"
TARGET_VERSION="$(manifest_env "${MANIFEST_FOR_VERSION}" MODEL_VERSION)"
if [ "${MODE}" = "consumer" ]; then
    if ! TARGET_VERSION="$(docker run --rm "${CONSUMER_TAG}" consume --check-only \
            --repo "${TARGET_REPO}" --version "${TARGET_VERSION}" 2>&1)"; then
        echo "${TARGET_VERSION}" >&2
        exit 1
    fi
else
    while true; do
        if CHECK_OUTPUT="$(docker run --rm "${PRODUCER_TAG}" produce --check-only \
                --target-repo "${TARGET_REPO}" --version "${TARGET_VERSION}" 2>&1)"; then
            TARGET_VERSION="${CHECK_OUTPUT}"
            break
        fi
        echo "${CHECK_OUTPUT}" >&2
        SUGGESTION="$(sed -n "s/.*next available version looks like '\([^']*\)'.*/\1/p" <<<"${CHECK_OUTPUT}")"
        read -rp "Enter a different version to publish under ${TARGET_REPO}${SUGGESTION:+ [${SUGGESTION}]}: " INPUT
        TARGET_VERSION="${INPUT:-${SUGGESTION}}"
        [ -z "${TARGET_VERSION}" ] && echo "a version is required" >&2
    done
fi
VERSION_OVERRIDE="${TARGET_VERSION}"
REPO_OVERRIDE="${TARGET_REPO}"
echo "Targeting ${REPO_OVERRIDE} version ${VERSION_OVERRIDE}"

echo "== Provisioning namespace and service account =="
kubectl apply -f "${REPO_ROOT}/k8s/namespace.yaml"
kubectl apply -f "${REPO_ROOT}/k8s/serviceaccount.yaml"

if [ "${MODE}" != "consumer" ]; then
    echo "== Provisioning secrets =="
    "${REPO_ROOT}/scripts/gen-key.sh"
    kubectl -n "${NAMESPACE}" create secret generic hf-credentials \
        --from-literal=hf-token="${HF_TOKEN}" \
        --dry-run=client -o yaml | kubectl apply -f -
fi

if [ "${MODE}" != "consumer" ]; then
    echo "== Running the producer job =="
    kubectl -n "${NAMESPACE}" delete job model-producer --ignore-not-found
    apply_manifest "${REPO_ROOT}/k8s/producer-job.yaml"
    if ! kubectl -n "${NAMESPACE}" wait --for=condition=complete --timeout=300s job/model-producer; then
        echo "producer job did not complete; last logs:" >&2
        kubectl -n "${NAMESPACE}" logs job/model-producer >&2 || true
        exit 1
    fi
    kubectl -n "${NAMESPACE}" logs job/model-producer
fi

if [ "${MODE}" = "producer" ]; then
    echo "== Demo complete: model published (--producer-only, consumer skipped). =="
    exit 0
fi

echo "== Running the consumer pod =="
kubectl -n "${NAMESPACE}" delete pod model-consumer --ignore-not-found
apply_manifest "${REPO_ROOT}/k8s/consumer-pod.yaml"

# Polls for a terminal phase instead of `kubectl wait --for=...=Succeeded`:
# that condition never becomes true for a pod that fails fast (e.g. the
# version preflight above still raced with someone else publishing in the
# meantime), so it would otherwise block for the full timeout before this
# script could report anything.
CONSUMER_TIMEOUT_S=300
CONSUMER_ELAPSED_S=0
CONSUMER_PHASE=""
while [ "${CONSUMER_ELAPSED_S}" -lt "${CONSUMER_TIMEOUT_S}" ]; do
    CONSUMER_PHASE="$(kubectl -n "${NAMESPACE}" get pod model-consumer -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "${CONSUMER_PHASE}" in
        Succeeded|Failed) break ;;
    esac
    sleep 2
    CONSUMER_ELAPSED_S=$((CONSUMER_ELAPSED_S + 2))
done

if [ "${CONSUMER_PHASE}" != "Succeeded" ]; then
    echo "consumer pod did not complete (phase=${CONSUMER_PHASE:-unknown}); last logs:" >&2
    kubectl -n "${NAMESPACE}" logs pod/model-consumer >&2 || true
    exit 1
fi
kubectl -n "${NAMESPACE}" logs pod/model-consumer

echo "== Demo complete: model published, decrypted, and loaded. =="
