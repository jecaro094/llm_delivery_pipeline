# llm_delivery_pipeline

[![CI](https://github.com/jecaro094/llm_delivery_pipeline/actions/workflows/ci.yml/badge.svg?branch=layer_2)](https://github.com/jecaro094/llm_delivery_pipeline/actions/workflows/ci.yml?query=branch%3Alayer_2)

> This branch (`layer_2`) implements the mandatory layer of the exercise plus its optional
> signing/verification layer. For the mandatory layer on its own, see the
> [`main`](https://github.com/jecaro094/llm_delivery_pipeline/tree/main) branch.

A proof of concept for confidential distribution of an LLM/ML model through Kubernetes: a
**producer** encrypts a small, open Hugging Face model, signs the manifest describing it, and
publishes the ciphertext, manifest, and signature to the Hugging Face Hub, storing the decryption
key and the signing key as Kubernetes Secrets; a **consumer** pod mounts the decryption key and a
public verification key from a ConfigMap, verifies the manifest's signature, then downloads,
decrypts, and loads the model — aborting before any of that if verification fails.

```text
producer (Job) --encrypt, sign--> Hugging Face Hub (public: .enc + manifest + .sig)
     |                                          |
     v                                          v
model-encryption-key (Secret) --+          consumer (Pod) --verify--> decrypt --> model loaded
model-signing-key (Secret)      |               ^
                                 |               |
                                 +--------- model-signing-public-key (ConfigMap)
```

Two independent security properties: Hugging Face stores the artifact but can never decrypt it —
the decryption key never leaves the cluster — and Hugging Face (or anyone with write access to the
repo) can serve arbitrary bytes but cannot make the consumer accept them, because the consumer's
trust anchor (the public verification key) also never leaves the cluster and never comes from the
Hub. See [`docs/architecture.md`](docs/architecture.md) for the full data flow, container format,
and signing scheme, [`docs/decisions.md`](docs/decisions.md) for why each choice was made over its
alternatives, and [`docs/threat-model.md`](docs/threat-model.md) for what this does and does not
protect against.

This repository implements the mandatory layer of the underlying exercise (encrypt, publish, mount
a key, decrypt, load) plus its optional signing/verification layer (generate a key pair, sign the
published manifest, verify it before decrypting, abort on failure). There is deliberately no toggle
to run the pipeline "without signing" — see [Verifying the Kubernetes demo](#verifying-the-kubernetes-demo-option-3)
below for how each layer is demonstrated independently, through what its own negative test catches.
Attestation-gated key release is documented as a future extension in
[`docs/decisions.md`](docs/decisions.md) and [`docs/threat-model.md`](docs/threat-model.md), not
implemented.

## Prerequisites

Dependencies vary by how you choose to test the repository locally — see the comparison table in
[Testing this locally](#testing-this-locally) below. Every `pip install` command in this README
assumes an isolated virtual environment, created the same way in each option:

```bash
python3.12 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
```

## Source model compatibility

`produce` only accepts a source model whose `config.json` declares a `model_type`, since that is
what lets `transformers` auto-detect its architecture on the consumer side. Some older Hugging Face
repos omit this key; publishing one of those is rejected immediately, before any encryption or
upload happens, with an error naming the missing key.

## Testing this locally

There are three independent ways to exercise this repository, covering progressively more of the
architecture, plus a zero-setup fast path against a pinned demo artifact for anyone without a
Hugging Face account or short on time. Each is self-contained; pick the one that matches the
dependencies you're willing to install.

If you're driving this repository through Claude Code, the [`test-locally`](.claude/skills/test-locally/SKILL.md)
skill runs any of them for you — including the full verification sequence after Option 3 —
without you having to copy commands by hand: just ask it to run the repo locally, or invoke it
directly with `/test-locally`.

**Short on time?** [Option 1](#option-1--run-the-test-suite-only) needs nothing but a Python
virtualenv and already exercises the cryptographic core directly, including the tampering,
truncation, and reordering tests that back the security claims in this README. To also see the
real pipeline verify and decrypt a real published artifact — no Hugging Face account, no token,
nothing to publish yourself — see [`demo/README.md`](demo/README.md).

| | What it proves | What it needs | ~Time |
|---|---|---|---|
| [Option 1](#option-1--run-the-test-suite-only) | The code is correct (crypto round-trip, tampering detection, mocked HF/producer/consumer logic) | Python only | 1 min |
| [Option 2](#option-2--run-the-pipeline-directly-without-kubernetes) | The pipeline works end-to-end against real Hugging Face Hub | Python + HF write token | 3-5 min |
| [Option 3](#option-3--full-end-to-end-demo-on-kubernetes) | The full architecture works, including the Secret mount and in-memory decryption | Docker + minikube + HF write token | 8-10 min |

### Fast path — pinned demo artifact (no account, no token)

Runs the real consumer against a real, already-published artifact using a demo-only encryption key
committed to the repository on purpose — see [`demo/README.md`](demo/README.md) for why that
exception is safe. This proves the same thing Option 2's consume step proves (download, decryption,
model loading) against a real published artifact, without the producer side or the Secret/Pod
machinery from Option 3.

**Dependencies needed:** Python 3.12+ only. No Docker, no minikube, no Hugging Face account or
token, and nothing to publish.

```bash
python3.12 -m venv .venv   # skip if a .venv already exists
source .venv/bin/activate
pip install -e ".[consumer,dev]"

WORKDIR="$(mktemp -d)"   # a throwaway directory for the decrypted model -- never /tmp itself

ENCRYPTION_KEY_FILE=demo/encryption-key \
  python -m model_pipeline consume \
    --repo jecaro/bert-tiny-encrypted \
    --version demo \
    --workdir "${WORKDIR}" \
    --smoke-test

rm -rf "${WORKDIR}"
```

### Option 1 — Run the test suite only

No external services are touched: Hugging Face Hub and the heavy `torch`/`transformers` dependencies
are mocked. This only proves the code (including the cryptographic core) is correct, not that the
pipeline works end-to-end.

**Dependencies needed:** Python 3.12+ only. No Docker, no minikube, no Hugging Face account.

```bash
python3.12 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[producer,dev]"
python -m pytest
```

`tests/` has no `__init__.py`, so it must be run as `python -m pytest`, not the `pytest`
console script: only `python -m pytest` adds the current directory to `sys.path`, which the
test modules need to import `tests.constants`.

### Option 2 — Run the pipeline directly, without Kubernetes

Drives the real producer and consumer CLI commands against the real Hugging Face Hub: an artifact is
actually encrypted, uploaded, downloaded, decrypted, and loaded. This skips Kubernetes entirely, so it
does not exercise the Secret mount or the in-memory (`tmpfs`) decryption — it isolates the pipeline
logic from the deployment layer.

**Dependencies needed:**
- Python 3.12+
- A Hugging Face account with a **write** token, to publish to a repo of your own (e.g.
  `<your-namespace>/bert-tiny-encrypted`). The consumer step does not need a token: the target repo is
  public (see decision 8 in `docs/decisions.md`). Run `hf auth login` once beforehand and
  `produce` picks up the cached token automatically -- no need to type or export it; `HF_TOKEN`
  (or `HF_TOKEN_FILE`, for a mounted-file token) still works and takes precedence if set.
- No Docker, no minikube

```bash
python3.12 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[producer,consumer,dev]"

hf auth login   # once; produce picks up the cached token from here on

python -m model_pipeline keygen > .encryption-key           # base64 AES-256 key, local file only
python -m model_pipeline signing-keygen > .signing-keypair   # Ed25519 PEM pair, both keys printed

# Split the combined output into the two files the flags below expect
# (the marker lines are what signing-keygen prints before each PEM block).
sed -n '/BEGIN PRIVATE/,/END PRIVATE/p' .signing-keypair > .signing-key.pem
sed -n '/BEGIN PUBLIC/,/END PUBLIC/p' .signing-keypair > .signing-public-key.pem

ENCRYPTION_KEY_FILE=.encryption-key SIGNING_KEY_FILE=.signing-key.pem \
  python -m model_pipeline produce \
    --source-model google/bert_uncased_L-2_H-128_A-2 \
    --target-repo <your-namespace>/bert-tiny-encrypted \
    --version 1.0.0

# Verify the signature alone, with no decryption key at all
python -m model_pipeline verify \
  --repo <your-namespace>/bert-tiny-encrypted \
  --version 1.0.0 \
  --public-key-file .signing-public-key.pem

WORKDIR="$(mktemp -d)"   # a throwaway directory for the decrypted model -- never /tmp itself

ENCRYPTION_KEY_FILE=.encryption-key SIGNING_PUBLIC_KEY_FILE=.signing-public-key.pem \
  python -m model_pipeline consume \
    --repo <your-namespace>/bert-tiny-encrypted \
    --version 1.0.0 \
    --workdir "${WORKDIR}" \
    --smoke-test
```

See `.env.example` for every recognized environment variable and the CLI's argument-over-env-over-default
precedence.

Run `produce`/`consume` at a real terminal and a version conflict (already published for `produce`,
not published for `consume`) prompts for a replacement instead of failing outright — pass
`--check-only` to only resolve/validate `--version` and print it, without publishing or downloading
anything.

`--workdir` is where the consumer writes the decrypted model; it must never be a fixed `/tmp` path
(see [`docs/decisions.md`](docs/decisions.md#local-runs-outside-kubernetes-do-not-decrypt-into-tmp-either)
for why). Remove it once you're done inspecting the result (`rm -rf "${WORKDIR}"`), the local
equivalent of the cleanup Option 3 does automatically.

### Option 3 — Full end-to-end demo on Kubernetes

The full, reproducible path from a clean checkout to a loaded model on minikube: producer Job, Secret,
consumer Pod, in-memory decryption. This is the option that actually demonstrates the architecture
described at the top of this README, not just the underlying Python logic.

**Dependencies needed:**
- Docker (to build both images)
- [minikube](https://minikube.sigs.k8s.io/) and `kubectl`
- A Hugging Face account with a **write** token, same as Option 2. Unlike Option 2, `hf auth
  login`'s cached token is not enough here: the producer Job runs inside its own container, with
  no access to your host's login cache, so it needs the token passed in explicitly as `HF_TOKEN`.
  The consumer Pod does not need one.
- Enough local resources to run minikube and build/load two images that bundle `torch`/`transformers`

```bash
export HF_TOKEN=<a Hugging Face token with write access>
./scripts/demo.sh
```

`scripts/demo.sh` starts minikube if it isn't running, builds and loads both images, provisions the
namespace/service account/Secrets (`model-encryption-key` via `scripts/gen-key.sh`, and
`model-signing-key` + `model-signing-public-key` via `scripts/gen-signing-key.sh`), runs the
producer Job, and then the consumer Pod, printing both sets of logs. By default it targets the repo
and version baked into `k8s/producer-job.yaml` and `k8s/consumer-pod.yaml`
(`jecaro/bert-tiny-encrypted`, version `1.0.3`).

Since the producer refuses to overwrite an existing version (artifact versions are immutable, see
decision 7 in `docs/decisions.md`), re-running the script against an already-published version
would otherwise only fail once the producer Job is already running in the cluster — which looks
like the script hanging until `kubectl`'s wait times out. Instead, `scripts/demo.sh` checks the
target version against the target repo itself before touching the cluster at all (running
`model_pipeline produce --check-only` locally via the already-built producer image), and prompts
on the terminal for a different version on a conflict, suggesting the next available one:

```text
version '1.0.3' already exists in 'jecaro/bert-tiny-encrypted'; the next available version looks like '1.0.4'
Enter a different version to publish under jecaro/bert-tiny-encrypted [1.0.4]:
```

Press Enter to accept the suggestion, type a different version, or avoid the prompt entirely by
passing one you already know is free:

```bash
./scripts/demo.sh --version 1.0.4
# or target your own repo entirely:
./scripts/demo.sh --repo <your-namespace>/bert-tiny-encrypted --version 1.0.0
```

`--version`/`--repo` (or the `MODEL_VERSION`/`MODEL_REPO_ID` environment variables) patch the two
manifests in memory via `kubectl set env --local` before applying them; the files on disk are never
modified.

Pass `--producer-only` or `--consumer-only` to run just one side of the pipeline against the
cluster, without waiting on the other — useful when debugging one side in isolation:

```bash
# publish an artifact and stop; the consumer Pod is never touched
./scripts/demo.sh --producer-only --repo <your-namespace>/bert-tiny-encrypted --version 1.0.0

# decrypt an already-published artifact; no HF_TOKEN needed
./scripts/demo.sh --consumer-only --repo <your-namespace>/bert-tiny-encrypted --version 1.0.0
```

`--consumer-only` skips `HF_TOKEN`, the `hf-credentials` Secret, and regenerating the
`model-encryption-key` Secret — that key must stay the one the targeted artifact was actually
encrypted with, so it has to already exist in the cluster (from a prior full run or
`--producer-only` run) before `--consumer-only` can decrypt anything with it.

By default the producer Job, the consumer Pod, the encryption-key and signing-key Secrets, and the
signing public-key ConfigMap are left in the `confidential-models` namespace after a run, so
`kubectl logs`/`get` still work against them afterwards. End a local run with either:

```bash
./scripts/demo.sh --cleanup          # remove them once the run's final logs have been printed
# or, any time later:
./scripts/cleanup.sh                 # same cleanup, run standalone; --all also deletes the namespace
```

Interrupting `scripts/demo.sh` (Ctrl-C, or any signal) always cleans up on the way out regardless
of `--cleanup`, since a run that never finished leaves nothing worth inspecting; a completed run —
success or an already-diagnosed failure whose logs were printed — never cleans up on its own unless
`--cleanup` was passed.

## Verifying the Kubernetes demo (Option 3)

Steps 5 and 8 use `python -m model_pipeline verify`/`signing-keygen` and step 3/4 use
`huggingface-cli`; both assume a local `pip install -e ".[producer,dev]"` (see Option 1/2 above) —
none of them need Docker or minikube themselves, only the cluster and repo the full demo already
populated.

Each step below is independently checkable after running `scripts/demo.sh`. After
`--producer-only`, only checks 1-4 apply (there is no consumer Pod to inspect yet). After
`--consumer-only`, checks 2-4 don't apply (no producer Job ran in this invocation) — checks 1, 5,
6, 7, and 8 do, since they only depend on the encryption/signing-public Secret and ConfigMap and the
consumer Pod, both already in place from the prior run that published the targeted artifact.

```bash
# 1. The Secrets exist and the decryption key has the right length
# (Kubernetes base64-encodes the stored value, which is itself the
# base64-encoded key that `keygen` produced, hence the double decode.)
kubectl -n confidential-models get secret model-encryption-key -o jsonpath='{.data.encryption-key}' \
  | base64 -d | base64 -d | wc -c        # -> 32
kubectl -n confidential-models get secret model-signing-key -o name          # -> exists
kubectl -n confidential-models get configmap model-signing-public-key -o name # -> exists

# 2. The producer job completed (encrypted, signed, and published)
kubectl -n confidential-models logs job/model-producer

# 3. The published artifact is opaque: without the key it is not a model
huggingface-cli download <namespace>/bert-tiny-encrypted versions/1.0.0/model.tar.enc --local-dir /tmp/check
file /tmp/check/versions/1.0.0/model.tar.enc      # -> data
tar tf /tmp/check/versions/1.0.0/model.tar.enc    # -> fails: not a tar archive

# 4. The signature is actually published alongside the artifact, and is a raw 64-byte Ed25519 signature
huggingface-cli download <namespace>/bert-tiny-encrypted versions/1.0.0/manifest.json.sig --local-dir /tmp/check
wc -c /tmp/check/versions/1.0.0/manifest.json.sig      # -> 64

# 5. The published version verifies against the public key, with no decryption key involved at all
kubectl -n confidential-models get configmap model-signing-public-key \
  -o jsonpath='{.data.public-key\.pem}' > /tmp/check-public-key.pem
python -m model_pipeline verify --repo <namespace>/bert-tiny-encrypted --version 1.0.0 \
  --public-key-file /tmp/check-public-key.pem      # -> signature OK, key fingerprint <hex>

# 6. The consumer verified the signature, then decrypted and loaded the model
kubectl -n confidential-models logs pod/model-consumer
# -> signature OK, manifest verified, sha256 OK, model verified and decrypted, smoke test prediction printed

# 7. NEGATIVE TEST: with the wrong decryption key, the consumer fails loudly (Layer 1's guarantee)
kubectl -n confidential-models delete secret model-encryption-key
kubectl -n confidential-models create secret generic model-encryption-key \
  --from-literal=encryption-key="$(openssl rand -base64 32)"
kubectl -n confidential-models delete pod model-consumer --ignore-not-found
kubectl apply -f k8s/consumer-pod.yaml
kubectl -n confidential-models logs pod/model-consumer   # -> authentication error, non-zero exit

# 8. NEGATIVE TEST: with the wrong public key, the consumer never even reaches decryption (Layer 2's
# guarantee) -- re-run scripts/gen-signing-key.sh first to restore the real Secret/ConfigMap pair,
# then swap only the ConfigMap for an unrelated key:
python -m model_pipeline signing-keygen | sed -n '/BEGIN PUBLIC/,/END PUBLIC/p' > /tmp/unrelated-public-key.pem
kubectl -n confidential-models delete configmap model-signing-public-key
kubectl -n confidential-models create configmap model-signing-public-key \
  --from-file=public-key.pem=/tmp/unrelated-public-key.pem
kubectl -n confidential-models delete pod model-consumer --ignore-not-found
kubectl apply -f k8s/consumer-pod.yaml
kubectl -n confidential-models logs pod/model-consumer
# -> signature verification failed; aborting, non-zero exit, and NO artifact download in the logs
```

Steps 7 and 8 are what actually demonstrate each layer is not decorative, and deliberately have the
same shape: swap one mounted piece of key material, re-run, watch it fail loudly. Step 7 shows
encryption catches a wrong decryption key. Step 8 shows signing catches an untrusted publisher —
and the absence of an artifact-download log line there is what proves verification runs *before*
decryption, not just that it runs at all.

## Design decisions

Every architectural choice in this repository — the model, the container format, the chunked
AES-256-GCM scheme, the Kubernetes resource layout, why the artifact repo is public, why CI never
publishes anything — is recorded with its rejected alternatives and reasoning in
[`docs/decisions.md`](docs/decisions.md).

## What this does not cover

[`docs/threat-model.md`](docs/threat-model.md) lists what is and is not protected: in short, this
protects the model at rest on Hugging Face and in transit, detects tampering, and proves who
published an artifact — but a cluster administrator can still read either Secret or replace the
trust anchor ConfigMap outright, and nothing here attests to the node either key is released to.

## Extending toward stronger guarantees

- **Attestation-gated key release**: replacing the Kubernetes Secret/ConfigMap mounts with a request
  to a Confidential Containers key broker (Trustee KBS) would mean key material is only released to
  a node that first proves its integrity. The extension point is `model_pipeline.keys`: swapping
  "read a file" for "request the resource from the local confidential data hub" leaves the rest of
  the pipeline, including the signing and verification step, untouched: signature verification never
  depends on how the decryption key is obtained (see decisions 17-18 in
  [`docs/decisions.md`](docs/decisions.md)), so this layer was deliberately kept independent of how
  either key is delivered.

Discussed in more detail, including why it was left out of this PoC, in
[`docs/decisions.md`](docs/decisions.md) and [`docs/threat-model.md`](docs/threat-model.md).
