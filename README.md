# llm_delivery_pipeline

A proof of concept for confidential distribution of an LLM/ML model through Kubernetes: a
**producer** encrypts a small, open Hugging Face model and publishes the ciphertext to the
Hugging Face Hub, storing the decryption key as a Kubernetes Secret; a **consumer** pod mounts
that Secret, downloads the ciphertext, decrypts it in memory, and loads the model.

```text
producer (Job) --encrypt--> Hugging Face Hub (public, opaque .enc)
     |                              |
     v                              v
model-encryption-key (Secret) --> consumer (Pod) --decrypt--> model loaded
```

The security property this demonstrates: Hugging Face stores the artifact but can never decrypt
it. The decryption key never leaves the Kubernetes cluster. See [`docs/architecture.md`](docs/architecture.md)
for the full data flow and container format, [`docs/decisions.md`](docs/decisions.md) for why each
choice was made over its alternatives, and [`docs/threat-model.md`](docs/threat-model.md) for what
this does and does not protect against.

This repository implements only the mandatory layer of the underlying exercise (encrypt, publish,
mount a key, decrypt, load). Signing the manifest and attestation-gated key release are documented
as future extensions in [`docs/decisions.md`](docs/decisions.md) and [`docs/threat-model.md`](docs/threat-model.md),
not implemented.

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
architecture. Each is self-contained; pick the one that matches the dependencies you're willing to
install.

If you're driving this repository through Claude Code, the [`test-locally`](.claude/skills/test-locally/SKILL.md)
skill runs any of the three for you — including the full verification sequence after Option 3 —
without you having to copy commands by hand: just ask it to run the repo locally, or invoke it
directly with `/test-locally`.

**Short on time?** [Option 1](#option-1--run-the-test-suite-only) needs nothing but a Python
virtualenv and already exercises the cryptographic core directly, including the tampering,
truncation, and reordering tests that back the security claims in this README. To also see the
real pipeline decrypt a real published artifact — no Hugging Face account, no token, nothing to
publish yourself — see [`demo/README.md`](demo/README.md).

| | What it proves | What it needs | ~Time |
|---|---|---|---|
| [Option 1](#option-1--run-the-test-suite-only) | The code is correct (crypto round-trip, tampering detection, mocked HF/producer/consumer logic) | Python only | 1 min |
| [Option 2](#option-2--run-the-pipeline-directly-without-kubernetes) | The pipeline works end-to-end against real Hugging Face Hub | Python + HF write token | 3-5 min |
| [Option 3](#option-3--full-end-to-end-demo-on-kubernetes) | The full architecture works, including the Secret mount and in-memory decryption | Docker + minikube + HF write token | 8-10 min |

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
- A Hugging Face account with a **write** token (`HF_TOKEN`), to publish to a repo of your own (e.g.
  `<your-namespace>/bert-tiny-encrypted`). The consumer step does not need a token: the target repo is
  public (see decision 8 in `docs/decisions.md`).
- No Docker, no minikube

```bash
python3.12 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[producer,consumer,dev]"

python -m model_pipeline keygen > .encryption-key   # base64 AES-256 key, local file only

HF_TOKEN=<your token> ENCRYPTION_KEY_FILE=.encryption-key \
  python -m model_pipeline produce \
    --source-model google/bert_uncased_L-2_H-128_A-2 \
    --target-repo <your-namespace>/bert-tiny-encrypted \
    --version 1.0.0

ENCRYPTION_KEY_FILE=.encryption-key \
  python -m model_pipeline consume \
    --repo <your-namespace>/bert-tiny-encrypted \
    --version 1.0.0 \
    --workdir /tmp/model \
    --smoke-test
```

See `.env.example` for every recognized environment variable and the CLI's argument-over-env-over-default
precedence.

Run `produce`/`consume` at a real terminal and a version conflict (already published for `produce`,
not published for `consume`) prompts for a replacement instead of failing outright — pass
`--check-only` to only resolve/validate `--version` and print it, without publishing or downloading
anything.

### Option 3 — Full end-to-end demo on Kubernetes

The full, reproducible path from a clean checkout to a loaded model on minikube: producer Job, Secret,
consumer Pod, in-memory decryption. This is the option that actually demonstrates the architecture
described at the top of this README, not just the underlying Python logic.

**Dependencies needed:**
- Docker (to build both images)
- [minikube](https://minikube.sigs.k8s.io/) and `kubectl`
- A Hugging Face account with a **write** token (`HF_TOKEN`), same as Option 2. The consumer Pod does
  not need one.
- Enough local resources to run minikube and build/load two images that bundle `torch`/`transformers`

```bash
export HF_TOKEN=<a Hugging Face token with write access>
./scripts/demo.sh
```

`scripts/demo.sh` starts minikube if it isn't running, builds and loads both images, provisions the
namespace/service account/Secrets, runs the producer Job, and then the consumer Pod, printing both
sets of logs. By default it targets the repo and version baked into `k8s/producer-job.yaml` and
`k8s/consumer-pod.yaml` (`jecaro/bert-tiny-encrypted`, version `1.0.5`).

Since the producer refuses to overwrite an existing version (artifact versions are immutable, see
decision 7 in `docs/decisions.md`), re-running the script against an already-published version
would otherwise only fail once the producer Job is already running in the cluster — which looks
like the script hanging until `kubectl`'s wait times out. Instead, `scripts/demo.sh` checks the
target version against the target repo itself before touching the cluster at all (running
`model_pipeline produce --check-only` locally via the already-built producer image), and prompts
on the terminal for a different version on a conflict, suggesting the next available one:

```text
version '1.0.5' already exists in 'jecaro/bert-tiny-encrypted'; the next available version looks like '1.0.6'
Enter a different version to publish under jecaro/bert-tiny-encrypted [1.0.6]:
```

Press Enter to accept the suggestion, type a different version, or avoid the prompt entirely by
passing one you already know is free:

```bash
./scripts/demo.sh --version 1.0.6
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

## Verifying the Kubernetes demo (Option 3)

Each step below is independently checkable after running `scripts/demo.sh`. After
`--producer-only`, only checks 1-3 apply (there is no consumer Pod to inspect yet). After
`--consumer-only`, checks 2 and 3 don't apply (no producer Job ran in this invocation) — checks 1,
4, and 5 do, since they only depend on the encryption-key Secret and the consumer Pod, both already
in place from the prior run that published the targeted artifact.

```bash
# 1. The Secret exists and the key has the right length
# (Kubernetes base64-encodes the stored value, which is itself the
# base64-encoded key that `keygen` produced, hence the double decode.)
kubectl -n confidential-models get secret model-encryption-key -o jsonpath='{.data.encryption-key}' \
  | base64 -d | base64 -d | wc -c        # -> 32

# 2. The producer job completed
kubectl -n confidential-models logs job/model-producer

# 3. The published artifact is opaque: without the key it is not a model
huggingface-cli download <namespace>/bert-tiny-encrypted versions/1.0.0/model.tar.enc --local-dir /tmp/check
file /tmp/check/versions/1.0.0/model.tar.enc      # -> data
tar tf /tmp/check/versions/1.0.0/model.tar.enc    # -> fails: not a tar archive

# 4. The consumer decrypted and loaded the model
kubectl -n confidential-models logs pod/model-consumer
# -> manifest verified, sha256 OK, model verified and decrypted, smoke test prediction printed

# 5. Negative test: with the wrong key, the consumer fails loudly
kubectl -n confidential-models delete secret model-encryption-key
kubectl -n confidential-models create secret generic model-encryption-key \
  --from-literal=encryption-key="$(openssl rand -base64 32)"
kubectl -n confidential-models delete pod model-consumer --ignore-not-found
kubectl apply -f k8s/consumer-pod.yaml
kubectl -n confidential-models logs pod/model-consumer   # -> authentication error, non-zero exit
```

Step 5 is what actually demonstrates the encryption is not decorative: garbage or a mismatched key
never produces a silently wrong model, it fails authentication.

## Design decisions

Every architectural choice in this repository — the model, the container format, the chunked
AES-256-GCM scheme, the Kubernetes resource layout, why the artifact repo is public, why CI never
publishes anything — is recorded with its rejected alternatives and reasoning in
[`docs/decisions.md`](docs/decisions.md).

## What this does not cover

[`docs/threat-model.md`](docs/threat-model.md) lists what is and is not protected: in short, this
protects the model at rest on Hugging Face and in transit, and detects tampering, but a cluster
administrator can still read the Secret, and nothing here proves who published an artifact or
attests to the node the key is released to.

## Extending toward stronger guarantees

- **Manifest signing**: the manifest already commits to the artifact's hash, so a single asymmetric
  signature (Ed25519 or Sigstore/cosign) over the manifest, verified by the consumer before
  decrypting, would give authenticity of origin without changing the container format.
- **Attestation-gated key release**: replacing the Kubernetes Secret mount with a request to a
  Confidential Containers key broker (Trustee KBS) would mean the key is only released to a node
  that first proves its integrity. The extension point is `model_pipeline.keys`: swapping "read a
  file" for "request the resource from the local confidential data hub" leaves the rest of the
  pipeline untouched.

Both are discussed in more detail, including why they were left out of this PoC, in
[`docs/decisions.md`](docs/decisions.md) and [`docs/threat-model.md`](docs/threat-model.md).
