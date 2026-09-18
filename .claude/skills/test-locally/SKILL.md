---
name: test-locally
description: Test the llm_delivery_pipeline repository locally, in any of its three independent ways — the pytest suite, the producer/consumer CLI against real Hugging Face Hub, or the full end-to-end demo on minikube — or via the pinned demo artifact for a zero-setup check with no Hugging Face account or token. Use this whenever the user wants to run, test, verify, or demo this project locally, check that a change still works, or asks "how do I try this out", even if they don't name a specific option. Also use it to answer "how do I test this" for someone evaluating the repository (e.g. a technical interviewer) or who is short on time.
---

# Test locally

This repository has three independent ways to exercise it locally, plus a zero-setup fast path
against a pinned demo artifact, documented in detail in the README's ["Testing this
locally"](../../../README.md#testing-this-locally) section and `demo/README.md`. This skill's job
is to run the right one — the README is the source of truth for exact commands and dependencies;
if the two ever disagree, trust the README and flag the mismatch instead of silently following
this file.

## Choosing an option

Never guess which option to run. Ask the user which one they want, using this framing:

- **Option 1 — test suite only.** Fastest, no external dependencies beyond Python. Proves the code
  (including the cryptographic core) is correct, not that the live pipeline works. ~1 min.
- **Option 2 — CLI without Kubernetes.** Runs the real producer/consumer against the real Hugging
  Face Hub. Needs a Hugging Face **write** token, picked up automatically from `hf auth login` --
  no need to ask the user for one. Proves the pipeline logic works end-to-end, but skips the
  Secret mount and in-memory decryption. ~3-5 min.
- **Option 3 — full Kubernetes demo (`scripts/demo.sh`).** Needs Docker, minikube, `kubectl`, and
  an explicit `HF_TOKEN`: the producer Job runs in its own container, with no access to a host
  login cache, so `hf auth login` alone is not enough here. The only option that exercises the
  actual architecture (Job, Secret, Pod, `tmpfs` decryption) described in the README. ~8-10 min.

If the user has no Hugging Face account, no write token, or is short on time (e.g. an interviewer
evaluating the repository), mention the **pinned demo artifact fast path** as an alternative to
Option 2 before asking: it runs the real consumer against a real, already-published artifact with
no account, no token, and nothing to publish — see "Fast path" below. Offer it alongside the three
options rather than instead of them; the user still picks.

If the user's request already implies one (e.g. "run the tests", "just check the code compiles" →
Option 1; "show me the full demo" → Option 3; "no token"/"short on time" → the fast path), proceed
directly without asking. Otherwise, ask.

## Asking for required inputs

Never assume, invent, or reuse a stale value for anything an option needs to run (a target repo,
a version, an `HF_TOKEN` for Option 3, …). If the value isn't already clear from the current
conversation, stop and ask the user for it interactively in the terminal before running the
command that needs it — one value at a time is fine; don't block on gathering all of them
upfront. Option 1 needs no external input, so this only applies to Options 2 and 3.

Never ask the user to type or paste a Hugging Face token. Option 2 needs no token input at all —
`produce` resolves it itself, from `HF_TOKEN`/`HF_TOKEN_FILE` if set, otherwise from `hf auth
login`'s cached login. If neither is available, the command fails with a clear error naming
`hf auth login`; relay that error rather than prompting for a token by hand. Option 3 is the one
exception: its producer Job runs in a container with no access to a host login cache, so it
genuinely needs `HF_TOKEN` set in the environment before `scripts/demo.sh` runs — check whether
it's already set before asking. If the user is logged in via `hf auth login`, suggest running
`export HF_TOKEN=$(hf auth token)` themselves so the value never has to be typed or pasted at
all; only if they are not logged in does this need a token from
https://huggingface.co/settings/tokens, and even then it's the user who runs the `export`, never
something to relay through chat.

## Running each option

### Fast path — pinned demo artifact (no account, no token)

Runs the real consumer against a real, already-published artifact (`demo/README.md`), using a
demo-only encryption key committed to the repository on purpose (see `demo/README.md` for why that
exception is safe: the key protects nothing but a disposable public demo artifact). Needs no
`HF_TOKEN`, no Hugging Face account, and publishes nothing.

```bash
python3.12 -m venv .venv   # skip if a .venv already exists
source .venv/bin/activate
pip install -e ".[consumer,dev]"

ENCRYPTION_KEY_FILE=demo/encryption-key \
  python -m model_pipeline consume \
    --repo jecaro/bert-tiny-encrypted \
    --version demo \
    --workdir /tmp/model \
    --smoke-test
```

This proves the same thing Option 2's consume step proves — download, decryption, model loading —
against a real published artifact, without the producer side or the Secret/Pod machinery from
Option 3.

### Option 1 — test suite

```bash
python3.12 -m venv .venv   # skip if a .venv already exists
source .venv/bin/activate
pip install -e ".[producer,dev]"
python -m pytest
```

### Option 2 — CLI without Kubernetes

Needs two things that are never known in advance — a target repo (their own namespace, e.g.
`<their-namespace>/bert-tiny-encrypted`) and a version string (e.g. `1.0.0`). Ask the user for
whichever of the two aren't already resolved, rather than assuming a value for either. The
Hugging Face token is not one of them: `produce` resolves it itself from `HF_TOKEN`/
`HF_TOKEN_FILE` if set, otherwise from a cached `hf auth login`. If neither is available, run `hf
auth login` (once) before retrying, rather than asking the user for a token to type or paste.

```bash
python3.12 -m venv .venv   # skip if a .venv already exists
source .venv/bin/activate
pip install -e ".[producer,consumer,dev]"

hf auth login   # only if produce reports no token available

python -m model_pipeline keygen > .encryption-key

ENCRYPTION_KEY_FILE=.encryption-key \
  python -m model_pipeline produce \
    --source-model google/bert_uncased_L-2_H-128_A-2 \
    --target-repo <namespace>/bert-tiny-encrypted \
    --version <version>

ENCRYPTION_KEY_FILE=.encryption-key \
  python -m model_pipeline consume \
    --repo <namespace>/bert-tiny-encrypted \
    --version <version> \
    --workdir /tmp/model \
    --smoke-test
```

### Option 3 — full Kubernetes demo, with verification

Needs `HF_TOKEN` (a Hugging Face write token), plus Docker, minikube, and `kubectl` on the `PATH`
with the Docker daemon running. `scripts/demo.sh` checks all of these itself before doing anything
else and exits immediately with a clear message naming what's missing — if that happens, don't
retry the script; tell the user what's missing and point at Option 1/2 or the fast path above
instead, exactly as the script's own message does. Check whether `HF_TOKEN` is already set in the
environment before asking the user for it. Run the demo:

```bash
export HF_TOKEN=<token>
./scripts/demo.sh
```

`scripts/demo.sh` starts minikube if needed, builds and loads both images, then — before touching
the cluster at all — checks the target version against the target repo (`produce --check-only` via
the already-built producer image). If the targeted artifact version already exists (versions are
immutable), it prompts on the terminal for a different one, suggesting the next available version;
press Enter to accept the suggestion or type another. Only then does it provision the
namespace/Secrets and run the producer Job followed by the consumer Pod, printing both sets of
logs. Pass `--version`/`--repo` up front to skip the prompt entirely for a version/repo you already
know is free, e.g. a fresh repo with `--repo <namespace>/bert-tiny-encrypted --version 1.0.0`.

`--producer-only` and `--consumer-only` run just one side against the cluster, without waiting on
the other — use them when the user only wants to debug the producer Job or the consumer Pod in
isolation, not a full round trip. See the README's Option 3 section for exact behavior and
requirements (`--consumer-only` needs the encryption key already in the cluster from a prior run
and skips `HF_TOKEN`).

After a full (no-flag) run, run the full verification sequence from the README's ["Verifying the
Kubernetes demo"](../../../README.md#verifying-the-kubernetes-demo-option-3) section — all five
checks, not a subset, since the last one (swapping in a wrong key and confirming the consumer fails
authentication loudly) is what actually demonstrates the encryption is doing something, not just
that the happy path runs. After `--producer-only`, only checks 1-3 apply (no consumer Pod ran).
After `--consumer-only`, only checks 1, 4, and 5 apply (no producer Job ran in that invocation).

```bash
# 1. Secret exists with a 32-byte key
kubectl -n confidential-models get secret model-encryption-key -o jsonpath='{.data.encryption-key}' \
  | base64 -d | base64 -d | wc -c        # -> 32

# 2. Producer job completed
kubectl -n confidential-models logs job/model-producer

# 3. Published artifact is opaque without the key
huggingface-cli download <namespace>/bert-tiny-encrypted versions/<version>/model.tar.enc --local-dir /tmp/check
file /tmp/check/versions/<version>/model.tar.enc      # -> data
tar tf /tmp/check/versions/<version>/model.tar.enc    # -> fails: not a tar archive

# 4. Consumer decrypted and loaded the model
kubectl -n confidential-models logs pod/model-consumer
# -> manifest verified, sha256 OK, model verified and decrypted, smoke test prediction printed

# 5. Negative test: wrong key fails loudly
kubectl -n confidential-models delete secret model-encryption-key
kubectl -n confidential-models create secret generic model-encryption-key \
  --from-literal=encryption-key="$(openssl rand -base64 32)"
kubectl -n confidential-models delete pod model-consumer --ignore-not-found
kubectl apply -f k8s/consumer-pod.yaml
kubectl -n confidential-models logs pod/model-consumer   # -> authentication error, non-zero exit
```

Report the outcome of each of the five checks to the user, not just whether the demo script itself
exited cleanly — a green `demo.sh` run with a check 5 that doesn't fail loudly would mean the
encryption isn't actually protecting anything.

## Cleaning up afterwards

After any option that created cluster objects or a local decrypted-model directory, clean them up
and report what was removed:

- **Option 2 / the fast path**: remove the `--workdir` directory the consumer wrote to (e.g. `rm -rf
  /tmp/model`).
- **Option 3**: run `./scripts/demo.sh --cleanup` up front to have the script clean up automatically
  once it prints its final logs, or `./scripts/cleanup.sh` afterwards — both remove the producer Job,
  the consumer Pod, and both Secrets from the `confidential-models` namespace, and are safe to run
  even if nothing exists. `./scripts/cleanup.sh --all` also deletes the namespace itself. An
  interrupted `demo.sh` run (Ctrl-C) already cleans up on its own, regardless of `--cleanup`.

## Reporting results

Summarize what ran, what passed, and — if something failed — the exact error rather than a
paraphrase, plus which of the four paths it was (so the user, or a future session, knows which
dependency to check first: Python environment, `HF_TOKEN`/network, or the local Kubernetes setup).
