# Demo key material — for this pinned demo artifact only

**This directory intentionally does what the rest of this repository explicitly avoids: it commits
key material to git.** Every other key in this project (the real encryption key) is generated at
runtime and never written to a file tracked by git. The one exception is here, and only here, for 
one reason: to let someone evaluating this repository decrypt a real, already-published artifact 
without creating a Hugging Face account, without a write token, and without publishing anything 
themselves.

**Never reuse this pattern for anything real.** This key protects nothing sensitive — the
decrypted content is the same small, public, open-weights BERT model this repository already
encrypts in every other example — and it is committed here for exactly one purpose: decrypting
the one pinned demo artifact below. If you fork this repository to distribute an actual model,
generate your own key with `model_pipeline keygen` as documented in the main `README.md`, and
never commit it.

## What's in this directory

- `encryption-key`: the base64-encoded AES-256 key the demo artifact below was encrypted with.

## The pinned demo artifact

Published to the same public repository used throughout this project's walkthrough
(`jecaro/bert-tiny-encrypted`), under the version `demo` — a name chosen so it's never confused
with one of the numbered, real versions used elsewhere.

```bash
source .venv/bin/activate   # after `pip install -e ".[consumer,dev]"`, see the main README

ENCRYPTION_KEY_FILE=demo/encryption-key \
  python -m model_pipeline consume \
    --repo jecaro/bert-tiny-encrypted \
    --version demo \
    --workdir /tmp/model \
    --smoke-test
```

No `HF_TOKEN` needed: the repo is public, and this command only downloads and decrypts. This runs
the full consumer path — download, decryption, model loading, and a smoke test — against a real
published artifact, in one command.

Remove `--workdir` once you're done inspecting the decrypted model (`rm -rf /tmp/model`).
