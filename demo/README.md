# Demo key material — for this pinned demo artifact only

key material to git.** Every other key in this project (the real encryption key, the real signing
key) is generated at runtime and never written to a file tracked by git. The one exception is here,
and only here, for one reason: to let someone evaluating this repository decrypt and verify a real,
already-published artifact without creating a Hugging Face account, without a write token,
and without publishing anything themselves.

**Never reuse this pattern for anything real.** These keys protect nothing sensitive — the
decrypted content is the same small, public, open-weights BERT model this repository already
encrypts in every other example — and they are committed here for exactly one purpose: decrypting
the one pinned demo artifact below. If you fork this repository to distribute an actual model,
generate your own key with `model_pipeline keygen`/`signing-keygen` as documented in the main
`README.md`, and never commit it.

## What's in this directory

- `encryption-key`: the base64-encoded AES-256 key the demo artifact below was encrypted with.
- `signing-public-key.pem`: the Ed25519 public key that verifies the demo artifact's signature.
  Its matching private key was used once, to sign that artifact, and was discarded — it was never
  committed, and no one (including whoever generated it) can sign a new "demo" version with it.

## The pinned demo artifact

Published to the same public repository used throughout this project's walkthrough
(`jecaro/bert-tiny-encrypted`), under the version `demo-signed` — a name chosen so it's never
confused with one of the numbered, real versions used elsewhere.

```bash
source .venv/bin/activate   # after `pip install -e ".[consumer,dev]"`, see the main README

ENCRYPTION_KEY_FILE=demo/encryption-key SIGNING_PUBLIC_KEY_FILE=demo/signing-public-key.pem \
  python -m model_pipeline consume \
    --repo jecaro/bert-tiny-encrypted \
    --version demo-signed \
    --workdir /tmp/model \
    --smoke-test
```

No `HF_TOKEN` needed: the repo is public, and this command only downloads and decrypts. This runs
the full consumer path — signature verification, download, decryption, model loading, and a smoke
test — against a real published artifact, in one command.
