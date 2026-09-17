# Threat model

This is a short, honest account of what this pipeline protects and what it deliberately does not,
because the gap between the two is exactly why the underlying exercise defines further layers on
top of this one.

## What this protects

- **Confidentiality of the model at rest on Hugging Face and in transit.** The Hub, its operator,
  and anyone with access to the repository see only ciphertext; the repository is public precisely
  to demonstrate that this is not a secrecy-through-obscurity scheme.
- **Integrity of the artifact.** Tampering, truncation, or reordering of the encrypted container's
  chunks is detected before the model is ever loaded, via AES-GCM's authentication tag combined
  with per-chunk additional authenticated data (see `docs/architecture.md`). Corruption of the
  published files themselves is caught by the manifest's `sha256`/`plaintext_sha256` checks.
- **Origin authenticity.** The consumer verifies an Ed25519 signature over the manifest before
  trusting anything in it, using a public key that arrives only through the cluster (a ConfigMap),
  never through the Hugging Face repo the artifact itself is served from. Hugging Face — or anyone
  who gains write access to the artifact repo — can serve arbitrary bytes, but cannot make the
  consumer accept them: the only party whose artifacts the consumer will load is the holder of the
  private signing key, and that key never leaves the producer's Secret.
- **Rollback, partially.** The signed `artifact.version` is cross-checked against the version the
  consumer actually requested, so an attacker with repo write access cannot silently substitute an
  older, genuinely signed version for the one asked for by version number. This is not full replay
  protection (see below).
- **Secrets never live in code, in the git repository, or in the Docker images.** The decryption
  key, the signing private key, and the Hugging Face write token are only ever injected at runtime,
  through a Kubernetes Secret or an environment variable read at process start.

## What this does not protect

- **A cluster administrator can read the Secret directly** (`kubectl get secret -o yaml`), including
  now the signing private key and the decryption key alike. Nothing in this layer restricts who
  inside the cluster can access either key once it exists there.
- **Kubernetes Secrets are base64-encoded, not encrypted, in etcd**, unless encryption-at-rest is
  separately enabled on the cluster. This pipeline does not configure or assume that.
- **The node operator sees the plaintext model in the pod's memory** and can inspect the running
  process. Decrypting onto a `tmpfs` volume instead of the node's disk reduces exposure — the
  plaintext never survives on persistent storage — but does not eliminate this threat; the
  plaintext is still resident in RAM the operator's hypervisor or host access can reach.
- **A compromised producer signs malicious content perfectly validly.** Signing proves origin, not
  good intent: if the machine or credentials that hold the signing key are compromised, everything
  it signs is, by definition, validly signed.
- **A cluster administrator can replace the trust anchor itself.** Overwriting the
  `model-signing-public-key` ConfigMap with an attacker-controlled key, then serving artifacts
  signed by the matching private key, passes every check this layer performs. This layer moves the
  trust anchor from the Hub into the cluster; it does not remove the need to trust the cluster. That
  is exactly what attestation-gated key release (below) addresses.
- **Full rollback / replay protection.** An attacker with repo write access can still delete a newer
  version and leave an older, genuinely signed one in place under a version number the consumer was
  never told to avoid. The per-request version cross-check (above) only catches the case where the
  consumer names the version it expects; it is not a substitute for a transparency log or a
  monotonically pinned version, which is out of scope here.
- **Availability.** Nothing here stops the repo from being emptied.
- **The consumer must trust whatever host hands it either key.** Mounting a Secret or a ConfigMap
  assumes the node running the pod is not compromised and is exactly who it claims to be; there is
  no mechanism here that verifies the node's integrity before either key is released to it. Closing
  this requires **attestation-gated key release** — replacing the Secret/ConfigMap mounts with a
  request to a Confidential Containers key broker (Trustee KBS) that only releases key material
  after the node proves, via remote attestation, that it is running the expected, unmodified
  workload inside a Kata/Confidential Containers sandbox.

## Why this is the right line to draw here

The remaining gap — node trust — is exactly the further layer the exercise defines on top of this
one. Recognizing it precisely, rather than either ignoring it or trying to informally patch around
it within this layer, is what this document is for: it is the case for treating it as a separate,
well-understood extension (see `docs/decisions.md`) instead of scope creep on this PoC.
