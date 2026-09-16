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
- **Secrets never live in code, in the git repository, or in the Docker images.** The decryption
  key and the Hugging Face write token are only ever injected at runtime, through a Kubernetes
  Secret or an environment variable read at process start.

## What this does not protect

- **A cluster administrator can read the Secret directly** (`kubectl get secret -o yaml`). Nothing
  in this layer restricts who inside the cluster can access the key once it exists there.
- **Kubernetes Secrets are base64-encoded, not encrypted, in etcd**, unless encryption-at-rest is
  separately enabled on the cluster. This pipeline does not configure or assume that.
- **The node operator sees the plaintext model in the pod's memory** and can inspect the running
  process. Decrypting onto a `tmpfs` volume instead of the node's disk reduces exposure — the
  plaintext never survives on persistent storage — but does not eliminate this threat; the
  plaintext is still resident in RAM the operator's hypervisor or host access can reach.
- **No proof of who published an artifact.** Anything with write access to the target Hugging Face
  repo can overwrite a version (barring the producer's own immutability check) or publish a new one
  under the same manifest shape, and a consumer has no way to distinguish a legitimate publisher
  from an attacker who obtained write access. Closing this requires **signing the manifest** —
  asymmetrically, with Ed25519 or Sigstore/cosign — and having the consumer verify that signature
  before trusting the manifest's hashes. The manifest is already designed for this: one signature
  over it is enough, because it commits to the artifact's hash.
- **The consumer must trust whatever host hands it the key.** Mounting a Secret assumes the node
  running the pod is not compromised and is exactly who it claims to be; there is no mechanism here
  that verifies the node's integrity before the key is released to it. Closing this requires
  **attestation-gated key release** — replacing the Secret mount with a request to a Confidential
  Containers key broker (Trustee KBS) that only releases the key after the node proves, via remote
  attestation, that it is running the expected, unmodified workload inside a Kata/Confidential
  Containers sandbox.

## Why this is the right line to draw here

The two gaps above — origin authenticity and node trust — are exactly the two further layers the
exercise defines on top of this one. Recognizing them precisely, rather than either ignoring them
or trying to informally patch around them within this layer, is what this document is for: it is
the case for treating them as separate, well-understood extensions (see `docs/decisions.md`)
instead of scope creep on this PoC.
