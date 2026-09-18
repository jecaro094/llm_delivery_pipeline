# Architecture

This document describes the data flow, the encrypted container format, and the manifest published
alongside it. For *why* each choice was made over its alternatives, see [`decisions.md`](decisions.md).

## Data flow

```text
+-----------------------------------------------------------------------+
|                          Kubernetes (minikube)                        |
|                                                                        |
|  Secret: hf-credentials      Secret: model-encryption-key             |
|  Secret: model-signing-key             ConfigMap: model-signing-public-key
|      |          |                  |                |                |
|      v          v                  |                v                |
|  +---------------------------+     |    +---------------------------+
|  | Job: model-producer       |     |    | Pod: model-consumer       |
|  |                           |     |    |                           |
|  | 1. snapshot_download()    |     |    | 1. read public key (file) |
|  | 2. tar the snapshot       |     |    | 2. download manifest+.sig |
|  | 3. AES-256-GCM per chunk  |     |    | 3. VERIFY signature: abort|
|  | 4. build manifest.json    |     |    |    on failure             |
|  | 5. sign manifest (Ed25519)|     +--->| 4. read decryption key    |
|  | 6. upload .enc/.sig/.json |          | 5. download .enc          |
|  |                           |          | 6. verify hashes, decrypt |
|  +-----------+---------------+          | 7. unpack onto tmpfs, load|
|              |                          +--------------^------------+
+--------------|-------------------------------------------|-------------+
               | push (needs HF_TOKEN)                      | pull (public
               v                                             |  repo, no token)
      +--------------------------------------------------------------+
      | Hugging Face Hub -- <namespace>/bert-tiny-encrypted           |
      |   versions/1.0.0/model.tar.enc       (opaque)                 |
      |   versions/1.0.0/manifest.json       (signed payload)         |
      |   versions/1.0.0/manifest.json.sig   (64-byte Ed25519)        |
      +--------------------------------------------------------------+
                       ^
                       | snapshot_download (public plaintext model)
              google/bert_uncased_L-2_H-128_A-2
```

Note what the diagram does *not* show: any arrow from the Hub to the consumer's public key. The
`model-signing-public-key` ConfigMap arrow comes from the cluster only — a public key fetched from
the same repository that serves the artifact would not be a trust anchor (see decision 18 in
`decisions.md`).

**Security invariants**:

- Hugging Face stores the artifact but can never decrypt it. The decryption key only ever exists
  inside the cluster (etcd and the memory of the pod that mounts it). The manifest is public and
  contains no cryptographic material.
- Hugging Face — or anyone who gains write access to the artifact repo — can serve arbitrary bytes,
  but cannot make the consumer accept them. The only party whose artifacts the consumer will load is
  the holder of the private signing key, and that key never leaves the producer's Secret.

These two invariants are independent: encryption without signing gives confidentiality but no
origin authenticity (AES-GCM's tag proves the artifact came from someone holding the *encryption*
key — and the consumer holds that key too, so it proves nothing about *who* published it); signing
without encryption would give authenticity but no confidentiality. Combined, the consumer knows both
that nobody read the model in transit and that the producer is who published it.

## Where the decrypted model lives

Three different paths hold three different kinds of data, and only one of them is sensitive:

| Where | What lives there | Path |
| --- | --- | --- |
| Consumer Pod, in-cluster | the **decrypted plaintext model** | `/mnt/model`, an `emptyDir` with `medium: Memory` (tmpfs) — never touches the node's disk, gone when the pod terminates |
| Producer/consumer containers | the Hugging Face Hub cache | `/tmp` (`HF_HOME=/tmp/huggingface`), a plain disk-backed `emptyDir` — non-sensitive, exists only so a `readOnlyRootFilesystem: true` container has a writable scratch path |
| A local run (Options 2, the fast path, `demo/README.md`) | the **decrypted plaintext model** | an operator-owned throwaway directory the run creates and removes itself, never a fixed `/tmp` path |

The plaintext model is treated the same way in all three contexts: never written to shared,
persistent, world-readable storage, and cleaned up automatically or by the operator once it is no
longer needed. `/tmp` is only ever used for the non-sensitive Hub cache, never for the model
itself — see [`decisions.md`](decisions.md#local-runs-outside-kubernetes-do-not-decrypt-into-tmp-either)
for the full reasoning.

## Encrypted container format

A small, self-describing container, not a third-party format, so every field is intentional and
inspectable:

```text
+-----------------------------------------------------------------+
| magic      "MDLENC\0"                                8 bytes    |  (7 bytes + a NUL separator)
| header_len uint32 big-endian                          4 bytes   |
| header     JSON UTF-8                        header_len bytes   |
+-----------------------------------------------------------------+
| chunk 0:  uint32 len | ciphertext + GCM tag (16 bytes)          |
| chunk 1:  uint32 len | ciphertext + GCM tag (16 bytes)          |
| ...                                                              |
+-----------------------------------------------------------------+
```

`header` (plaintext, and authenticated as additional data for every chunk):

```json
{
  "format_version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "HKDF-SHA256",
  "salt": "<16 random bytes, hex-encoded, unique per artifact>",
  "chunk_size": 4194304
}
```

### Key derivation

The master key held in the Kubernetes Secret is never used to encrypt directly:

```text
file_key = HKDF-SHA256(master_key, salt=<random salt>, info=b"model-pipeline/v1")
```

This lets the container use **deterministic, counter-based nonces** (`nonce_i = i`, 12 bytes
big-endian) with no risk of nonce reuse across artifacts, which is the classic catastrophic failure
mode of GCM: every artifact has its own random salt, so every artifact has its own `file_key`, so
the same nonce value under two different artifacts never encrypts under the same key.

### Authenticated data per chunk

```text
AAD_i = SHA256(header) || uint32_be(i) || (0x01 if this is the last chunk, else 0x00)
```

This binds each chunk to the header, its own index, and whether it is the final chunk, which
detects:

- **Header tampering** — any change to `chunk_size` or the salt invalidates every chunk's AAD.
- **Chunk reordering** — a chunk decrypted at the wrong index fails authentication.
- **Truncation** — removing trailing chunks means the last remaining chunk's `is_last` flag no
  longer matches what it was encrypted with, so decryption fails loudly instead of silently
  producing an incomplete model.
- **Cross-artifact mixing** — a chunk from one artifact decrypted as part of another fails, because
  the AAD binds to that specific header's hash.

### Why the model is packaged as a tar before encryption

A single artifact per version keeps the manifest, upload, and verification simple, and it also
hides the file names and file count of the model — metadata that would otherwise leak
file-by-file. The tradeoff is that the archive cannot be partially decrypted, which this use case
does not need. Extraction uses path-traversal-safe filtering (validated destination paths, no
absolute or `..`-escaping members).

## Manifest

`manifest.json` is published next to the artifact and never carries key material — including its
own signature, see below:

```json
{
  "manifest_version": "2.0",
  "created_at": "2026-09-15T10:00:00Z",
  "model": {
    "source_repo": "google/bert_uncased_L-2_H-128_A-2",
    "source_revision": "<commit sha resolved at download time>",
    "task_hint": "fill-mask"
  },
  "artifact": {
    "version": "1.0.0",
    "path": "versions/1.0.0/model.tar.enc",
    "size_bytes": 17825792,
    "sha256": "<hash of the encrypted file>",
    "plaintext_sha256": "<hash of the plaintext tar>",
    "plaintext_size_bytes": 17612345
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "kdf": "HKDF-SHA256",
    "chunk_size_bytes": 4194304,
    "format_version": 1,
    "key_id": "model-encryption-key"
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key_sha256": "<hex SHA-256 of the raw 32-byte public key>",
    "signature_path": "versions/1.0.0/manifest.json.sig"
  },
  "producer": { "tool": "model_pipeline", "tool_version": "0.1.0" }
}
```

Notable fields:

- `key_id` is a **label** (the name of the Secret), not the key or a hash of it. It lets the
  consumer detect it is holding the wrong decryption key before spending time decrypting.
- `plaintext_sha256` verifies the decryption end to end. Publishing it is a deliberate choice: the
  source model is already named in the manifest and is public, so this adds no new disclosure. In a
  scenario where the source model itself were confidential, this field would be omitted or moved
  inside the encrypted payload.
- The consumer checks `sha256` **before** decrypting (catches corruption in transit) and
  `plaintext_sha256` **after** (catches an incorrect or incomplete decryption).
- `signature.public_key_sha256` is a content-derived fingerprint, unlike `encryption.key_id`, which
  is only a label. That asymmetry is deliberate: the encryption key is secret, so publishing any
  digest of it would hand an offline verification oracle to anyone checking key guesses, hence a
  name instead. The signing *public* key is public by construction, so a hash of it leaks nothing
  and is strictly more useful than a name — the consumer computes the fingerprint of the key it
  actually mounted and compares, turning "the signature did not verify" into "you mounted the wrong
  public key" (see `cmd_verify` and `_download_and_verify_manifest` in `consumer.py`).
- The `signature` section cannot contain the signature itself: the manifest is the signed payload,
  so a field containing its own signature would be circular. The signature bytes live in the
  detached `manifest.json.sig` file instead.
- The section is *inside* the signed bytes, but the consumer never uses its `algorithm` or
  `public_key_sha256` fields to *choose* how to verify or which key to trust — both are fixed by the
  consumer's own configuration (the mounted public key), and the manifest fields are only
  cross-checked against them afterwards. Letting a document nominate its own verification algorithm
  or key is the classic `alg: none` / algorithm-confusion bug, and this design avoids it by
  construction.

## Signing and verification

The producer signs the manifest, never the plaintext or even the encrypted artifact bytes directly
(see decision 14 in `decisions.md`):

```text
manifest_bytes = serialize_manifest(artifact_manifest)
signature_bytes = signing.sign(manifest_bytes, signing_private_key)   # Ed25519, 64 bytes
```

`producer.py` passes that exact `manifest_bytes` object to `hub.upload_artifact`, never a
re-serialization, so the bytes signed and the bytes published are provably identical. Upload order
is artifact, then signature, then manifest last: uploads to Hugging Face are three separate,
non-atomic calls, and a manifest download is the consumer's first step, so a partial publish looks
like "version not published yet" rather than "version published but unverifiable."

The consumer verifies *before* parsing the manifest as JSON, before downloading the artifact, and
before reading the decryption key (`consumer._download_and_verify_manifest`):

1. Load the public key from its mounted file. Missing or unreadable → abort, before any network I/O.
2. Download `manifest.json` and `manifest.json.sig` (raw bytes).
3. `signing.verify(manifest_bytes, signature_bytes, public_key)` on the raw bytes — no JSON parsing
   happens until this succeeds, since parsing attacker-supplied bytes before they are authenticated
   is an attack surface this design has no reason to accept.
4. Only now is the manifest deserialized, and two cheap cross-checks run: the signed
   `artifact.version` against the version requested (closes a rollback path where an attacker with
   repo write access deletes a new version and leaves an older, genuinely signed one in place), and
   the signed `signature.public_key_sha256` against the fingerprint of the key that was actually used
   to verify (turns a cryptic failure into "you mounted the wrong public key"). Neither cross-check
   ever selects *which* key verifies the signature — that is always the mounted `public_key`.
5. The rest of the existing flow — download the artifact, check `sha256`, decrypt, check
   `plaintext_sha256`, unpack — proceeds unchanged.

There is no unsigned path: a missing public key, a missing `.sig` file, a failed verification, or a
manifest whose `manifest_version` predates signing all abort with a non-zero exit (decision 19).
