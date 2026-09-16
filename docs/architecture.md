# Architecture

This document describes the data flow, the encrypted container format, and the manifest published
alongside it. For *why* each choice was made over its alternatives, see [`decisions.md`](decisions.md).

## Data flow

```text
+-------------------------------------------------------------------+
|                       Kubernetes (minikube)                       |
|                                                                    |
|  Secret: hf-credentials       Secret: model-encryption-key        |
|        | (hf-token)                 | (encryption-key, 32 bytes)  |
|        |                            +---------------+             |
|        v                            v               v             |
|  +---------------------------+  +---------------------------+     |
|  | Job: model-producer       |  | Pod: model-consumer        |    |
|  |                           |  |                             |    |
|  | 1. snapshot_download()    |  | 1. read key from mounted    |    |
|  | 2. tar the snapshot       |  |    file (0440)               |    |
|  | 3. AES-256-GCM per chunk  |  | 2. download .enc + manifest |    |
|  | 4. manifest.json (hashes) |  | 3. verify hashes             |    |
|  | 5. upload to the Hub      |  | 4. decrypt onto tmpfs         |    |
|  |                           |  | 5. load model + inference     |    |
|  +-----------+---------------+  +--------------^--------------+    |
|              |                                  |  tmpfs volume    |
+--------------|----------------------------------|-------------------+
               | push (needs HF_TOKEN)            | pull (public repo,
               v                                   |       no token)
      +----------------------------------------------------+
      | Hugging Face Hub -- <namespace>/bert-tiny-encrypted |
      |   versions/1.0.0/model.tar.enc   (opaque)           |
      |   versions/1.0.0/manifest.json   (no key material)  |
      +----------------------------------------------------+
                       ^
                       | snapshot_download (public plaintext model)
              google/bert_uncased_L-2_H-128_A-2
```

**Security invariant**: Hugging Face stores the artifact but can never decrypt it. The key only
ever exists inside the cluster (etcd and the memory of the pod that mounts it). The manifest is
public and contains no cryptographic material.

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

`manifest.json` is published next to the artifact and never carries key material:

```json
{
  "manifest_version": "1.0",
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
  "producer": { "tool": "model_pipeline", "tool_version": "0.1.0" }
}
```

Notable fields:

- `key_id` is a **label** (the name of the Secret), not the key or a hash of it. It lets the
  consumer detect it is holding the wrong key before spending time decrypting.
- `plaintext_sha256` verifies the decryption end to end. Publishing it is a deliberate choice: the
  source model is already named in the manifest and is public, so this adds no new disclosure. In a
  scenario where the source model itself were confidential, this field would be omitted or moved
  inside the encrypted payload.
- The consumer checks `sha256` **before** decrypting (catches corruption in transit) and
  `plaintext_sha256` **after** (catches an incorrect or incomplete decryption).
- This manifest is exactly what a future signature would cover: one signature over the manifest is
  enough, because the manifest already commits to the artifact's hash.
