# Architecture decision records

Each record states the decision, the alternatives considered, and why the decision won. They are
listed in the order the pipeline touches them: model, cluster, cryptography, workload shape, key
delivery, artifact versioning, repository visibility, CI scope, image layout, how the application
talks to Kubernetes, and — decisions 12 onward — the signing and verification step layered on top.

## 1. Source model: `google/bert_uncased_L-2_H-128_A-2`

**Alternatives considered**: `prajjwal1/bert-tiny`, `distilbert-base-uncased`, `Qwen3-8B`.

**Decision**: use `google/bert_uncased_L-2_H-128_A-2` (~17 MB), configurable via `--source-model`.

**Why**: the exercise explicitly calls for a small model. This one completes the full cycle in
seconds, fits comfortably inside minikube and a CI runner, and the pipeline treats the model as a
parameter rather than a fixed value, so any compatible model works unchanged.

It is architecturally the same BERT-tiny (2 layers, 128 hidden size) as `prajjwal1/bert-tiny`,
which was tried first and rejected: that repo's real, published `config.json` on the Hub has no
`model_type` key, so `transformers.pipeline` cannot auto-detect its architecture. This only
surfaced when running the full cycle for real against Hugging Face — a mocked `transformers` in
tests never exercises architecture auto-detection, so the incompatibility was invisible until a
real `docker run` produce+consume cycle. The producer now validates `model_type` presence before
encrypting anything, so this class of failure is caught immediately instead of surfacing only when
the consumer tries to load the model.

## 2. Local Kubernetes: minikube

**Alternatives considered**: kind, Docker Desktop's Kubernetes, k3d.

**Decision**: minikube.

**Why**: the de facto standard for local development, extensively documented, and
`minikube image load` lets the manifests reference locally built images with no registry. The
manifests themselves are otherwise distribution-agnostic.

## 3. Encryption: AES-256-GCM in chunks

**Alternatives considered**: Fernet (AES-128-CBC + HMAC), `age`/ChaCha20-Poly1305, envelope
encryption (DEK/KEK).

**Decision**: AES-256-GCM, applied per chunk (see `docs/architecture.md` for the container format
and the chunk AAD scheme).

**Why**: GCM is an AEAD — confidentiality and integrity from a single primitive — and benefits from
AES-NI hardware acceleration on any modern CPU. Chunking allows streaming the model without loading
it entirely into memory. Fernet was rejected because it is AES-128 and has no native streaming
mode. Envelope encryption (a data-encryption key wrapped by a key-encryption key) is closer to how
production systems manage keys, but it adds complexity this layer does not need; it is the natural
next step toward attestation-gated key release, documented as a future extension.

## 4. The producer runs as a Kubernetes Job

**Alternatives considered**: running locally with Docker only, running as a GitHub Actions job.

**Decision**: a Kubernetes Job (`restartPolicy: Never`, `backoffLimit: 2`), with the same container
image also runnable locally via `docker run`.

**Why**: the exercise frames the pipeline as running inside a Kubernetes environment. A Job also
lets the producer and consumer share the same Secret-mounting mechanism and gives more manifest
surface to demonstrate (resource requests/limits, security context, Secret projection) than a
purely local script would.

## 5. The consumer decrypts onto a `tmpfs` `emptyDir`

**Alternatives considered**: the container's `/tmp`, a disk-backed `emptyDir`, decrypting entirely
in memory with no filesystem at all.

**Decision**: `emptyDir` with `medium: Memory`, mounted at `/mnt/model`, with an explicit
`sizeLimit` (256Mi for this model size).

**Why**: the plaintext model is never written to the node's disk and disappears once the pod
terminates. Fully in-memory decryption with no filesystem would be purer, but `transformers`
expects file paths to load a model from, which would force fragile workarounds; tmpfs gets 95% of
the benefit with straightforward, robust code.

### Local runs (outside Kubernetes) do not decrypt into `/tmp` either

Not part of the original decision table, but the same reasoning applies once `consume` runs
directly on a workstation (Option 2, the fast path, and `demo/README.md`) rather than inside the
Pod above. Early versions of those docs pointed `--workdir` at `/tmp/model`.

**Alternatives considered**: a fixed path under `/tmp`, an operator-chosen throwaway directory.

**Decision**: every local-run example uses a throwaway directory the operator creates and removes
themselves (e.g. `mktemp -d`, or any directory outside `/tmp`), never a fixed `/tmp` path.

**Why**: `/tmp` on Linux is normally a real, on-disk, world-readable filesystem shared between every
user and process on the machine — using it for the decrypted model would demonstrate exactly the
disk exposure this pipeline's architecture avoids in the Kubernetes case above (macOS's per-user
`/tmp` is still disk-backed). Nothing removes it either: the model sits there, readable by other
local accounts, until the OS eventually reclaims it, which on macOS can take days. A fixed,
predictable path also invites collisions between concurrent local runs. `/tmp` remains the right
choice for the *non-sensitive* Hugging Face Hub cache inside the container image (`HF_HOME=/tmp/huggingface`),
which exists only to satisfy `readOnlyRootFilesystem: true` and is discarded with the pod — that
case is unrelated to where the plaintext model itself lands.

## 6. The decryption key is delivered as a mounted file, not an environment variable

**Alternatives considered**: `env.valueFrom.secretKeyRef`.

**Decision**: the Secret is mounted as a file (`/etc/model-keys/encryption-key`, `defaultMode:
0440`, `readOnly: true`); `ENCRYPTION_KEY` as a literal value remains supported only for local,
file-less execution outside Kubernetes.

**Why**: a mounted file updates automatically when the Secret rotates, never appears in
`/proc/<pid>/environ`, is not inherited by child processes, and does not end up in crash dumps or
debug logs the way an environment variable can. The exercise also states literally that the
workload "mounts the decryption key."

A consequence discovered by running the real Job and Pod on minikube, not visible from the
manifests alone: Kubernetes mounts Secret volumes owned by `root` regardless of `defaultMode`, so a
non-root container (`runAsUser: 1000`) could not read the file without also setting
`securityContext.fsGroup: 1000` on the pod. Both `k8s/producer-job.yaml` and `k8s/consumer-pod.yaml`
set it for this reason.

## 7. Explicit artifact versioning with a signable manifest

**Alternatives considered**: publishing a single unversioned artifact at the root of the repo.

**Decision**: every artifact lives under `versions/<version>/`, next to a `manifest.json` that
records its hashes (see `docs/architecture.md`).

**Why**: this lets a consumer verify integrity before decrypting, unambiguously identifies which
artifact it is looking at, and is the natural hook for a future signature: sign the manifest once,
instead of every file, because the manifest already commits to the artifact's hash. The producer
also refuses to overwrite a version that already exists, treating published artifacts as immutable.

Deliberately not implemented: having the producer silently pick the next version and publish under
it when the requested one is taken. Which version comes next is a semantic versioning judgment call
(a patch bump is not always the right one), so it belongs to whoever is publishing, not to the
pipeline. Instead, `produce()` fails fast and its error names the next version that *would* be
available (a plain dotted-integer bump past the highest existing version, or no suggestion at all
when the existing versions do not follow that scheme), so the operator can decide and retry
explicitly — `scripts/demo.sh --version <suggested>` for the demo path, or `--version` on the CLI
directly.

## 8. The Hugging Face repo holding the encrypted artifact is public

**Alternatives considered**: a private repo with a read token distributed to the consumer.

**Decision**: the target repo is always created and used as public; there is no `--public` flag to
opt out (`hub.ensure_public_repo()` always passes `private=False`).

**Why**: this is the strongest demonstration of the security model — the ciphertext can be public
because **all** of the security lives in the key, which never leaves the cluster. It also produces
a clean asymmetry: the producer needs a Hugging Face token with write access, the consumer needs
none at all, because it only ever reads from a public repo.

## 9. CI only validates; it publishes nothing

**Alternatives considered**: publishing images to GHCR, running the full pipeline through to
Hugging Face from CI.

**Decision**: `.github/workflows/ci.yml` runs
`quality -> test -> security -> k8s-manifests -> build`, with `build` gated on `quality` and
`test` via `needs:`, and never touches any secret.

**Why**: no credentials live in CI, the workflow is always green and reproducible by anyone who
clones the repository, and gating `build` on the earlier jobs satisfies the requirement that
nothing gets built if validation fails, without depending on any credential to prove it. Publishing
to Hugging Face from a manual (`workflow_dispatch`) job using repository secrets is a natural
extension, deliberately left out here.

The `k8s-manifests` job runs `kubectl apply -k k8s/ --dry-run=server` against an ephemeral `kind`
cluster. `kind` (not minikube) is used only here because it runs Kubernetes nodes as plain Docker
containers, needing no KVM/nested virtualization, so it boots in seconds on any GitHub-hosted
runner. A server-side dry run validates the manifests against a real API server (schema, enum
values, immutability rules) without persisting any object, so it needs neither the Secrets nor the
container images the real workloads depend on. This only catches structural mistakes in the
manifests; it cannot prove the pipeline behaves correctly at runtime with real credentials and a
real Hugging Face artifact, which is exactly the part deliberately left to the local minikube demo
described in the README.

## 10. Two separate Dockerfiles

**Alternatives considered**: a single multi-stage Dockerfile with a producer and a consumer target.

**Decision**: `docker/Dockerfile.producer` and `docker/Dockerfile.consumer`.

**Why**: literal compliance with the deliverable, and more importantly, the producer image needs no
PyTorch (it stays in the tens of MB) and the consumer image needs no Hugging Face write client.
Each workload gets a smaller attack surface and a faster build than a shared multi-stage image
would give either of them.

## 11. The Python application never talks to the Kubernetes API

**Alternatives considered**: reading the Secret through the Kubernetes API with a `ServiceAccount`
and RBAC.

**Decision**: the code only ever reads a file at a configured path or an environment variable
(`model_pipeline.settings.Settings`, `model_pipeline.keys`); the `ServiceAccount` used by both
workloads sets `automountServiceAccountToken: false`.

**Why**: the same binary runs identically locally, in Docker, in CI, and in Kubernetes, with no
Kubernetes-specific code path to test separately. Not projecting a service account token into
either pod also removes a credential neither workload needs.

## 12. Signature algorithm: Ed25519

**Alternatives considered**: RSA-PSS (3072/4096-bit), ECDSA P-256, Sigstore/cosign, GPG detached
signatures, in-toto/SLSA attestations.

**Decision**: Ed25519, via the `cryptography` package already in the base dependencies.

**Why**: Ed25519 signing is deterministic (RFC 8032) — the per-signature nonce is derived from the
key and the message, so there is no per-signature randomness to get wrong. That rules out the
failure mode that has repeatedly broken real-world ECDSA deployments, where a repeated or
predictable nonce leaks the private key outright; it is the same class of argument behind the
counter-nonce design in decision 3. Keys are 32 bytes and signatures 64 bytes, negligible next to
the artifact. It adds no new production dependency: `cryptography` already ships in both images.
RSA-PSS works but carries more parameters to choose badly (key size, padding, MGF, salt length) and
much larger keys and signatures.

## 13. Encrypt, then sign — the signature covers ciphertext, never plaintext

**Alternatives considered**: sign the plaintext tar before encrypting; sign both.

**Decision**: the producer signs the manifest only after `crypto.encrypt` has produced the
ciphertext; nothing plaintext is ever signed.

**Why**: signing the ciphertext lets the consumer reject a forged or tampered artifact without ever
using the decryption key — an attacker-controlled blob is never fed to the AES-GCM decryptor.
Signing the plaintext would force decrypting attacker-supplied data before learning whether to
trust it, inverting the point of this layer. It also keeps verification (the `verify` subcommand)
runnable by a party holding no decryption key at all.

## 14. The signed payload is the canonical `manifest.json`, not the raw artifact bytes

**Alternatives considered**: sign `model.tar.enc` directly; sign both separately.

**Decision**: `signing.sign()` is called on `serialize_manifest(artifact_manifest)`, and the
manifest already contains `artifact.sha256` over the encrypted container.

**Why**: one signature over the manifest transitively authenticates the artifact **and** every
piece of metadata around it (version, source model, source revision, chunk size, format version,
plaintext hash), for the cost of signing a few hundred bytes instead of streaming the whole
container twice. Signing only the artifact bytes would leave the manifest itself unsigned and
therefore substitutable — an attacker could keep a genuine artifact and rewrite its recorded
provenance. Decision 7 already anticipated this move: the manifest was designed from the start so
that one signature over it would be enough.

## 15. Detached signature, published as its own file

**Alternatives considered**: a `signature` field inside `manifest.json`; a signature block appended
to `model.tar.enc`; embedding the signature in the encrypted container header.

**Decision**: `manifest.json.sig`, 64 raw Ed25519 signature bytes, no base64 or PEM encoding.

**Why**: a signature stored inside the document it signs has to define precisely which bytes are
excluded from the signed payload, and that canonicalization rule is a recurring source of real
signature-bypass bugs. Detached keeps an unambiguous invariant instead: the bytes published as
`manifest.json` are byte-for-byte the bytes that were signed (`producer.py` passes the exact
`manifest_bytes` it signed straight to `hub.upload_artifact`, never a re-serialization). Appending
the signature to the container, or into its header, would also mix signing concerns into the
encryption format for no benefit — see decision 16.

## 16. The encrypted container format is unchanged

**Alternatives considered**: bump `crypto.py`'s `FORMAT_VERSION` to carry signature metadata.

**Decision**: `crypto.py`, `MAGIC`, and `FORMAT_VERSION` are untouched by this layer.

**Why**: keeps the two cryptographic concerns strictly separate — `crypto.py` knows nothing about
signatures, and `signing.py` knows nothing about AES — and every artifact already published under
format version 1 stays byte-compatible. Only the metadata layer around the container changes.

## 17. The private signing key lives in its own Kubernetes Secret

**Alternatives considered**: adding a second key to the existing `model-encryption-key` Secret.

**Decision**: `model-signing-key`, mounted only by the producer Job, at
`/etc/model-signing/signing-key.pem`; the consumer Pod has no mount path for it at all.

**Why**: separate secrets mean separate mounts and separate blast radius, the same
least-privilege-per-workload argument as decision 6. The consumer not having a mount path for the
signing key is a stronger property than "a permission it declines to use" — the key material simply
does not exist anywhere the consumer's pod spec can reach. The two keys also have unrelated
lifecycles and rotation cadences.

## 18. The public verification key reaches the consumer through a Kubernetes ConfigMap, never from the Hugging Face repo

**Alternatives considered**: publishing the public key next to the artifact and having the consumer
fetch it from the Hub; baking the key into the consumer image; pinning only a fingerprint and
fetching the key from the Hub.

**Decision**: `model-signing-public-key`, mounted as a file at
`/etc/model-signing-pub/public-key.pem`, read by `keys.resolve_signing_public_key`.

**Why**: this is the crux of the whole layer. A public key fetched from the same repository that
serves the artifact is not a trust anchor — an attacker able to rewrite the repo rewrites the key
and the signature together, and verification degenerates into a self-consistent no-op. The
verification key must arrive over a channel the attacker of the artifact channel does not control;
here, that channel is the cluster. Mounting it as a file also reuses the pattern the consumer
already implements for the decryption key (decision 6), so the application code stays "read a file
at a path," with no Kubernetes API dependency (decision 11). A ConfigMap rather than a Secret
because the key is public by definition; storing it as a Secret would misrepresent its sensitivity.

## 19. Fail closed: no unsigned path, no verification bypass flag

**Alternatives considered**: an `--insecure-skip-verify` flag; silently skipping verification when
no public key is configured; accepting a manifest with no signature section.

**Decision**: `consume()` and `verify_published_version()` always verify; a missing public key,
missing `manifest.json.sig`, failed verification, or a manifest whose `manifest_version` predates
signing (`deserialize_manifest` rejects anything other than the current `const.MANIFEST_VERSION`,
now `"2.0"`) all abort with a non-zero exit and no unsigned fallback path exists in the code.

**Why**: a verification step that can be turned off by a flag or by omitting a file is a downgrade
attack waiting to happen, and it is the single most common way signature checks fail in practice.
The practical consequence — artifacts published under the earlier, unsigned manifest schema become
unconsumable by this consumer — is accepted deliberately: quietly proceeding with no verification
is a worse failure mode than refusing an old artifact.

## Configuration resolution via `pydantic-settings`

Not part of the original decision table, but closed during implementation: configuration
resolution (`src/model_pipeline/settings.py`) uses `pydantic_settings.BaseSettings` rather than a
hand-written precedence helper and `.env` parser. `pydantic` and `pydantic-settings` were added to
the core dependencies (not an optional extra) because `Settings` is imported by the CLI regardless
of which workload runs. Field validation, `.env` loading, and environment-variable resolution come
from a well-tested library instead of custom code, while the CLI layer still applies the final
"explicit argument overrides everything" rule on top of the resolved `Settings` object.

The set of recognized environment variable names is documented once, in `.env.example`, rather than
duplicated as string constants in `model_pipeline.constants`: `Settings`' field names already are
the contract (case-insensitively mapped to their environment variable), so a separate constant for
each name would be a second, driftable source of truth for information the type already carries.

## Resolving a version conflict before touching the cluster

Also closed during implementation, once running `scripts/demo.sh` against an already-published
version showed the actual failure mode: the producer rejecting an existing version (decision 7)
only surfaced once a Kubernetes Job was already running, and looked like the script hanging until
`kubectl`'s wait timed out, since a failing Job pod is retried under its `backoffLimit` before the
Job is finally marked failed. The consumer pod had the same failure shape in reverse (waiting on a
Pod phase that a fast-failing Pod would never reach).

`produce`/`consume` now resolve the requested version against the target repo before doing
anything else (`model_pipeline.producer.resolve_produce_version`,
`model_pipeline.consumer.resolve_consume_version`), and `scripts/demo.sh` runs that resolution
locally, via `--check-only` on the already-built producer image, before applying anything to the
cluster. On a real terminal, a conflict prompts for a replacement version instead of failing; in a
non-interactive context — inside the Job/Pod itself, or `--check-only` invoked without a terminal
attached — it fails immediately with no prompt, since blocking on input nobody can answer would
just trade one hang for another. The consumer Pod's wait was also changed from a fixed-timeout
`kubectl wait --for=...=Succeeded` to polling for either terminal phase, so a Pod that fails fast is
reported in seconds rather than after the full timeout.
