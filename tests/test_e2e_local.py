"""End-to-end local round trip across packaging, crypto, signing, and manifest, with no network.

This is the integration test that ties the modules together: it packs a
fake model snapshot, encrypts it, builds and signs a manifest, verifies the
signature, decrypts it back, and confirms the restored files match the
originals bit for bit.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import tests.constants as test_const

from model_pipeline import crypto, keys, manifest, packaging, signing


def test_pack_encrypt_manifest_decrypt_verify_round_trip(
    fake_model_dir: Path, tmp_path: Path
) -> None:
    """A model snapshot must survive pack -> encrypt -> sign -> verify -> decrypt -> unpack."""
    plaintext_tar = packaging.pack_directory(fake_model_dir)

    encrypted_container = crypto.encrypt(
        plaintext_tar,
        test_const.TEST_MASTER_KEY,
        chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
    )

    signing_private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    signing_public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    artifact_manifest = manifest.build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=manifest.ModelInfo(
            source_repo="prajjwal1/bert-tiny", source_revision="deadbeef", task_hint="fill-mask"
        ),
        artifact=manifest.ArtifactInfo(
            version="1.0.0",
            path="versions/1.0.0/model.tar.enc",
            size_bytes=len(encrypted_container),
            sha256=manifest.compute_sha256(encrypted_container),
            plaintext_sha256=manifest.compute_sha256(plaintext_tar),
            plaintext_size_bytes=len(plaintext_tar),
        ),
        encryption=manifest.EncryptionInfo(
            algorithm="AES-256-GCM",
            kdf="HKDF-SHA256",
            chunk_size_bytes=test_const.SMALL_TEST_CHUNK_SIZE,
            format_version=1,
            key_id="model-encryption-key",
        ),
        signature=manifest.SignatureInfo(
            algorithm="Ed25519",
            public_key_sha256=signing.public_key_fingerprint(signing_public_key),
            signature_path="versions/1.0.0/manifest.json.sig",
        ),
        producer=manifest.ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )
    manifest_bytes = manifest.serialize_manifest(artifact_manifest)
    signature_bytes = signing.sign(manifest_bytes, signing_private_key)

    # Consumer side, from here: only the manifest, its signature, the
    # encrypted artifact, and the two key files (public, then private).
    signing.verify(manifest_bytes, signature_bytes, signing_public_key)
    received_manifest = manifest.deserialize_manifest(manifest_bytes)
    manifest.verify_artifact_sha256(received_manifest, encrypted_container)

    key_file = tmp_path / "encryption-key"
    key_file.write_text(
        base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii") + "\n",
        encoding="utf-8",
    )
    resolved_key = keys.resolve_key(key_file=key_file, key_value=None)

    decrypted_tar = crypto.decrypt(encrypted_container, resolved_key)
    manifest.verify_plaintext_sha256(received_manifest, decrypted_tar)

    restored_dir = tmp_path / "restored-model"
    packaging.unpack_archive(decrypted_tar, restored_dir)

    for relative_path in ["config.json", "pytorch_model.bin", "tokenizer/vocab.txt"]:
        assert (restored_dir / relative_path).read_bytes() == (
            fake_model_dir / relative_path
        ).read_bytes()


def test_wrong_key_fails_the_end_to_end_flow(fake_model_dir: Path) -> None:
    """Decrypting the artifact with the wrong key must fail loudly, not produce a bad model."""
    plaintext_tar = packaging.pack_directory(fake_model_dir)
    encrypted_container = crypto.encrypt(
        plaintext_tar, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(encrypted_container, test_const.OTHER_MASTER_KEY)
