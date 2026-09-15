"""Application-wide constants for the model delivery pipeline.

Centralizing these values keeps magic numbers and labels out of the modules
that use them, and gives every module a single place to agree on the
container format and key material sizes.
"""

# --- Container format ---

# Fixed tag identifying a model-pipeline encrypted container; a trailing NUL
# separates it from the 1-byte format version stored right after it.
MAGIC = b"MDLENC\0"

FORMAT_VERSION = 1

# Width, in bytes, of the big-endian length prefix preceding the JSON header.
HEADER_LEN_SIZE = 4

# Width, in bytes, of the big-endian length prefix preceding each chunk's ciphertext.
CHUNK_LEN_SIZE = 4

# --- Key material sizes (bytes) ---

# Required length of an AES-256 key (master key or derived file key).
KEY_SIZE = 32

# Length of the random per-artifact salt used for key derivation.
SALT_SIZE = 16

# Length of the AES-GCM nonce (the standard 96-bit size).
NONCE_SIZE = 12

# Length of the AES-GCM authentication tag appended to each chunk.
TAG_SIZE = 16

# --- Chunking ---

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

# --- Key derivation ---

# Context/application-binding info string for the HKDF derivation of the
# per-artifact file key from the master key.
HKDF_INFO = b"model-pipeline/v1"

# --- Header labels ---

# Recorded in the container header so the consumer can detect a key or
# algorithm mismatch before attempting to decrypt.
ALGORITHM_LABEL = "AES-256-GCM"
KDF_LABEL = "HKDF-SHA256"

# --- Manifest ---

# Schema version of the published manifest.json, independent of the
# container's own format_version.
MANIFEST_VERSION = "1.0"
