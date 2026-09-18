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

# --- Hugging Face Hub layout ---

# Prefix under which every published artifact version lives in a target repo.
VERSIONS_PREFIX = "versions"

ARTIFACT_FILENAME = "model.tar.enc"
MANIFEST_FILENAME = "manifest.json"

# Name of the Kubernetes Secret expected to hold the decryption key, recorded
# in the manifest as a label so a consumer can detect a key mismatch early.
DEFAULT_KEY_ID = "model-encryption-key"

# --- CLI defaults ---

# The recognized environment variable names themselves are documented in
# .env.example, the single source of truth for the pipeline's external
# configuration contract; model_pipeline.config.load_dotenv() and the CLI
# read them straight from the process environment by name.
DEFAULT_SOURCE_MODEL = "google/bert_uncased_L-2_H-128_A-2"
DEFAULT_TASK_HINT = "fill-mask"

# --- Producer metadata ---

TOOL_NAME = "model_pipeline"

# --- Interactive prompts ---

# Number of rejected candidates prompt_for_value tolerates before giving up,
# so an unattended run against a non-interactive stdin can never hang forever.
MAX_PROMPT_ATTEMPTS = 5

# --- Source model validation ---

# Some published Hugging Face repos (see PLAN.md, decision #1) predate the
# convention of recording an architecture identifier in their config file
# and omit it entirely; transformers then cannot auto-detect the model
# class, which is otherwise only discovered once the consumer tries to load
# it. The producer rejects such a source model before encrypting it.
MODEL_CONFIG_FILENAME = "config.json"
MODEL_TYPE_KEY = "model_type"
