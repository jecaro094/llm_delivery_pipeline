"""Test-only constants for the model delivery pipeline test suite.

Kept separate from ``model_pipeline.constants`` so that test fixtures (small
chunk sizes, fixed dummy keys) never leak into, or get confused with, the
constants the application itself relies on.
"""

from model_pipeline.constants import KEY_SIZE

# --- Crypto test fixtures ---

# 32-byte key used as the "correct" key in crypto round-trip tests.
TEST_MASTER_KEY = b"\x11" * KEY_SIZE

# 32-byte key distinct from TEST_MASTER_KEY, used as the "wrong" key in tests.
OTHER_MASTER_KEY = b"\x22" * KEY_SIZE

# Small chunk size used to exercise multi-chunk containers cheaply.
SMALL_TEST_CHUNK_SIZE = 8

# --- Key loading test fixtures ---

# Decodes to 16 bytes, i.e. the wrong length for an AES-256 key.
WRONG_LENGTH_KEY_BYTES = b"\x33" * 16

# --- Signing test fixtures ---

# Fixed Ed25519 key pair used as the "correct" pair in signing round-trip
# and known-answer tests. Derived from a fixed 32-byte seed rather than
# generated per run, so tests stay deterministic.
TEST_SIGNING_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIERERERERERERERERERERERERERERERERERERERERERE
-----END PRIVATE KEY-----
"""
TEST_SIGNING_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11l5O7wTooGagnx2rbb7qKSa7gB/SfLQmS2ZuCWtLEg=
-----END PUBLIC KEY-----
"""

# Fixed Ed25519 key pair distinct from TEST_SIGNING_*, used as the "wrong"
# pair in key-confusion and cross-key tests.
OTHER_SIGNING_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
-----END PRIVATE KEY-----
"""
OTHER_SIGNING_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxoImN8fTEOxXYnvgC6JZ0lN0n0qvZERwz/vlOjX3MkI=
-----END PUBLIC KEY-----
"""

# Known-answer pair: signing this exact payload with TEST_SIGNING_PRIVATE_KEY_PEM
# must always yield this exact signature, which only holds because Ed25519
# signing is deterministic.
KNOWN_ANSWER_PAYLOAD = b"known-answer-test-payload"
KNOWN_ANSWER_SIGNATURE = bytes.fromhex(
    "0ab85cd27b7a6d2c584ca29b416c5feea7ed33142b672659cbd96274e2479dc"
    "d788f87934a7c57eebf25919a77137cd0974a36114adbca8f7e1bdb4255967f08"
)
