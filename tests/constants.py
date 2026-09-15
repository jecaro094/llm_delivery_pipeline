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
