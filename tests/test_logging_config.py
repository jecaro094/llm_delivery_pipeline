"""Tests for configure_logging: level control and repeated-call safety."""

from __future__ import annotations

import logging

from model_pipeline.logging_config import configure_logging


def test_configure_logging_sets_the_root_level() -> None:
    """configure_logging must set the root logger to the requested level."""
    try:
        configure_logging(logging.DEBUG)
        assert logging.getLogger().level == logging.DEBUG
        configure_logging(logging.WARNING)
        assert logging.getLogger().level == logging.WARNING
    finally:
        configure_logging(logging.INFO)


def test_configure_logging_replaces_only_its_own_handler() -> None:
    """A second call must not accumulate handlers or remove handlers it does not own."""
    root_logger = logging.getLogger()
    foreign_handler = logging.NullHandler()
    root_logger.addHandler(foreign_handler)
    try:
        configure_logging(logging.INFO)
        first_handler_count = len(root_logger.handlers)
        configure_logging(logging.INFO)
        assert len(root_logger.handlers) == first_handler_count
        assert foreign_handler in root_logger.handlers
    finally:
        root_logger.removeHandler(foreign_handler)
        configure_logging(logging.INFO)


def test_configure_logging_holds_noisy_third_party_loggers_at_warning() -> None:
    """huggingface_hub/urllib3/filelock must be held at WARNING even at --log-level debug."""
    configure_logging(logging.DEBUG)
    assert logging.getLogger("huggingface_hub").level == logging.WARNING
    assert logging.getLogger("urllib3").level == logging.WARNING
    assert logging.getLogger("filelock").level == logging.WARNING
    configure_logging(logging.INFO)
