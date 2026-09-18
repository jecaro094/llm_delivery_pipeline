"""Logging configuration for the CLI entry point.

Only :func:`model_pipeline.cli.main` calls :func:`configure_logging`, never
a library module, so importing ``model_pipeline`` on its own configures no
logging -- a caller embedding this package keeps full control over its own
logging setup.
"""

from __future__ import annotations

import logging
import sys

import model_pipeline.constants as const

_OWNED_HANDLER_ATTR = "_model_pipeline_owned"


def configure_logging(level: int) -> None:
    """Configure the root logger to write timestamped records to stderr at level.

    Safe to call more than once per process: each call replaces only the
    handler this function previously installed, never a handler owned by
    something else (e.g. pytest's log-capture handler attached to the root
    logger during tests), and always targets the current ``sys.stderr``
    rather than one captured on an earlier call. The noisy third-party
    loggers behind huggingface_hub's HTTP client are always held at
    WARNING, regardless of level, so ``--log-level debug`` surfaces this
    pipeline's own diagnostics without being drowned out by HTTP chatter.
    """
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, _OWNED_HANDLER_ATTR, False):
            root_logger.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(const.LOG_FORMAT))
    setattr(handler, _OWNED_HANDLER_ATTR, True)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    for noisy_logger_name in const.NOISY_LOGGERS:
        logging.getLogger(noisy_logger_name).setLevel(logging.WARNING)
