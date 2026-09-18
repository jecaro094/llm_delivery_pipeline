"""Bounded interactive prompting on a terminal stream.

The only place in the pipeline that reads from stdin is the "enter a version"
retry prompt used by the producer and the consumer (see
:func:`model_pipeline.producer.resolve_produce_version` and
:func:`model_pipeline.consumer.resolve_consume_version`). Both share the same
mechanics -- print a prompt, apply a default on empty input, validate the
result, retry on rejection -- and only differ in the validation policy, which
callers supply as ``is_valid``/``invalid_message``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TextIO

import model_pipeline.constants as const


class PromptError(Exception):
    """Raised when no valid value was entered within the attempt budget, or stdin is closed."""


def prompt_for_value(
    *,
    prompt: str,
    default: str | None,
    is_valid: Callable[[str], bool],
    invalid_message: Callable[[str], str],
    max_attempts: int = const.MAX_PROMPT_ATTEMPTS,
    stream: TextIO = sys.stderr,
) -> str:
    """Prompt on stream until is_valid accepts a candidate, or raise PromptError.

    Each attempt prints prompt to stream, reads one line with input(), and
    applies default when the line is empty after stripping. The resulting
    candidate is accepted and returned as soon as is_valid(candidate) is
    True; otherwise invalid_message(candidate) is printed to stream and the
    next attempt begins. Raises PromptError after max_attempts rejected
    candidates, and also on EOFError (a closed or non-interactive stdin),
    so this function always terminates.
    """
    for _ in range(max_attempts):
        print(prompt, end="", file=stream)
        stream.flush()
        try:
            raw_line = input()
        except EOFError as exc:
            raise PromptError("no input available: stdin is closed") from exc
        candidate = raw_line.strip() or (default or "")
        if is_valid(candidate):
            return candidate
        print(invalid_message(candidate), file=stream)
    raise PromptError(f"no valid value entered after {max_attempts} attempts")
