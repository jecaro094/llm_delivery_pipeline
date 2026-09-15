"""Entry point for ``python -m model_pipeline``."""

import sys


def main() -> int:
    print("model_pipeline: no subcommands implemented yet", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
