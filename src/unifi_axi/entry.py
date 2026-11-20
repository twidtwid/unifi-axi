"""Console-script entry point.

A bare `-v`, `-V` or `--version` prints the version before the CLI graph is
imported (AXI principle 10, fast path). Everything else goes to cli.main,
which owns argument parsing and the single error boundary.
"""

import sys

from ._version import VERSION

VERSION_FLAGS = ("-v", "-V", "--version")


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) == 1 and argv[0] in VERSION_FLAGS:
        sys.stdout.write(VERSION + "\n")
        return 0
    from .cli import main as cli_main  # the heavy graph loads only here

    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
