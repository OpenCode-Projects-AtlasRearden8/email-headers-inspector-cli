"""Run `python -m mailtimeline` without importing the CLI twice."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
