#!/usr/bin/env python3
import os
import subprocess


def _format_project():
    """Run black on the project."""
    # Run ruff format
    subprocess.run(
        ["poetry", "run", "ruff", "format"],
        check=True,
    )

    # Run ruff check --fix
    subprocess.run(
        ["poetry", "run", "ruff", "check", "--fix"],
        check=True,
    )

    # Run black
    subprocess.run(
        ["poetry", "run", "black", "."],
        check=True,
    )


def main():
    _format_project()


if __name__ == "__main__":
    main()
