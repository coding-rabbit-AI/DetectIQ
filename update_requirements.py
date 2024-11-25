#!/usr/bin/env python3
import os
import subprocess

import toml


def create_dirs():
    """Create requirements directory if it doesn't exist."""
    os.makedirs("requirements", exist_ok=True)


def get_extras():
    """Get list of extras from pyproject.toml."""
    with open("pyproject.toml") as f:
        pyproject = toml.load(f)
    return list(pyproject.get("tool", {}).get("poetry", {}).get("extras", {}).keys())


def export_requirements():
    """Export requirements from Poetry to separate files."""
    # Export main dependencies to common.txt
    subprocess.run(
        [
            "poetry",
            "export",
            "--format",
            "requirements.txt",
            "--without-hashes",
            "--without-urls",
            "--only",
            "main",
            "-o",
            "requirements/common.txt",
        ],
        check=True,
    )

    # Export dev dependencies to dev.txt
    subprocess.run(
        [
            "poetry",
            "export",
            "--format",
            "requirements.txt",
            "--without-hashes",
            "--without-urls",
            "--only",
            "dev",
            "-o",
            "requirements/dev.txt",
        ],
        check=True,
    )

    # Export each extra to its own file
    extras = get_extras()
    for extra in extras:
        subprocess.run(
            [
                "poetry",
                "export",
                "--format",
                "requirements.txt",
                "--without-hashes",
                "--without-urls",
                "--extras",
                extra,
                "-o",
                f"requirements/{extra}.txt",
            ],
            check=True,
        )

    # Create main requirements.txt with reference to common.txt and information about extras
    with open("requirements.txt", "w") as f:
        f.write("-r requirements/common.txt\n\n")
        f.write("# Available extras (install with pip -r requirements/<extra>.txt):\n")
        for extra in extras:
            f.write(f"# - {extra}\n")


def main():
    create_dirs()
    export_requirements()
    print("Requirements files updated successfully!")


if __name__ == "__main__":
    main()
