#!/usr/bin/env python3
import os
import subprocess


def create_dirs():
    """Create requirements directory if it doesn't exist."""
    os.makedirs("requirements", exist_ok=True)


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

    # Create main requirements.txt with reference to common.txt
    with open("requirements.txt", "w") as f:
        f.write("-r requirements/common.txt\n")


def main():
    create_dirs()
    export_requirements()
    print("Requirements files updated successfully!")


if __name__ == "__main__":
    main()
