import asyncio
import sys
from pathlib import Path
from pprint import pprint

from detectiq.core.utils.yara.file_analyzer import FileAnalyzer

# This script analyzes a file and outputs the results in a structured format
# Usage: python analyze_file_for_yara.py <filepath>


async def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_file_for_yara.py <filepath>")
        sys.exit(1)

    filepath = Path(sys.argv[1])
    if not filepath.exists():
        print(f"Error: File {filepath} does not exist")
        sys.exit(1)

    analyzer = FileAnalyzer()
    try:
        results = await analyzer.analyze_file(filepath)
        print("\nFile Analysis Results:")
        print("-" * 20)
        pprint(results)
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
