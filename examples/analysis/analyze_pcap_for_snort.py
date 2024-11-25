import asyncio
import sys
from pathlib import Path
from pprint import pprint

from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer

# This script analyzes a file and outputs the results in a structured format
# Usage: python analyze_file_for_yara.py <filepath>


async def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_pcap_for_snort.py <filepath>")
        sys.exit(1)

    file_path = sys.argv[1]

    filepath = Path(file_path)
    if not filepath.exists():
        print(f"Error: File {filepath} does not exist")
        sys.exit(1)

    analyzer = PcapAnalyzer()
    try:
        results = await analyzer.analyze_file(filepath)
        print("\nPCAP Analysis Results:")
        print("-" * 20)
        for key, value in results.items():
            print(f"\n{key}:")
            pprint(value, indent=4)
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
    