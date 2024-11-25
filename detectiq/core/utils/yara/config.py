from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AnalysisConfig:
    """Configuration for file analysis."""

    min_string_length: int = 4
    max_strings: int = 50
    entropy_threshold: float = 7.0
    chunk_size: int = 1024

    # File type specific configurations
    pe_section_entropy_threshold: float = 7.0
    resource_entropy_threshold: float = 7.5
    overlay_entropy_threshold: float = 7.0

    # Analysis thresholds
    suspicious_apis: Optional[Dict[str, str]] = None
    file_type_signatures: Optional[Dict[bytes, str]] = None

    def __post_init__(self):
        if self.suspicious_apis is None:
            self.suspicious_apis = {
                "VirtualAlloc": "Memory allocation",
                "WriteProcessMemory": "Process manipulation",
                "CreateRemoteThread": "Remote thread creation",
                "LoadLibrary": "Dynamic loading",
                "GetProcAddress": "API resolution",
                # Add more suspicious APIs
            }

        if self.file_type_signatures is None:
            self.file_type_signatures = {
                # Executables
                b"MZ": "PE",
                b"\x7fELF": "ELF",
                b"\xca\xfe\xba\xbe": "Mach-O",
                b"\xfe\xed\xfa\xce": "Mach-O PPC",
                b"\xfe\xed\xfa\xcf": "Mach-O x64",
                # Archives
                b"PK\x03\x04": "ZIP",
                b"Rar!\x1a\x07": "RAR",
                b"\x1f\x8b\x08": "GZIP",
                b"7z\xbc\xaf\x27\x1c": "7Z",
                b"BZh": "BZIP2",
                # Documents
                b"%PDF": "PDF",
                b"\xd0\xcf\x11\xe0": "MS Office",
                b"PK\x03\x04\x14\x00\x06\x00": "DOCX/XLSX/PPTX",
                b"\x50\x4b\x03\x04\x14\x00\x00\x00": "OpenDocument",
                # Images
                b"\xff\xd8\xff": "JPEG",
                b"\x89PNG\r\n\x1a\n": "PNG",
                b"GIF8": "GIF",
                b"BM": "BMP",
                b"\x00\x00\x01\x00": "ICO",
                # Scripts
                b"#!/": "Shell Script",
                b"<?php": "PHP",
                b"<%": "ASP",
                # System Files
                b"regf": "Registry Hive",
                b"MDMP": "Minidump",
                b"SZDD": "Compressed Windows File",
                # Media
                b"\x00\x00\x00\x20\x66\x74\x79\x70": "MP4",
                b"\x49\x44\x33": "MP3",
                b"RIFF": "AVI/WAV",
                b"\x1a\x45\xdf\xa3": "MKV",
                # Virtual Machine
                b"KDMV": "VMware Disk",
                b"VBox": "VirtualBox Disk",
                # Memory Dumps
                b"PMDM": "Process Memory Dump",
                b"PGDM": "Page Memory Dump",
                # Malware Related
                b"MZ\x90\x00": "Packed PE",
                b"SZDD\x88\xf0\x27\x33": "NSIS Installer",
                b"This program": "DOS Program",
            }
