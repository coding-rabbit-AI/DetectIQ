import binascii
import hashlib
import logging
import math
import re
import struct
import zipfile
from collections import Counter
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional


class FileAnalyzer:
    """Class for analyzing files and extracting patterns for YARA rules."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)

    def _extract_strings(
        self,
        data: bytes,
        min_length: int = 4,
        ascii_only: bool = False,
        wide: bool = False,
    ) -> List[str]:
        """Extract strings with position and entropy information.

        Args:
            data: Bytes to analyze
            min_length: Minimum string length to extract
            ascii_only: Only extract ASCII strings
            wide: Extract wide (UTF-16) strings
        """
        strings = []
        pattern = (
            b"[^\x00-\x1f\x7f-\xff]{%d,}" % min_length
            if ascii_only
            else b"(?:[\x20-\x7e][\x00]){%d,}" % (min_length // 2)
        )

        for match in re.finditer(pattern, data):
            try:
                if wide:
                    string = match.group().decode("utf-16")
                else:
                    string = match.group().decode("ascii")

                if string.isprintable():
                    strings.append(string)
            except UnicodeDecodeError:
                continue

        return strings

    def analyze_file(
        self,
        file_path: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        file_type: Optional[str] = None,
        min_string_length: int = 4,
        max_strings: int = 50,
    ) -> Dict:
        """Analyze file and extract useful patterns for YARA rules."""
        try:
            if file_path:
                with open(file_path, "rb") as f:
                    data = f.read()
            else:
                data = file_bytes

            if not data:
                raise ValueError("No file data provided")

            analysis = {
                "file_info": self._get_file_info(data),
                "string_patterns": {
                    "ascii": self._extract_strings(data, min_string_length, ascii_only=True),
                    "wide": self._extract_strings(data, min_string_length * 2, wide=True),
                    "hex_strings": self._extract_hex_patterns(data)[:max_strings],
                },
                "file_structure": self._analyze_file_structure(data),
                "entropy": self._analyze_entropy_patterns(data),
                "rich_header": (self._extract_rich_header(data) if self._is_pe_file(data) else None),
                "imports": (self._extract_imports(data) if self._is_pe_file(data) else None),
                "exports": (self._extract_exports(data) if self._is_pe_file(data) else None),
                "sections": (self._analyze_sections(data) if self._is_pe_file(data) else None),
                "resources": (self._analyze_resources(data) if self._is_pe_file(data) else None),
                "anomalies": self._detect_anomalies(data),
                "code_patterns": self._extract_code_patterns(data),
            }

            # Add analysis insights
            analysis["insights"] = self._generate_insights(analysis)
            return analysis

        except Exception as e:
            self.logger.error(f"Error analyzing file: {str(e)}")
            raise

    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is a PE file."""
        return data.startswith(b"MZ") and len(data) >= 64

    def _extract_hex_patterns(self, data: bytes, pattern_length: int = 8) -> List[str]:
        """Find recurring hex patterns in the file."""
        patterns = []
        seen_patterns = Counter()

        # Sliding window analysis
        for i in range(len(data) - pattern_length):
            pattern = data[i : i + pattern_length]
            # Skip patterns that are all zeros or all the same byte
            if len(set(pattern)) <= 1:
                continue
            # Skip ASCII strings
            if all(32 <= x <= 126 for x in pattern):
                continue
            seen_patterns[pattern] += 1

        # Convert top patterns to hex representation
        for pattern, count in seen_patterns.most_common(10):
            if count >= 3:  # Only show patterns that appear at least 3 times
                hex_pattern = binascii.hexlify(pattern).decode("ascii")
                patterns.append(hex_pattern)

        return patterns

    def _extract_code_patterns(self, data: bytes) -> Dict:
        """Extract common code patterns and sequences."""
        patterns = {
            "api_sequences": [],
            "function_prologs": [],
            "crypto_constants": [],
            "suspicious_instructions": [],
        }

        # Look for common API call sequences
        api_patterns = [
            b"GetProcAddress",
            b"LoadLibrary",
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"CreateThread",
        ]

        # Common function prologs
        prolog_patterns = [
            b"\x55\x8b\xec",  # push ebp; mov ebp, esp
            b"\x48\x89\x5c",  # mov [rsp+var], rbx
        ]

        # Crypto constants
        crypto_constants = [
            bytes.fromhex("67452301"),  # MD5
            bytes.fromhex("0123456789ABCDEF"),  # Common crypto
        ]

        # Add found patterns
        for api in api_patterns:
            if api in data:
                patterns["api_sequences"].append(api)

        for prolog in prolog_patterns:
            if prolog in data:
                patterns["function_prologs"].append(prolog.hex())

        for const in crypto_constants:
            if const in data:
                patterns["crypto_constants"].append(const.hex())

        return patterns

    def _extract_rich_header(self, data: bytes) -> Optional[Dict]:
        """Extract and analyze Rich header if present."""
        try:
            # Rich header starts with "Rich" signature
            rich_sig = b"Rich"
            dans_sig = b"DanS"

            rich_pos = data.find(rich_sig)
            if rich_pos == -1:
                return None

            # Find DanS signature before Rich
            dans_pos = data.rfind(dans_sig, 0, rich_pos)
            if dans_pos == -1:
                return None

            # Extract and decode Rich header
            rich_header = data[dans_pos : rich_pos + 8]
            return {
                "offset": dans_pos,
                "size": len(rich_header),
                "data": rich_header.hex(),
                "xor_key": self._find_rich_xor_key(rich_header),
            }
        except Exception:
            return None

    def _find_rich_xor_key(self, rich_header: bytes) -> int:
        """Find XOR key used in Rich header."""
        # Rich header XOR key is typically stored after "DanS" signature
        if len(rich_header) < 8:
            return 0
        return int.from_bytes(rich_header[4:8], byteorder="little")

    def _generate_insights(self, analysis: Dict) -> List[str]:
        """Generate insights for YARA rule creation based on analysis."""
        insights = []

        # Check for PE anomalies
        if analysis["file_structure"]["type"] == "Windows PE/EXE":
            details = analysis["file_structure"].get("details", [])
            if isinstance(details, dict):
                if details.get("overlay_size", 0) > 0:
                    insights.append("File contains overlay data - consider using uint32(filesize-N) patterns")
            elif isinstance(details, list):
                # Handle list of details
                for detail in details:
                    if isinstance(detail, dict) and detail.get("overlay_size", 0) > 0:
                        insights.append("File contains overlay data - consider using uint32(filesize-N) patterns")

            if analysis["sections"]:
                for section in analysis["sections"]:
                    if section["entropy"] > 7.5:
                        insights.append(f"High entropy section '{section['name']}' - possible packing/encryption")
                    if section["characteristics"] & 0xE0000000:
                        insights.append(f"Section '{section['name']}' has unusual characteristics")

        # Rich header insights
        if analysis["rich_header"]:
            insights.append("Rich header present - can be used for compiler/tool identification")

        # Import/Export patterns
        if analysis["imports"]:
            suspicious_apis = [
                api
                for api in analysis["imports"]
                if api.lower() in ["virtualalloc", "writeprocessmemory", "createremotethread"]
            ]
            if suspicious_apis:
                insights.append(f"Suspicious API imports found: {', '.join(suspicious_apis)}")

        # Code pattern insights
        if analysis["code_patterns"]["crypto_constants"]:
            insights.append("Cryptographic constants detected - possible encryption/hashing functionality")

        # String pattern insights
        if analysis["string_patterns"]["ascii"]:
            urls = [s for s in analysis["string_patterns"]["ascii"] if "http://" in s or "https://" in s]
            if urls:
                insights.append("Contains URLs - consider using regex patterns for C2 detection")

        # Entropy insights
        if analysis["entropy"]["total"] > 7.0:
            insights.append("High overall entropy - possible packed/encrypted content")
        if analysis["entropy"]["high_entropy_regions"]:
            insights.append(
                f"Found {len(analysis['entropy']['high_entropy_regions'])} high entropy regions - consider targeted entropy checks"
            )

        return insights

    def _get_file_info(self, data: bytes) -> Dict:
        """Get basic file information."""
        return {
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "type": "PE" if self._is_pe_file(data) else "Unknown",
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = Counter(data)

        # Calculate entropy
        entropy = 0
        for count in frequencies.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def _analyze_file_structure(self, content: bytes) -> Dict:
        """Analyze file structure and headers."""
        analysis = {}

        # Common file signatures
        signatures = {
            b"MZ": ("Windows PE/EXE", self._analyze_pe),
            b"PK\x03\x04": ("ZIP/Office Document", self._analyze_zip),
            b"\x7fELF": ("ELF Binary", self._analyze_elf),
            b"%PDF": ("PDF Document", self._analyze_pdf),
        }

        for sig, (file_type, analyzer) in signatures.items():
            if content.startswith(sig):
                analysis["type"] = file_type
                analysis["details"] = analyzer(content)
                break
        else:
            analysis["type"] = "Unknown"
            analysis["details"] = []

        return analysis

    def _find_hex_patterns(self, content: bytes, pattern_length: int = 8) -> List[str]:
        """Find recurring hex patterns in the file."""
        patterns = []
        seen_patterns = Counter()

        # Sliding window analysis
        for i in range(len(content) - pattern_length):
            pattern = content[i : i + pattern_length]
            # Skip patterns that are all zeros or all the same byte
            if len(set(pattern)) <= 1:
                continue
            # Skip ASCII strings
            if all(32 <= x <= 126 for x in pattern):
                continue
            seen_patterns[pattern] += 1

        # Convert top patterns to hex representation with context
        for pattern, count in seen_patterns.most_common(10):
            if count >= 3:  # Only show patterns that appear at least 3 times
                hex_pattern = binascii.hexlify(pattern).decode("ascii")
                context = self._get_pattern_context(content, pattern)
                patterns.append(f"{hex_pattern} (count: {count}, context: {context})")

        return patterns

    def _get_pattern_context(self, content: bytes, pattern: bytes, context_size: int = 8) -> str:
        """Get context around a pattern's first occurrence."""
        try:
            pos = content.index(pattern)
            start = max(0, pos - context_size)
            end = min(len(content), pos + len(pattern) + context_size)
            context = binascii.hexlify(content[start:end]).decode("ascii")
            return f"...{context}..."
        except ValueError:
            return "no context available"

    def _analyze_pe(self, content: bytes) -> List[str]:
        """Analyze PE file structure."""
        analysis = ["PE File Analysis:"]
        try:
            # Check for DOS header
            if content[:2] != b"MZ":
                return ["Invalid PE file - Missing MZ header"]

            # Get PE header offset
            pe_offset = struct.unpack("<I", content[0x3C:0x40])[0]
            if content[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return ["Invalid PE file - Missing PE header"]

            # Parse File Header
            machine = struct.unpack("<H", content[pe_offset + 4 : pe_offset + 6])[0]
            num_sections = struct.unpack("<H", content[pe_offset + 6 : pe_offset + 8])[0]
            characteristics = struct.unpack("<H", content[pe_offset + 22 : pe_offset + 24])[0]

            analysis.extend(
                [
                    f"Machine: 0x{machine:04x}",
                    f"Number of sections: {num_sections}",
                    f"Characteristics: 0x{characteristics:04x}",
                ]
            )

            # Optional Header
            optional_header_size = struct.unpack("<H", content[pe_offset + 20 : pe_offset + 22])[0]
            if optional_header_size:
                magic = struct.unpack("<H", content[pe_offset + 24 : pe_offset + 26])[0]
                analysis.append(f"Optional Header Magic: 0x{magic:04x} ({'PE32+' if magic == 0x20b else 'PE32'})")

            # Section analysis
            section_offset = pe_offset + 24 + optional_header_size
            analysis.append("\nSection Analysis:")

            for i in range(num_sections):
                section_header = content[section_offset + i * 40 : section_offset + (i + 1) * 40]
                if len(section_header) != 40:
                    break

                name = section_header[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
                virtual_size = struct.unpack("<I", section_header[8:12])[0]
                virtual_addr = struct.unpack("<I", section_header[12:16])[0]
                raw_size = struct.unpack("<I", section_header[16:20])[0]
                raw_addr = struct.unpack("<I", section_header[20:24])[0]
                characteristics = struct.unpack("<I", section_header[36:40])[0]

                section_data = content[raw_addr : raw_addr + raw_size]
                entropy = self._calculate_entropy(section_data) if section_data else 0

                analysis.extend(
                    [
                        f"\nSection: {name}",
                        f"Virtual Size: 0x{virtual_size:x}",
                        f"Virtual Address: 0x{virtual_addr:x}",
                        f"Raw Size: 0x{raw_size:x}",
                        f"Characteristics: 0x{characteristics:x}",
                        f"Entropy: {entropy:.2f}",
                    ]
                )

        except Exception as e:
            analysis.append(f"Error during PE analysis: {str(e)}")

        return analysis

    def _analyze_elf(self, content: bytes) -> List[str]:
        """Analyze ELF file structure."""
        analysis = ["ELF File Analysis:"]
        try:
            if content[:4] != b"\x7fELF":
                return ["Invalid ELF file"]

            # ELF Header
            ei_class = content[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = content[5]  # 1 = little endian, 2 = big endian
            ei_version = content[6]
            ei_osabi = content[7]
            e_type = struct.unpack("<H", content[16:18])[0]
            e_machine = struct.unpack("<H", content[18:20])[0]

            analysis.extend(
                [
                    f"Class: {'32-bit' if ei_class == 1 else '64-bit'}",
                    f"Data: {'Little Endian' if ei_data == 1 else 'Big Endian'}",
                    f"Version: {ei_version}",
                    f"OS/ABI: {ei_osabi}",
                    f"Type: 0x{e_type:x}",
                    f"Machine: 0x{e_machine:x}",
                ]
            )

        except Exception as e:
            analysis.append(f"Error during ELF analysis: {str(e)}")

        return analysis

    def _analyze_pdf(self, content: bytes) -> List[str]:
        """Analyze PDF file structure."""
        analysis = ["PDF File Analysis:"]
        try:
            # Check for basic PDF structure
            if not content.startswith(b"%PDF-"):
                return ["Invalid PDF file"]

            # Extract PDF version
            version = content[5:8].decode("ascii", errors="ignore")
            analysis.append(f"PDF Version: {version}")

            # Look for common PDF keywords
            keywords = [
                b"/JavaScript",
                b"/JS",
                b"/OpenAction",
                b"/Launch",
                b"/URI",
                b"/URL",
                b"/Action",
            ]
            for keyword in keywords:
                count = content.count(keyword)
                if count > 0:
                    analysis.append(f"Found {keyword.decode()} {count} times")

            # Check for encryption
            if b"/Encrypt" in content:
                analysis.append("PDF is encrypted")

            # Look for potential shellcode patterns
            if b"\\x" in content or b"%u" in content:
                analysis.append("WARNING: Potential shellcode/encoded content found")

        except Exception as e:
            analysis.append(f"Error during PDF analysis: {str(e)}")

        return analysis

    def _analyze_zip(self, content: bytes) -> List[str]:
        """Analyze ZIP/Office file structure."""
        analysis = ["ZIP/Office File Analysis:"]
        try:
            with BytesIO(content) as bio:
                with zipfile.ZipFile(bio) as zf:
                    # Get file listing
                    analysis.append("\nContained files:")
                    for info in zf.filelist:
                        # Extract file info
                        filename = info.filename
                        file_size = info.file_size
                        compress_size = info.compress_size
                        date_time = datetime(*info.date_time)

                        analysis.extend(
                            [
                                f"\nFile: {filename}",
                                f"Size: {file_size} bytes",
                                f"Compressed: {compress_size} bytes",
                                f"Modified: {date_time.isoformat()}",
                                f"Compression ratio: {(1 - compress_size/file_size)*100:.1f}%",
                            ]
                        )

                        # Check for common Office markers
                        if filename.endswith((".xml", ".rels")):
                            try:
                                file_content = zf.read(filename)
                                if b"vbaProject.bin" in file_content:
                                    analysis.append("WARNING: Contains VBA macros")
                                if b"ActiveX" in file_content:
                                    analysis.append("WARNING: Contains ActiveX controls")
                                if b"http://" in file_content or b"https://" in file_content:
                                    analysis.append("WARNING: Contains URLs")
                            except Exception as e:
                                analysis.append(f"Error reading {filename}: {str(e)}")

                    # Check for specific Office markers
                    office_markers = [
                        "word/document.xml",  # Word
                        "xl/workbook.xml",  # Excel
                        "ppt/presentation.xml",  # PowerPoint
                        "_rels/.rels",  # Office relationships
                        "[Content_Types].xml",  # Office content types
                    ]

                    found_markers = [m for m in office_markers if m in zf.namelist()]
                    if found_markers:
                        analysis.append("\nOffice Document Markers:")
                        for marker in found_markers:
                            analysis.append(f"- {marker}")

                        # Check for macros
                        if "vbaProject.bin" in zf.namelist():
                            analysis.append("WARNING: VBA Project found - Document contains macros")

        except zipfile.BadZipFile:
            analysis.append("Error: Invalid ZIP file format")
        except Exception as e:
            analysis.append(f"Error during ZIP analysis: {str(e)}")

        return analysis

    def _analyze_code_patterns(self, content: bytes) -> List[str]:
        """Analyze code patterns and potential indicators of malicious behavior."""
        analysis = ["=== Code Pattern Analysis ==="]

        # Known suspicious API patterns (hex encoded)
        suspicious_apis = {
            b"VirtualAlloc": "Memory allocation",
            b"CreateProcess": "Process creation",
            b"WriteProcessMemory": "Process manipulation",
            b"CreateRemoteThread": "Remote thread creation",
            b"RegCreateKey": "Registry manipulation",
            b"URLDownloadToFile": "File download",
            b"WinExec": "Command execution",
            b"CreateService": "Service manipulation",
        }

        # Check for suspicious API calls
        api_findings = []
        for api, description in suspicious_apis.items():
            count = content.count(api)
            if count > 0:
                api_findings.append(f"Found {api.decode()} ({description}) {count} times")

        if api_findings:
            analysis.append("\nSuspicious API Calls:")
            analysis.extend(api_findings)

        # Analyze for common obfuscation patterns
        obfuscation_patterns = self._detect_obfuscation(content)
        if obfuscation_patterns:
            analysis.append("\nPotential Obfuscation Techniques:")
            analysis.extend(obfuscation_patterns)

        # Analyze byte frequency distribution
        byte_analysis = self._analyze_byte_distribution(content)
        analysis.extend(byte_analysis)

        return analysis

    def _analyze_executable_sections(self, content: bytes) -> List[str]:
        """Analyze executable sections for suspicious characteristics."""
        analysis = []

        # Look for common shellcode patterns
        shellcode_patterns = [
            (rb"\x55\x8b\xec", "x86 function prologue"),
            (rb"\x48\x89\x5c", "x64 function prologue"),
            (rb"\x90{4,}", "NOP sled"),
            (rb"\xcc{2,}", "Multiple breakpoints"),
            (rb"\xe8....\xe9", "Jump chains"),
            (rb"\x68....\xff\x54", "Push/Call pattern"),
        ]

        for pattern, description in shellcode_patterns:
            matches = re.finditer(pattern, content)
            locations = [hex(m.start()) for m in matches]
            if locations:
                analysis.append(f"Found {description} at offsets: {', '.join(locations[:5])}")

        return analysis

    def _analyze_anti_analysis_patterns(self, content: bytes) -> List[str]:
        """Detect anti-analysis and evasion techniques commonly used by malware."""
        findings = ["=== Anti-Analysis Pattern Detection ==="]

        # Anti-debugging API calls
        anti_debug_apis = {
            b"IsDebuggerPresent": "Debug detection",
            b"CheckRemoteDebuggerPresent": "Remote debug detection",
            b"NtQueryInformationProcess": "Process information check",
            b"GetTickCount": "Timing check",
            b"QueryPerformanceCounter": "Timing check",
            b"OutputDebugString": "Debug detection",
            b"FindWindow": "Debugger window detection",
        }

        # VM detection strings
        vm_detect_strings = [
            b"VMware",
            b"VBox",
            b"QEMU",
            b"Virtual",
            b"Sandbox",
            b"WINE",
            b"Device\\VBoxGuest",
            b"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE",
        ]

        # Anti-analysis techniques
        for api, technique in anti_debug_apis.items():
            if content.find(api) != -1:
                findings.append(f"Anti-debugging technique found: {api.decode()} ({technique})")

        for vm_string in vm_detect_strings:
            if content.find(vm_string) != -1:
                findings.append(f"VM detection string found: {vm_string.decode()}")

        return findings

    def _analyze_network_indicators(self, content: bytes) -> List[str]:
        """Analyze potential network-related indicators."""
        findings = ["=== Network Indicators Analysis ==="]

        # URL and domain patterns
        url_pattern = rb"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        domain_pattern = rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
        ip_pattern = rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"

        # Network-related API calls
        network_apis = {
            b"WSAStartup": "Network initialization",
            b"socket": "Socket creation",
            b"connect": "Network connection",
            b"InternetOpen": "Internet access",
            b"HttpOpenRequest": "HTTP request",
            b"DnsQuery": "DNS query",
        }

        # Extract and analyze URLs
        urls = set(re.findall(url_pattern, content))
        if urls:
            findings.append("\nDetected URLs:")
            for url in urls:
                findings.append(f"- {url.decode(errors='ignore')}")

        # Extract and analyze domains
        domains = set(re.findall(domain_pattern, content))
        if domains:
            findings.append("\nDetected Domains:")
            for domain in domains:
                findings.append(f"- {domain.decode(errors='ignore')}")

        # Extract and analyze IP addresses
        ips = set(re.findall(ip_pattern, content))
        if ips:
            findings.append("\nDetected IP Addresses:")
            for ip in ips:
                findings.append(f"- {ip.decode()}")

        # Analyze network APIs
        for api, description in network_apis.items():
            if content.find(api) != -1:
                findings.append(f"Network API detected: {api.decode()} ({description})")

        return findings

    def _analyze_persistence_mechanisms(self, content: bytes) -> List[str]:
        """Analyze potential persistence mechanisms."""
        findings = ["=== Persistence Mechanism Analysis ==="]

        # Registry persistence patterns
        registry_keys = [
            rb"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            rb"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            rb"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            rb"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            rb"System\\CurrentControlSet\\Services",
        ]

        # Startup folder patterns
        startup_patterns = [
            rb"\\Startup\\",
            rb"\\Start Menu\\Programs\\Startup",
            rb"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ]

        # WMI persistence
        wmi_patterns = [
            b"root\\subscription",
            b"ActiveScriptEventConsumer",
            b"CommandLineEventConsumer",
            b"__EventFilter",
        ]

        # Check registry persistence
        for key in registry_keys:
            if content.find(key) != -1:
                findings.append(f"Registry persistence key found: {key.decode()}")

        # Check startup folder persistence
        for pattern in startup_patterns:
            if content.find(pattern) != -1:
                findings.append(f"Startup folder reference found: {pattern.decode()}")

        # Check WMI persistence
        for pattern in wmi_patterns:
            if content.find(pattern) != -1:
                findings.append(f"WMI persistence indicator found: {pattern.decode()}")

        return findings

    def _analyze_injection_techniques(self, content: bytes) -> List[str]:
        """Analyze potential code injection techniques."""
        findings = ["=== Code Injection Analysis ==="]

        # Process injection APIs
        injection_apis = {
            b"VirtualAllocEx": "Remote memory allocation",
            b"WriteProcessMemory": "Process memory writing",
            b"CreateRemoteThread": "Remote thread creation",
            b"NtCreateThreadEx": "Native thread creation",
            b"QueueUserAPC": "APC injection",
            b"SetWindowsHookEx": "Hook injection",
            b"RtlCreateUserThread": "Native user thread creation",
        }

        # Memory pattern analysis
        memory_patterns = [
            (rb"\x00\x00\x4D\x5A", "PE header in memory"),
            (rb"\x55\x8B\xEC\x83\xEC", "Stack frame setup"),
            (rb"\xFF\x15[\x00-\xFF]{4}", "IAT call pattern"),
        ]

        # Check for injection APIs
        for api, description in injection_apis.items():
            if content.find(api) != -1:
                findings.append(f"Injection API detected: {api.decode()} ({description})")

        # Analyze memory patterns
        for pattern, description in memory_patterns:
            matches = re.finditer(pattern, content)
            locations = [hex(m.start()) for m in matches]
            if locations:
                findings.append(f"Memory pattern found ({description}) at: {', '.join(locations[:3])}")

        return findings

    def _detect_obfuscation(self, content: bytes) -> List[str]:
        """Detect common obfuscation techniques."""
        findings = []

        # Check for base64-like patterns
        b64_pattern = rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        b64_matches = re.finditer(b64_pattern, content)
        b64_strings = [m.group() for m in b64_matches if len(m.group()) >= 20]
        if b64_strings:
            findings.append(f"Found {len(b64_strings)} potential base64 encoded strings")

        # Check for hex-encoded strings
        hex_pattern = rb"(?:[0-9A-Fa-f]{2}){10,}"
        hex_matches = re.finditer(hex_pattern, content)
        hex_strings = [m.group() for m in hex_matches]
        if hex_strings:
            findings.append(f"Found {len(hex_strings)} potential hex-encoded strings")

        return findings

    def _analyze_byte_distribution(self, content: bytes) -> List[str]:
        """Analyze byte frequency distribution for anomaly detection."""
        analysis = ["\nByte Distribution Analysis:"]

        # Calculate byte frequency
        byte_freq = Counter(content)
        total_bytes = len(content)

        # Calculate distribution statistics
        freq_stats = {
            "null_byte_ratio": byte_freq[0] / total_bytes,
            "printable_ratio": sum(byte_freq[i] for i in range(32, 127)) / total_bytes,
            "high_byte_ratio": sum(byte_freq[i] for i in range(128, 256)) / total_bytes,
        }

        # Analyze distribution patterns
        if freq_stats["null_byte_ratio"] > 0.3:
            analysis.append("High null byte ratio detected - possible packed/encrypted content")

        if freq_stats["high_byte_ratio"] > 0.5:
            analysis.append("High concentration of high bytes - possible encrypted/compressed content")

        # Calculate byte entropy distribution
        byte_entropy = self._calculate_byte_entropy_distribution(byte_freq, total_bytes)
        if byte_entropy > 7.5:
            analysis.append(f"Very high byte entropy ({byte_entropy:.2f}) - likely encrypted/compressed")
        elif byte_entropy > 6.5:
            analysis.append(f"High byte entropy ({byte_entropy:.2f}) - possible packed/encoded content")

        return analysis

    def _calculate_byte_entropy_distribution(self, byte_freq: Counter, total_bytes: int) -> float:
        """Calculate entropy of byte frequency distribution."""
        entropy = 0
        for count in byte_freq.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        return entropy

    def _analyze_entropy_patterns(self, data: bytes) -> Dict:
        """Analyze entropy patterns in the file."""
        result = {
            "total": self._calculate_entropy(data),
            "chunks": [],
            "high_entropy_regions": [],
        }

        # Analyze chunks
        chunk_size = min(1024, len(data))
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            entropy = self._calculate_entropy(chunk)
            result["chunks"].append({"offset": i, "size": len(chunk), "entropy": entropy})
            if entropy > 7.0:  # High entropy threshold
                result["high_entropy_regions"].append({"offset": i, "size": len(chunk), "entropy": entropy})

        return result

    def _analyze_sections(self, data: bytes) -> Optional[List[Dict]]:
        """Analyze PE sections if present."""
        if not self._is_pe_file(data):
            return None

        try:
            # Get PE header offset
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if pe_offset >= len(data):
                return None

            # Get number of sections
            num_sections = struct.unpack("<H", data[pe_offset + 6 : pe_offset + 8])[0]

            # Get optional header size
            opt_header_size = struct.unpack("<H", data[pe_offset + 20 : pe_offset + 22])[0]

            # Calculate section table offset
            section_offset = pe_offset + 24 + opt_header_size

            sections = []
            for i in range(num_sections):
                section_header = data[section_offset + i * 40 : section_offset + (i + 1) * 40]
                if len(section_header) != 40:
                    break

                name = section_header[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
                virtual_size = struct.unpack("<I", section_header[8:12])[0]
                virtual_addr = struct.unpack("<I", section_header[12:16])[0]
                raw_size = struct.unpack("<I", section_header[16:20])[0]
                raw_addr = struct.unpack("<I", section_header[20:24])[0]
                characteristics = struct.unpack("<I", section_header[36:40])[0]

                # Calculate section entropy
                if raw_addr < len(data) and raw_size > 0:
                    section_data = data[raw_addr : raw_addr + raw_size]
                    entropy = self._calculate_entropy(section_data)
                else:
                    entropy = 0.0

                sections.append(
                    {
                        "name": name,
                        "virtual_size": virtual_size,
                        "virtual_addr": virtual_addr,
                        "raw_size": raw_size,
                        "raw_addr": raw_addr,
                        "characteristics": characteristics,
                        "entropy": entropy,
                    }
                )

            return sections

        except Exception:
            return None

    def _analyze_resources(self, data: bytes) -> Optional[List[Dict]]:
        """Analyze PE resources if present."""
        if not self._is_pe_file(data):
            return None

        try:
            # Get PE header offset
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if pe_offset >= len(data):
                return None

            # TODO: Implement resource parsing
            return None

        except Exception:
            return None

    def _extract_imports(self, data: bytes) -> Optional[List[str]]:
        """Extract imported functions if present."""
        if not self._is_pe_file(data):
            return None

        # Common imported function names to look for
        common_imports = [
            b"LoadLibrary",
            b"GetProcAddress",
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"CreateThread",
            b"CreateProcess",
            b"RegCreateKey",
            b"InternetOpen",
            b"socket",
            b"WSAStartup",
        ]

        found_imports = []
        for imp in common_imports:
            if imp in data:
                found_imports.append(imp.decode())

        return found_imports if found_imports else None

    def _extract_exports(self, data: bytes) -> Optional[List[str]]:
        """Extract exported functions if present."""
        if not self._is_pe_file(data):
            return None

        # TODO: Implement export table parsing
        return None

    def _detect_anomalies(self, data: bytes) -> List[str]:
        """Detect various anomalies in the file."""
        anomalies = []

        # Check for high entropy
        if self._calculate_entropy(data) > 7.0:
            anomalies.append("High overall entropy - possible encryption/packing")

        # Check for suspicious patterns
        if b"This program cannot be run in DOS mode" not in data and self._is_pe_file(data):
            anomalies.append("Missing DOS stub - possible corruption or manipulation")

        # Add other anomaly checks as needed
        return anomalies
