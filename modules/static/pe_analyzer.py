"""Static Portable Executable (PE) analyzer implemented with Python stdlib."""

import os
import struct
import math
import hashlib
from datetime import datetime, timezone


def shannon_entropy(data):
    """Calculate Shannon entropy for a byte slice (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class PEAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filesize = os.path.getsize(filepath)
        self.data = None

    def analyze(self):
        with open(self.filepath, "rb") as f:
            self.data = f.read()

        results = {
            "filename": os.path.basename(self.filepath),
            "filesize": self.filesize,
            "md5": hashlib.md5(self.data).hexdigest(),
            "sha1": hashlib.sha1(self.data).hexdigest(),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "is_pe": False,
            "architecture": "Unknown",
            "compile_time": None,
            "sections": [],
            "overall_entropy": shannon_entropy(self.data),
            "is_likely_packed": False,
            "suspicious_indicators": []
        }

        if len(self.data) < 64 or self.data[:2] != b"MZ":
            results["suspicious_indicators"].append("Not an MZ/PE executable")
            return results

        results["is_pe"] = True
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if pe_offset + 4 > len(self.data) or self.data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            results["suspicious_indicators"].append("Missing PE signature at e_lfanew")
            return results

        # COFF File Header
        coff_offset = pe_offset + 4
        machine, num_sections, timedate, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", self.data, coff_offset
        )

        results["architecture"] = "x86 (32-bit)" if machine == 0x014c else ("x64 (64-bit)" if machine == 0x8664 else f"0x{machine:04x}")
        try:
            results["compile_time"] = datetime.fromtimestamp(timedate, timezone.utc).isoformat()
        except Exception:
            results["compile_time"] = f"Invalid/Anomalous ({timedate})"

        # Optional Header
        opt_hdr_offset = coff_offset + 20
        magic = struct.unpack_from("<H", self.data, opt_hdr_offset)[0]

        # Sections
        section_tbl_offset = opt_hdr_offset + opt_hdr_size
        high_entropy_sections = 0

        for i in range(num_sections):
            sec_offset = section_tbl_offset + (i * 40)
            if sec_offset + 40 > len(self.data):
                break
            sec_bytes = self.data[sec_offset:sec_offset+40]
            name = sec_bytes[:8].decode("latin-1", errors="replace").rstrip("\x00")
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", sec_bytes, 8)
            sec_chars = struct.unpack_from("<I", sec_bytes, 36)[0]

            sec_data = self.data[raw_ptr:raw_ptr+raw_size] if (raw_ptr + raw_size <= len(self.data)) else b""
            entropy = shannon_entropy(sec_data)

            is_executable = bool(sec_chars & 0x20000000)
            is_writable = bool(sec_chars & 0x80000000)

            if entropy > 7.0:
                high_entropy_sections += 1
            if is_executable and is_writable:
                results["suspicious_indicators"].append(f"Section {name} is both writable and executable (W^X violation / packer indicator)")

            results["sections"].append({
                "name": name,
                "virtual_address": hex(v_addr),
                "virtual_size": v_size,
                "raw_size": raw_size,
                "entropy": entropy,
                "executable": is_executable,
                "writable": is_writable
            })

        if high_entropy_sections > 0 or results["overall_entropy"] > 7.1:
            results["is_likely_packed"] = True
            results["suspicious_indicators"].append(f"High entropy detected ({high_entropy_sections} section(s) > 7.0) - Likely packed or encrypted")

        return results
