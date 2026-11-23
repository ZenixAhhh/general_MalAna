"""Automatic draft YARA rule generator for analyzed samples."""

import re
from datetime import datetime, timezone


def generate_yara_rule(sample_meta, rule_name=None, author="Antigravity"):
    """Generate a clean, readable draft YARA rule based on static metadata."""
    if not rule_name:
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', sample_meta.get('filename', 'sample'))
        rule_name = f"rule_{clean_name}"

    sha256 = sample_meta.get("sha256", "N/A")
    md5 = sample_meta.get("md5", "N/A")
    filesize = sample_meta.get("filesize", 0)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects {sample_meta.get('filename', 'sample')} based on static attributes"
        author = "{author}"
        date = "{created}"
        sha256 = "{sha256}"
        md5 = "{md5}"

    strings:
        $mz = "MZ"
"""
    # Add section names as strings if interesting
    sec_count = 0
    for sec in sample_meta.get("sections", []):
        name = sec.get("name", "").strip()
        if name and name not in [".text", ".data", ".rdata"]:
            rule += f'        $sec_{sec_count} = "{name}" fullword ascii\n'
            sec_count += 1

    rule += f"""
    condition:
        uint16(0) == 0x5A4D and
        filesize > {max(0, filesize - 10000)} and filesize < {filesize + 20000}"""

    if sec_count > 0:
        rule += f" and\n        any of ($sec_*)"
    else:
        rule += f"\n"

    rule += "\n}\n"
    return rule
