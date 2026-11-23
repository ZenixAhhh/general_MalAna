"""Report builder generating Markdown reports."""

def build_markdown_report(meta, iocs=None, dynamic_summary=None):
    md = []
    md.append(f"# Malware Analysis Report: {meta.get('filename', 'Unknown')}\n")
    md.append("## Executive Summary")
    md.append(f"- **File Name:** `{meta.get('filename')}`")
    md.append(f"- **File Size:** {meta.get('filesize', 0):,} bytes")
    md.append(f"- **Architecture:** {meta.get('architecture', 'Unknown')}")
    md.append(f"- **Compile Timestamp:** {meta.get('compile_time', 'N/A')}")
    md.append(f"- **Overall Entropy:** {meta.get('overall_entropy', 0.0)} / 8.0")
    md.append(f"- **Packing Status:** {'⚠️ **Likely Packed/Encrypted**' if meta.get('is_likely_packed') else '✅ Clean / Unpacked'}\n")

    md.append("## Hashes")
    md.append(f"- **MD5:** `{meta.get('md5')}`")
    md.append(f"- **SHA1:** `{meta.get('sha1')}`")
    md.append(f"- **SHA256:** `{meta.get('sha256')}`\n")

    if meta.get("suspicious_indicators"):
        md.append("## Suspicious Indicators & Triage Alerts")
        for alert in meta["suspicious_indicators"]:
            md.append(f"- ⚠️ {alert}")
        md.append("")

    md.append("## PE Section Table")
    md.append("| Name | Virtual Addr | Raw Size | Entropy | Flags |")
    md.append("| :--- | :--- | :--- | :--- | :--- |")
    for sec in meta.get("sections", []):
        flags = []
        if sec.get("executable"): flags.append("EXEC")
        if sec.get("writable"): flags.append("WRITE")
        md.append(f"| `{sec['name']}` | `{sec['virtual_address']}` | {sec['raw_size']:,} | {sec['entropy']} | {','.join(flags) or 'RO'} |")
    md.append("")

    if iocs:
        md.append("## Indicators of Compromise (IOCs)")
        for category, items in iocs.items():
            if items:
                md.append(f"### {category.upper()}")
                for item in items:
                    md.append(f"- `{item}`")
        md.append("")

    return "\n".join(md)
