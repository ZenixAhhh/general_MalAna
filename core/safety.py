"""Safety and containment rails for malware analysis."""

import os
import re
import hashlib


def sha256_file(filepath):
    """Safely hash a file on the host. Hashing reads bytes, never executes."""
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_vmx_isolation(vmx_path, allowed_net_types=None):
    """Audit a .vmx file for critical isolation parameters.
    Returns (is_isolated, findings_list)."""
    if allowed_net_types is None:
        allowed_net_types = ["hostonly", "pvn", "none", "custom"]

    findings = []
    is_safe = True

    if not os.path.isfile(vmx_path):
        return False, [("FAIL", f"VMX file does not exist: {vmx_path}")]

    with open(vmx_path, "r", encoding="utf-8", errors="replace") as f:
        vmx = f.read()

    # 1. Check network connection types
    nic_matches = re.findall(r'^ethernet(\d+)\.connectionType\s*=\s*"([^"]+)"', vmx, re.I | re.M)
    present_nics = set(re.findall(r'^ethernet(\d+)\.present\s*=\s*"TRUE"', vmx, re.I | re.M))

    if not nic_matches and not present_nics:
        findings.append(("OK", "No NICs present in VMX (Air-gapped)"))
    else:
        for nic_num, conn_type in nic_matches:
            if nic_num in present_nics:
                if conn_type.lower() in allowed_net_types:
                    findings.append(("OK", f"ethernet{nic_num} = {conn_type} (isolated)"))
                else:
                    is_safe = False
                    findings.append(("FAIL", f"ethernet{nic_num} = {conn_type} (can reach host/LAN/internet)"))

    # 2. Check Shared Folders (HGFS)
    if re.search(r'^isolation\.tools\.hgfs\.disable\s*=\s*"TRUE"', vmx, re.I | re.M):
        findings.append(("OK", "HGFS Shared Folders disabled"))
    else:
        is_safe = False
        findings.append(("FAIL", "HGFS Shared Folders not disabled (malware can write to host)"))

    # 3. Check clipboard and drag-and-drop
    for key, name in [
        ("isolation.tools.copy.disable", "clipboard copy"),
        ("isolation.tools.paste.disable", "clipboard paste"),
        ("isolation.tools.dnd.disable", "drag-and-drop")
    ]:
        if re.search(rf'^{re.escape(key)}\s*=\s*"TRUE"', vmx, re.I | re.M):
            findings.append(("OK", f"{name} disabled"))
        else:
            findings.append(("WARN", f"{name} not disabled"))

    return is_safe, findings


def is_allowed_artifact(filename, allow_exts, max_mb=64):
    """Check if an artifact extracted from VM is safe to store on host."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in [e.lower() for e in allow_exts]
