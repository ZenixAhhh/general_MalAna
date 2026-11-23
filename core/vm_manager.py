"""VMware management and dynamic snapshot control."""

import os
import subprocess
import re
from core.safety import check_vmx_isolation


class VMManager:
    def __init__(self, config):
        self.config = config
        self.vmrun = config.get("vmrun", "vmrun.exe")
        self.vmx = config.get("default_vmx", "")
        self.clean_snapshot = config.get("default_snapshot", "")

    def _call_vmrun(self, *args, timeout=300):
        cmd = [self.vmrun, "-T", "ws"] + list(args)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except Exception as e:
            return -1, "", str(e)

    def is_running(self, vmx=None):
        vmx = vmx or self.vmx
        code, out, _ = self._call_vmrun("list")
        if code == 0:
            return os.path.normcase(vmx) in os.path.normcase(out)
        return False

    def list_snapshots(self, vmx=None):
        """Return list of snapshot display names in order of discovery."""
        vmx = vmx or self.vmx
        code, out, err = self._call_vmrun("listSnapshots", vmx)
        if code != 0:
            return []
        lines = out.splitlines()
        # First line is count (e.g. "Total snapshots: 3")
        return [l.strip() for l in lines[1:] if l.strip()]

    def resolve_snapshot(self, requested_name=None, vmx=None):
        """Dynamically resolve snapshot target:
        - If requested_name is 'latest' or 'newest', returns the most recent snapshot.
        - If requested_name is an index (e.g. '0', '1', '2'), returns snapshot by index.
        - If requested_name is a substring / pattern, returns the best match.
        - Defaults to configured clean_snapshot or the latest snapshot."""
        snaps = self.list_snapshots(vmx)
        if not snaps:
            return None, "No snapshots found for VM"

        if not requested_name or requested_name.lower() in ("latest", "newest", "last"):
            # By default, the last snapshot returned by vmrun is the newest
            chosen = snaps[-1]
            return chosen, f"Selected latest snapshot: '{chosen}'"

        # Check exact match
        if requested_name in snaps:
            return requested_name, f"Selected exact snapshot: '{requested_name}'"

        # Check numeric index
        if requested_name.isdigit():
            idx = int(requested_name)
            if 0 <= idx < len(snaps):
                return snaps[idx], f"Selected snapshot [{idx}]: '{snaps[idx]}'"

        # Check substring / regex match
        pattern = re.compile(re.escape(requested_name), re.I)
        matches = [s for s in snaps if pattern.search(s)]
        if len(matches) == 1:
            return matches[0], f"Selected matching snapshot: '{matches[0]}'"
        elif len(matches) > 1:
            return matches[-1], f"Multiple matches found ({', '.join(matches)}). Chose newest: '{matches[-1]}'"

        return None, f"Snapshot '{requested_name}' not found. Available: {', '.join(snaps)}"

    def take_snapshot(self, snapshot_name, description="", vmx=None):
        """Create a new snapshot dynamically."""
        vmx = vmx or self.vmx
        if not snapshot_name:
            return False, "Snapshot name cannot be empty"

        args = ["snapshot", vmx, snapshot_name]
        code, out, err = self._call_vmrun(*args, timeout=600)
        output = (out + " " + err).strip()
        if code != 0 or re.search(r"\b(error|failed|unable)\b", output, re.I):
            return False, f"Failed to take snapshot: {output}"

        return True, f"Snapshot '{snapshot_name}' created successfully."

    def revert_snapshot(self, snapshot_name=None, vmx=None):
        """Revert VM to a snapshot with dynamic resolution and verification."""
        vmx = vmx or self.vmx
        chosen, msg = self.resolve_snapshot(snapshot_name or self.clean_snapshot, vmx)
        if not chosen:
            return False, msg

        code, out, err = self._call_vmrun("revertToSnapshot", vmx, chosen, timeout=600)
        output = (out + " " + err).strip()

        if code != 0 or re.search(r"\b(error|failed|unable|cannot)\b", output, re.I):
            return False, f"Revert failed (code {code}): {output}"

        # Verify snapshot still exists
        current_snaps = self.list_snapshots(vmx)
        if chosen not in current_snaps:
            return False, f"Snapshot '{chosen}' disappeared after revert"

        return True, f"Successfully reverted {os.path.basename(vmx)} to '{chosen}' ({msg})"

    def audit(self, vmx=None):
        vmx = vmx or self.vmx
        is_isolated, findings = check_vmx_isolation(vmx, self.config.get("allowed_net_types"))
        snaps = self.list_snapshots(vmx)
        running = self.is_running(vmx)
        return {
            "vmx": vmx,
            "running": running,
            "snapshots": snaps,
            "is_isolated": is_isolated,
            "findings": findings
        }
