"""Unified Command-Line Interface for general_MalAna."""

import sys
import os
import argparse
import json

from config.settings import load_config
from core.vm_manager import VMManager
from core.bridge import AgentPipelineBridge
from modules.static.pe_analyzer import PEAnalyzer
from modules.intelligence.yara_generator import generate_yara_rule
from modules.reporting.reporter import build_markdown_report


def cmd_status(config, args):
    print("=== general_MalAna Environment Status ===")
    vmm = VMManager(config)
    audit = vmm.audit()
    print(f"VMX Path     : {audit['vmx']}")
    print(f"VM Running   : {audit['running']}")
    print(f"Snapshots ({len(audit['snapshots'])}):")
    for i, s in enumerate(audit['snapshots']):
        is_latest = (i == len(audit['snapshots']) - 1)
        is_default = (s == vmm.clean_snapshot)
        tags = []
        if is_latest: tags.append("LATEST")
        if is_default: tags.append("DEFAULT")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        print(f"  [{i}] '{s}'{tag_str}")

    print(f"VM Isolation : {'PASSED (Isolated)' if audit['is_isolated'] else 'FAIL (Check network/shares)'}")
    for level, msg in audit["findings"]:
        print(f"  [{level}] {msg}")

    print("\n=== Agent-pipeline-for-MA Interop ===")
    bridge = AgentPipelineBridge(config)
    available = bridge.is_available()
    print(f"Bridge Target: {bridge.pipeline_dir}")
    print(f"Bridge Ready : {available}")
    if available:
        ok, out = bridge.run_check()
        print(f"Pipeline Check: {'OK' if ok else 'Preconditions Missing'}")
        if not ok:
            print(out.strip())


def cmd_vm(config, args):
    vmm = VMManager(config)
    sub = args.vm_action

    if sub in ("list", "snapshots"):
        snaps = vmm.list_snapshots()
        print(f"Available Snapshots ({len(snaps)}):")
        for i, s in enumerate(snaps):
            is_latest = (i == len(snaps) - 1)
            is_default = (s == vmm.clean_snapshot)
            tags = []
            if is_latest: tags.append("LATEST")
            if is_default: tags.append("DEFAULT")
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            print(f"  [{i}] '{s}'{tag_str}")

    elif sub == "resolve":
        target = args.target or "latest"
        chosen, msg = vmm.resolve_snapshot(target)
        print(f"Resolution: {msg}")
        if chosen:
            print(f"Resolved name: '{chosen}'")

    elif sub == "revert":
        target = args.snapshot
        if args.latest:
            target = "latest"
        print(f"[*] Reverting VM to: {target or 'configured default'}")
        ok, msg = vmm.revert_snapshot(target)
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")

    elif sub == "take":
        name = args.name
        print(f"[*] Taking snapshot: '{name}'")
        ok, msg = vmm.take_snapshot(name)
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")


def cmd_bridge(config, args):
    bridge = AgentPipelineBridge(config)
    if not bridge.is_available():
        print(f"[!] Bridge target not found at {bridge.pipeline_dir}", file=sys.stderr)
        sys.exit(1)

    sub = args.bridge_action
    if sub == "check":
        ok, out = bridge.run_check(snapshot=args.snapshot)
        print(out.strip())
    elif sub == "detonate":
        if not args.sample or not os.path.isfile(args.sample):
            print(f"[!] Sample file not found: {args.sample}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Delegating detonation of {args.sample} to Agent-pipeline-for-MA...")
        ok, out = bridge.detonate(args.sample, mode=args.mode, timeout=args.timeout, snapshot=args.snapshot)
        print(out)


def cmd_scan(config, args):
    if not os.path.isfile(args.sample):
        print(f"[!] Error: File not found: {args.sample}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing static PE metadata for: {args.sample}")
    analyzer = PEAnalyzer(args.sample)
    results = analyzer.analyze()

    print(f"\n--- Triage Summary ---")
    print(f"File: {results['filename']} ({results['filesize']:,} bytes)")
    print(f"Arch: {results['architecture']}")
    print(f"SHA256: {results['sha256']}")
    print(f"Entropy: {results['overall_entropy']} (Packed: {results['is_likely_packed']})")
    for ind in results["suspicious_indicators"]:
        print(f"  [!] {ind}")

    if args.json:
        print("\n" + json.dumps(results, indent=2))

    if args.report:
        rep = build_markdown_report(results)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(rep)
        print(f"[+] Saved Markdown report to: {args.report}")


def cmd_yara(config, args):
    if not os.path.isfile(args.sample):
        print(f"[!] Error: File not found: {args.sample}", file=sys.stderr)
        sys.exit(1)

    analyzer = PEAnalyzer(args.sample)
    meta = analyzer.analyze()
    rule = generate_yara_rule(meta, rule_name=args.name)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(rule)
        print(f"[+] Saved YARA rule to: {args.out}")
    else:
        print(rule)


def main():
    parser = argparse.ArgumentParser(description="general_MalAna - Malware Analysis Toolkit")
    subparsers = parser.add_subparsers(dest="command")

    # status
    subparsers.add_parser("status", help="Show environment, VM, and interop status")

    # vm
    vm_p = subparsers.add_parser("vm", help="Dynamic snapshot and VM control")
    vm_subs = vm_p.add_subparsers(dest="vm_action")
    vm_subs.add_parser("list", help="List all snapshots")
    vm_subs.add_parser("snapshots", help="List all snapshots")
    
    resolve_p = vm_subs.add_parser("resolve", help="Test snapshot resolution")
    resolve_p.add_argument("target", nargs="?", default="latest", help="Snapshot name, index, or 'latest'")

    revert_p = vm_subs.add_parser("revert", help="Revert to snapshot")
    revert_p.add_argument("--snapshot", "-s", help="Snapshot name, index, or regex pattern")
    revert_p.add_argument("--latest", action="store_true", help="Automatically revert to the latest snapshot")

    take_p = vm_subs.add_parser("take", help="Take a new snapshot")
    take_p.add_argument("name", help="Snapshot name")

    # bridge
    br_p = subparsers.add_parser("bridge", help="Interact with Agent-pipeline-for-MA")
    br_subs = br_p.add_subparsers(dest="bridge_action")
    chk_p = br_subs.add_parser("check", help="Run mal.py check via bridge")
    chk_p.add_argument("--snapshot", "-s", help="Override snapshot name dynamically")

    det_p = br_subs.add_parser("detonate", help="Run mal.py detonate via bridge")
    det_p.add_argument("sample", help="Path to sample file")
    det_p.add_argument("--mode", default="full", choices=["basic", "full"], help="Detonation mode")
    det_p.add_argument("--timeout", type=int, default=120, help="Detonation timeout in seconds")
    det_p.add_argument("--snapshot", "-s", help="Dynamic snapshot to revert before/after detonation")

    # scan
    scan_p = subparsers.add_parser("scan", help="Run standalone static PE triage on a sample")
    scan_p.add_argument("sample", help="Path to sample file")
    scan_p.add_argument("--json", action="store_true", help="Print raw JSON results")
    scan_p.add_argument("--report", help="Save report to Markdown file")

    # yara
    yara_p = subparsers.add_parser("yara", help="Generate draft YARA rule for a sample")
    yara_p.add_argument("sample", help="Path to sample file")
    yara_p.add_argument("--name", help="Custom rule name")
    yara_p.add_argument("--out", help="Save rule to file")

    args = parser.parse_args()
    config = load_config()

    if args.command == "status":
        cmd_status(config, args)
    elif args.command == "vm":
        cmd_vm(config, args)
    elif args.command == "bridge":
        cmd_bridge(config, args)
    elif args.command == "scan":
        cmd_scan(config, args)
    elif args.command == "yara":
        cmd_yara(config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
