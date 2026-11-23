# general_MalAna

A modular, safety-first Malware Analysis framework designed for both standalone triage and unified interoperability with [`Agent-pipeline-for-MA`](../Agent-pipeline-for-MA).

---

## Architecture Overview

```
                               ┌──────────────────────────────────────────────┐
                               │                 general_MalAna               │
                               │  cli.py                                      │
                               └──────┬───────────────────────────────┬───────┘
                                      │                               │
                       ┌──────────────▼──────────────┐ ┌──────────────▼──────────────┐
                       │       Standalone Mode       │ │      Integrated Bridge      │
                       │                             │ │                             │
                       │ • PE Header & Raw Entropy   │ │ • Interop with              │
                       │ • Packing / Obfuscation     │ │   Agent-pipeline-for-MA     │
                       │ • Automated YARA generation │ │ • vmrun snapshot & isolate  │
                       │ • IOC Extractor             │ │ • Dynamic Snapshot Manager  │
                       │ • Markdown Report Generator │ │ • Safe detonation rail      │
                       │                             │ │ • Procmon/FakeNet ingestion │
                       └─────────────────────────────┘ └─────────────────────────────┘
```

---

## Key Features

1. **Dual-Mode Operation:**
   - **Standalone:** Fast triage of PE binaries without hypervisor dependencies (pure Python standard library). Computes Shannon entropy per section, detects W^X violations, generates draft YARA rules, and formats reports.
   - **Integrated:** Orchestrator and companion to `Agent-pipeline-for-MA`, managing VM snapshot reversions and feeding dynamic behavioral artifacts into threat intelligence outputs.
2. **Dynamic Snapshot Management:**
   - Avoids rigid hardcoding of snapshot timestamps.
   - Dynamically resolves snapshots by **name**, **numeric index** (`0`, `1`, `2`), **substring/regex pattern**, or keyword (`latest`).
   - Create snapshots on the fly before executing samples (`cli.py vm take <name>`).
   - Seamlessly passes dynamic snapshots through to `Agent-pipeline-for-MA` via the bridge (`--snapshot` or `CLEAN_SNAPSHOT` env var).
3. **Safety Containment Rails:**
   - Samples are **never executed on the host**.
   - Verifies VMware isolation parameters (network set to `hostonly`, HGFS shared folders disabled, clipboard/DnD disabled).
   - Artifact pull-filters strictly prevent binaries or dropped payloads from touching the host.

---

## Quick Start

### 1. Dynamic Snapshot Operations
List all snapshots and check which is active or newest:
```bash
python cli.py vm snapshots
```

Resolve any snapshot dynamically (by keyword, index, or date pattern):
```bash
python cli.py vm resolve latest
python cli.py vm resolve 0
python cli.py vm resolve "9-11"
```

Revert the VM dynamically:
```bash
python cli.py vm revert --latest
python cli.py vm revert -s "14-9-2026 16-38"
```

Take a new snapshot before analyzing:
```bash
python cli.py vm take "pre_sample_triage"
```

### 2. Check System & Pipeline Bridge Status
Verify your VM isolation, snapshot state, and bridge connectivity:
```bash
python cli.py status
# Or test bridge with a specific dynamic snapshot:
python cli.py bridge check --snapshot "14-9-2026 16-38"
```

### 3. Static PE Triage (Standalone)
Run instant static analysis on any sample without touching a VM:
```bash
python cli.py scan path/to/sample.exe --report out/sample_report.md
```

### 4. Generate a YARA Rule
Automatically extract static characteristics and generate a YARA rule:
```bash
python cli.py yara path/to/sample.exe --out out/sample.yar
```

---

## Configuration

Settings live in `config/config.json` (copied from `config/config.example.json`). Sensitive credentials and snapshot overrides can be supplied via environment variables without touching configuration files:
```bash
set GUEST_USER=REM
set GUEST_PASS=<password>
set CLEAN_SNAPSHOT=latest
```
