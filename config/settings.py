"""Configuration and settings manager for general_MalAna."""

import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
CONFIG_PATH = os.environ.get("MAL_CONFIG") or os.path.join(CONFIG_DIR, "config.json")
CONFIG_EXAMPLE = os.path.join(CONFIG_DIR, "config.example.json")


def load_config():
    """Load configuration from config.json with fallback to config.example.json and environment."""
    cfg = {}
    path_to_read = CONFIG_PATH if os.path.isfile(CONFIG_PATH) else CONFIG_EXAMPLE
    if os.path.isfile(path_to_read):
        try:
            with open(path_to_read, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except Exception as e:
            print(f"[!] Warning: failed to parse config file {path_to_read}: {e}")

    # Environment variables take precedence over config file
    if os.environ.get("GUEST_USER"):
        cfg["guest_user"] = os.environ["GUEST_USER"]
    if os.environ.get("GUEST_PASS"):
        cfg["guest_pass"] = os.environ["GUEST_PASS"]
    if os.environ.get("VMRUN_PATH"):
        cfg["vmrun"] = os.environ["VMRUN_PATH"]
    if os.environ.get("CLEAN_SNAPSHOT") or os.environ.get("MAL_SNAPSHOT"):
        cfg["default_snapshot"] = os.environ.get("CLEAN_SNAPSHOT") or os.environ.get("MAL_SNAPSHOT")
    if os.environ.get("VMX_PATH"):
        cfg["default_vmx"] = os.environ["VMX_PATH"]

    # Normalize paths
    if "agent_pipeline_dir" in cfg:
        pipeline_dir = cfg["agent_pipeline_dir"]
        if not os.path.isabs(pipeline_dir):
            cfg["agent_pipeline_dir"] = os.path.normpath(os.path.join(BASE_DIR, pipeline_dir))

    return cfg
