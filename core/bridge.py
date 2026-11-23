"""Bridge for interoperability with Agent-pipeline-for-MA."""

import os
import subprocess
import sys


class AgentPipelineBridge:
    def __init__(self, config):
        self.config = config
        self.pipeline_dir = config.get("agent_pipeline_dir")
        self.python_exe = sys.executable

    def is_available(self):
        if not self.pipeline_dir or not os.path.isdir(self.pipeline_dir):
            return False
        mal_py = os.path.join(self.pipeline_dir, "host", "mal.py")
        return os.path.isfile(mal_py)

    def run_check(self, snapshot=None):
        """Run `python host/mal.py check` in the pipeline repo with optional snapshot override."""
        if not self.is_available():
            return False, f"Pipeline not found at {self.pipeline_dir}"
        cmd = [self.python_exe, "host/mal.py", "check"]
        env = os.environ.copy()
        if snapshot:
            env["CLEAN_SNAPSHOT"] = snapshot
        res = subprocess.run(cmd, cwd=self.pipeline_dir, capture_output=True, text=True, env=env)
        return res.returncode == 0, res.stdout + res.stderr

    def detonate(self, sample_path, mode="full", timeout=120, snapshot=None):
        """Run `python host/mal.py detonate` inside the pipeline repo with dynamic snapshot."""
        if not self.is_available():
            return False, f"Pipeline not found at {self.pipeline_dir}"
        cmd = [self.python_exe, "host/mal.py", "detonate", sample_path, "--mode", mode, "--timeout", str(timeout)]
        env = os.environ.copy()
        if snapshot:
            env["CLEAN_SNAPSHOT"] = snapshot
        res = subprocess.run(cmd, cwd=self.pipeline_dir, capture_output=True, text=True, env=env)
        return res.returncode == 0, res.stdout + res.stderr
