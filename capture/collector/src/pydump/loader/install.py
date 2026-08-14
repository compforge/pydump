from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

from pydump.target import Target


def install_agent(target: Target, source: Path) -> tuple[Path, str]:
    """Copy a content-addressed Agent into the target mount namespace."""
    fingerprint = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    target_path = f"/tmp/pydump-agent-{fingerprint}.so"
    host_path = target.root / target_path.lstrip("/")
    if not host_path.exists():
        temporary = host_path.with_suffix(".partial")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755)
        os.replace(temporary, host_path)
    return host_path, target_path
