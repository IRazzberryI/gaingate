"""Copy the fictional notes-api walkthrough into a new directory."""

from __future__ import annotations

import shutil
from pathlib import Path

from gaingate.workspace import EXAMPLE_DIR, WorkspaceError

WALKTHROUGH_LEAVES = ("pass", "fail-baseline", "fail-required-hop")


def synth_example(dest_dir: str | Path) -> Path:
    dest = Path(dest_dir).expanduser().resolve()
    if dest.exists() and any(dest.iterdir()):
        raise WorkspaceError(
            f"{dest} already exists and is not empty. Choose an empty path."
        )
    if not EXAMPLE_DIR.is_dir():
        raise WorkspaceError(f"shipped example is missing: {EXAMPLE_DIR}")
    for leaf in WALKTHROUGH_LEAVES:
        if not (EXAMPLE_DIR / leaf / "gate.yaml").is_file():
            raise WorkspaceError(f"shipped example is incomplete: missing {leaf}")
    dest.mkdir(parents=True, exist_ok=True)
    # Copy the walkthrough README plus each case directory.
    readme = EXAMPLE_DIR / "README.md"
    if readme.is_file():
        shutil.copyfile(readme, dest / "README.md")
    for leaf in WALKTHROUGH_LEAVES:
        shutil.copytree(EXAMPLE_DIR / leaf, dest / leaf, dirs_exist_ok=False)
    return dest
