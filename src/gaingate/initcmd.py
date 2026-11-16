"""Create a new case workspace from the shipped templates."""

from __future__ import annotations

import shutil
from pathlib import Path

from gaingate.workspace import CASE_MARKERS, TEMPLATE_DIR, WorkspaceError

TEMPLATE_FILES = CASE_MARKERS + ("confound_registry.yaml",)


def init_case(case_dir: str | Path) -> Path:
    dest = Path(case_dir).expanduser().resolve()
    if dest.exists():
        if not dest.is_dir():
            raise WorkspaceError(f"path exists and is not a directory: {dest}")
        leftover = [name for name in TEMPLATE_FILES if (dest / name).exists()]
        if leftover:
            raise WorkspaceError(
                f"{dest} already looks like a case directory "
                f"(found {', '.join(leftover)}). Choose an empty path."
            )
    else:
        dest.mkdir(parents=True)

    for name in TEMPLATE_FILES:
        src = TEMPLATE_DIR / name
        if not src.is_file():
            raise WorkspaceError(f"missing shipped template: {src}")
        shutil.copyfile(src, dest / name)

    (dest / "evidence").mkdir(exist_ok=True)
    return dest
