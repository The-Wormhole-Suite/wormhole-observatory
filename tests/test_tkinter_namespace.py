from __future__ import annotations

import ast
import tkinter.ttk as ttk
from pathlib import Path


def _assigned_self_attributes(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assigned: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets.extend(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets.append(node.target)
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                assigned.add(target.attr)
    return assigned


def test_settings_pages_do_not_shadow_tkinter_widget_callables() -> None:
    reserved = {
        name
        for name in dir(ttk.Frame)
        if callable(getattr(ttk.Frame, name, None))
    }
    collisions: dict[str, list[str]] = {}
    settings_dir = Path("pihole_manager/gui/tabs")
    for path in sorted(settings_dir.glob("settings*.py")):
        shadowed = sorted(_assigned_self_attributes(path) & reserved)
        if shadowed:
            collisions[str(path)] = shadowed

    assert not collisions, f"Tkinter callable names shadowed by instance state: {collisions}"
