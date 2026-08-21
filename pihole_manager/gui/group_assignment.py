from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any


def choose_groups(
    parent: tk.Misc,
    groups: list[dict[str, Any]],
    selected_ids: set[int] | list[int] | tuple[int, ...],
    *,
    title: str = "Assign groups",
    description: str = "Select the Pi-hole groups that should apply to the selected items.",
) -> list[int] | None:
    selected = {int(value) for value in selected_ids}
    result: list[int] | None = None

    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent.winfo_toplevel())
    dialog.resizable(True, True)
    dialog.minsize(420, 360)

    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=description, wraplength=560, justify="left").pack(fill="x")

    list_frame = ttk.Frame(frame)
    list_frame.pack(fill="both", expand=True, pady=(10, 10))
    listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE, exportselection=False)
    scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
    listbox.configure(yscrollcommand=scrollbar.set)
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    ids: list[int] = []
    for index, group in enumerate(groups):
        group_id = int(group["id"])
        ids.append(group_id)
        label = str(group.get("name") or f"Group {group_id}")
        if not group.get("enabled", True):
            label += " (disabled)"
        listbox.insert("end", f"{label}  [#{group_id}]")
        if group_id in selected:
            listbox.selection_set(index)

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x")

    def select_all() -> None:
        listbox.selection_set(0, "end")

    def select_none() -> None:
        listbox.selection_clear(0, "end")

    def apply() -> None:
        nonlocal result
        result = [ids[index] for index in listbox.curselection()]
        dialog.destroy()

    ttk.Button(buttons, text="All", command=select_all).pack(side="left")
    ttk.Button(buttons, text="None", command=select_none).pack(side="left", padx=(6, 0))
    ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right")
    ttk.Button(buttons, text="Apply", command=apply).pack(side="right", padx=(0, 6))

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    dialog.wait_window()
    return result
