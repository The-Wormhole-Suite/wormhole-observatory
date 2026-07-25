from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def apply_theme(root: tk.Misc, theme: str) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        return

    if theme != "dark":
        return

    background = "#1f2430"
    foreground = "#e6e6e6"
    field = "#2b3245"
    selected = "#3b4252"
    style.configure(".", background=background, foreground=foreground)
    style.configure("TFrame", background=background)
    style.configure("TLabel", background=background, foreground=foreground)
    style.configure("TLabelframe", background=background, foreground=foreground)
    style.configure("TLabelframe.Label", background=background, foreground=foreground)
    style.configure("TButton", background=field, foreground=foreground, padding=6)
    style.map("TButton", background=[("active", selected), ("pressed", selected)])
    style.configure("TEntry", fieldbackground=field, foreground=foreground)
    style.configure("TCombobox", fieldbackground=field, foreground=foreground)
    style.configure(
        "Treeview", background=background, fieldbackground=background, foreground=foreground
    )
    style.map(
        "Treeview",
        background=[("selected", selected)],
        foreground=[("selected", foreground)],
    )
    style.configure("TNotebook", background=background)
    style.configure("TNotebook.Tab", background=field, foreground=foreground, padding=(10, 6))
    style.map("TNotebook.Tab", background=[("selected", selected)])
