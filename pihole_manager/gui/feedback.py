from __future__ import annotations

import tkinter as tk
from contextlib import suppress
from tkinter import ttk


def show_toast(parent: tk.Misc, message: str, *, duration_ms: int = 2200) -> None:
    """Show a small non-modal notification near the bottom-right of the app window."""
    if not message:
        return
    root = parent.winfo_toplevel()
    popup = tk.Toplevel(root)
    popup.withdraw()
    popup.overrideredirect(True)
    with suppress(tk.TclError):
        popup.attributes("-topmost", True)

    frame = ttk.Frame(popup, padding=(12, 8), relief="solid", borderwidth=1)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=message, justify="left", wraplength=420).pack()

    popup.update_idletasks()
    root.update_idletasks()
    width = popup.winfo_reqwidth()
    height = popup.winfo_reqheight()
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    x = root_x + max(0, root.winfo_width() - width - 18)
    y = root_y + max(0, root.winfo_height() - height - 42)
    popup.geometry(f"+{x}+{y}")
    popup.deiconify()
    popup.after(max(500, int(duration_ms)), popup.destroy)
