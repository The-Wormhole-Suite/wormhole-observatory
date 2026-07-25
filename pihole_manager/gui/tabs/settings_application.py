from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from pihole_manager.config import Options


class ApplicationSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)

        self.logging_enabled = tk.BooleanVar()
        self.logging_level = tk.StringVar()
        self.logging_filename = tk.StringVar()
        self.theme = tk.StringVar()
        self.auto_update = tk.BooleanVar()
        self.auto_scroll = tk.BooleanVar()
        self.refresh_ms = tk.StringVar()

        ttk.Checkbutton(
            self, text="Write rotating log file", variable=self.logging_enabled
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=4)
        self._row("Log level", self.logging_level, 1, values=("DEBUG", "INFO", "WARNING", "ERROR"))
        self._row("Log filename", self.logging_filename, 2)
        self._row("Theme", self.theme, 3, values=("system", "light", "dark"))
        ttk.Checkbutton(
            self, text="Auto-update live queries", variable=self.auto_update
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Checkbutton(
            self, text="Auto-scroll live queries", variable=self.auto_scroll
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=4)
        self._row("Query refresh interval (ms)", self.refresh_ms, 6)

    def _row(
        self,
        label: str,
        variable: tk.StringVar,
        row: int,
        values: tuple[str, ...] | None = None,
    ) -> None:
        ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", pady=4)
        if values:
            widget = ttk.Combobox(self, textvariable=variable, values=values, state="readonly")
        else:
            widget = ttk.Entry(self, textvariable=variable)
        widget.grid(row=row, column=1, sticky="ew", padx=(10, 0), pady=4)

    def load(self, options: Options) -> None:
        self.logging_enabled.set(options.logging.enabled)
        self.logging_level.set(options.logging.level)
        self.logging_filename.set(options.logging.filename)
        self.theme.set(options.ui.theme)
        self.auto_update.set(options.ui.auto_update_queries)
        self.auto_scroll.set(options.ui.auto_scroll_queries)
        self.refresh_ms.set(str(options.ui.query_refresh_ms))

    def store(self, options: Options) -> bool:
        try:
            refresh_ms = int(self.refresh_ms.get())
        except ValueError:
            messagebox.showerror("Application", "Refresh interval must be an integer.")
            return False
        options.logging.enabled = self.logging_enabled.get()
        options.logging.level = self.logging_level.get()
        options.logging.filename = self.logging_filename.get().strip()
        options.ui.theme = self.theme.get()
        options.ui.auto_update_queries = self.auto_update.get()
        options.ui.auto_scroll_queries = self.auto_scroll.get()
        options.ui.query_refresh_ms = refresh_ms
        return True
