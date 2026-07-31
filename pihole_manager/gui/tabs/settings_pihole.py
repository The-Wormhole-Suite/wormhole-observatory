from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, ttk

from pihole_manager.config import Options, PiHoleOptions


class PiHoleSettingsPage(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        save_test_command: Callable[[], None],
    ) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)

        self.base_url = tk.StringVar()
        self.password = tk.StringVar()
        self.verify_tls = tk.BooleanVar()
        self.timeout = tk.StringVar()
        self.result = tk.StringVar(value="No connection test performed.")

        ttk.Label(self, text="Base URL").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.base_url).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        ttk.Label(self, text="Application password").grid(
            row=1,
            column=0,
            sticky="w",
            pady=4,
        )
        ttk.Entry(self, textvariable=self.password, show="•").grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )

        ttk.Label(self, text="Timeout in seconds").grid(
            row=2,
            column=0,
            sticky="w",
            pady=4,
        )
        timeout_row = ttk.Frame(self)
        timeout_row.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=4)
        ttk.Entry(timeout_row, textvariable=self.timeout, width=10).pack(side="left")
        ttk.Checkbutton(
            timeout_row,
            text="Verify TLS certificate",
            variable=self.verify_tls,
        ).pack(side="left", padx=(12, 0))

        self.save_test_button = ttk.Button(
            self,
            text="Save + Test",
            command=save_test_command,
        )
        self.save_test_button.grid(
            row=3,
            column=1,
            sticky="w",
            padx=(10, 0),
            pady=(8, 4),
        )
        self.save_test_button._skip_auto_save = True  # type: ignore[attr-defined]

        ttk.Label(self, textvariable=self.result, wraplength=900).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(8, 0),
        )

    def load(self, options: Options) -> None:
        self.base_url.set(options.pihole.base_url)
        self.password.set(options.pihole.password)
        self.verify_tls.set(options.pihole.verify_tls)
        self.timeout.set(str(options.pihole.timeout_sec))

    def _values(self) -> PiHoleOptions | None:
        try:
            timeout = float(self.timeout.get())
        except ValueError:
            messagebox.showerror("Connection", "Timeout must be a number.")
            return None
        if timeout <= 0:
            messagebox.showerror("Connection", "Timeout must be greater than zero.")
            return None
        return PiHoleOptions(
            base_url=self.base_url.get().strip(),
            password=self.password.get(),
            verify_tls=self.verify_tls.get(),
            timeout_sec=timeout,
        )

    def store(self, options: Options) -> bool:
        values = self._values()
        if values is None:
            return False
        options.pihole = values
        return True

    def set_connection_status(self, text: str) -> None:
        self.result.set(text)

    def set_test_running(self, running: bool) -> None:
        self.save_test_button.state(["disabled"] if running else ["!disabled"])
