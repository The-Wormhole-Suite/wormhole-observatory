from __future__ import annotations

import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk

from pihole_manager.config import Options, PiHoleOptions
from pihole_manager.pihole_service import test_connection


class PiHoleSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master, padding=12)
        self.executor = executor
        self.columnconfigure(1, weight=1)

        self.base_url = tk.StringVar()
        self.password = tk.StringVar()
        self.verify_tls = tk.BooleanVar()
        self.timeout = tk.StringVar()
        self.result = tk.StringVar(value="No test performed.")

        fields = (
            ("Base URL", self.base_url, False),
            ("Application password", self.password, True),
            ("Timeout in seconds", self.timeout, False),
        )
        for row, (label, variable, secret) in enumerate(fields):
            ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(self, textvariable=variable, show="•" if secret else "").grid(
                row=row, column=1, sticky="ew", padx=(10, 0), pady=4
            )

        ttk.Checkbutton(
            self, text="Verify TLS certificates", variable=self.verify_tls
        ).grid(row=3, column=1, sticky="w", padx=(10, 0), pady=4)
        ttk.Label(
            self,
            text=(
                "The password is stored only in the local options.json file. "
                "That file is excluded from Git."
            ),
            wraplength=760,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 4))

        self.test_button = ttk.Button(
            self, text="Test connection", command=self._test_connection
        )
        self.test_button.grid(row=5, column=0, sticky="w", pady=(12, 4))
        ttk.Label(self, textvariable=self.result, wraplength=900).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(8, 0)
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

    def _test_connection(self) -> None:
        values = self._values()
        if values is None:
            return
        self.test_button.state(["disabled"])
        self.result.set("Testing connection …")
        future = self.executor.submit(test_connection, values)
        future.add_done_callback(lambda item: self.after(0, self._show_result, item))

    def _show_result(self, future: Future) -> None:
        self.test_button.state(["!disabled"])
        try:
            result = future.result()
        except Exception as exc:
            self.result.set(str(exc))
            return
        state = "SUCCESS" if result.success else "FAILED"
        self.result.set(
            f"{state} — {result.request_url} — {result.elapsed_ms} ms — {result.summary}"
        )
