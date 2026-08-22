from __future__ import annotations

import json
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tkinter import messagebox, ttk

from pihole_manager.database import get_state
from pihole_manager.list_audit_config import (
    ListAuditOptions,
    load_list_audit_options,
    save_list_audit_options,
)
from pihole_manager.list_audit_worker import get_list_auditor, request_list_audit_now


class ListAuditTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master, padding=12)
        self.executor = executor
        self.enabled = tk.BooleanVar()
        self.interval = tk.StringVar()
        self.batch_size = tk.StringVar()
        self.rate_limit = tk.StringVar()
        self.max_domains = tk.StringVar()
        self.status = tk.StringVar(value="List audit is not configured yet.")
        self._build_ui()
        self.load()

    def _build_ui(self) -> None:
        self.columnconfigure(1, weight=1)
        ttk.Label(
            self,
            text=(
                "Audit enabled Pi-hole subscription lists without flooding the analysis queue. "
                "Lists are downloaded once per audit, domains are deduplicated, already "
                "classified domains are skipped, and remaining domains are queued in "
                "rate-limited background batches."
            ),
            wraplength=900,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        ttk.Checkbutton(
            self,
            text="Enable periodic subscription-list audits",
            variable=self.enabled,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=4)

        fields = (
            ("Audit interval (seconds)", self.interval),
            ("Domains per queue batch", self.batch_size),
            ("Delay between batches (seconds)", self.rate_limit),
            ("Maximum domains per list", self.max_domains),
        )
        for row, (label, variable) in enumerate(fields, start=2):
            ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(self, textvariable=variable, width=18).grid(
                row=row, column=1, sticky="w", padx=(10, 0), pady=4
            )

        actions = ttk.Frame(self)
        actions.grid(row=6, column=0, columnspan=3, sticky="w", pady=(12, 8))
        ttk.Button(actions, text="Save", command=self.save).pack(side="left")
        ttk.Button(actions, text="Run now", command=self.run_now).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="Refresh status", command=self.refresh_status).pack(
            side="left", padx=(8, 0)
        )

        ttk.Separator(self).grid(row=7, column=0, columnspan=3, sticky="ew", pady=8)
        ttk.Label(self, textvariable=self.status, wraplength=900, justify="left").grid(
            row=8, column=0, columnspan=3, sticky="w"
        )

    def load(self) -> None:
        options = load_list_audit_options()
        self.enabled.set(options.enabled)
        self.interval.set(str(options.interval_sec))
        self.batch_size.set(str(options.batch_size))
        self.rate_limit.set(str(options.rate_limit_sec))
        self.max_domains.set(str(options.max_domains_per_list))
        self.refresh_status()

    def _options_from_form(self) -> ListAuditOptions | None:
        try:
            return ListAuditOptions(
                enabled=self.enabled.get(),
                interval_sec=int(self.interval.get()),
                batch_size=int(self.batch_size.get()),
                rate_limit_sec=float(self.rate_limit.get()),
                max_domains_per_list=int(self.max_domains.get()),
            )
        except ValueError:
            messagebox.showerror(
                "List audit",
                "Interval, batch size, batch delay, and domain cap must be numeric.",
                parent=self,
            )
            return None

    def save(self) -> bool:
        options = self._options_from_form()
        if options is None:
            return False
        normalized = save_list_audit_options(options)
        self.interval.set(str(normalized.interval_sec))
        self.batch_size.set(str(normalized.batch_size))
        self.rate_limit.set(str(normalized.rate_limit_sec))
        self.max_domains.set(str(normalized.max_domains_per_list))
        get_list_auditor().wake()
        self.status.set("List-audit settings saved.")
        return True

    def run_now(self) -> None:
        if not self.save():
            return
        if not self.enabled.get():
            messagebox.showinfo(
                "List audit",
                "Enable periodic subscription-list audits before starting an audit.",
                parent=self,
            )
            return
        request_list_audit_now()
        self.status.set("List audit requested; the background worker will start immediately.")

    def refresh_status(self) -> None:
        raw = get_state("list_audit_last_summary", "") or ""
        if not raw:
            self.status.set("No completed subscription-list audit has been recorded yet.")
            return
        try:
            data = json.loads(raw)
            completed_at = int(data.get("completed_at") or 0)
            when = datetime.fromtimestamp(completed_at).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            self.status.set(
                f"Last audit: {when} — {int(data.get('lists_audited', 0))} list(s) audited, "
                f"{int(data.get('lists_failed', 0))} failed, "
                f"{int(data.get('domains_seen', 0))} unique domain(s) seen, "
                f"{int(data.get('domains_queued', 0))} queued in "
                f"{int(data.get('batches', 0))} batch(es)."
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            self.status.set("The last list-audit status record could not be read.")
