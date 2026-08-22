from __future__ import annotations

import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Callable

from pihole_manager.pihole_audit import (
    PiHoleAuditEntry,
    list_pihole_audit,
    rollback_pihole_audit,
)


class PiHoleAuditTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        executor: ThreadPoolExecutor,
        *,
        on_rollback: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master, padding=10)
        self.executor = executor
        self.on_rollback = on_rollback
        self._entries: dict[str, PiHoleAuditEntry] = {}
        self.status = tk.StringVar(value="Audit log has not been loaded yet.")

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(
            toolbar,
            text="Roll back selected",
            command=self.rollback_selected,
        ).pack(side="left", padx=(8, 0))
        ttk.Label(toolbar, textvariable=self.status).pack(side="left", padx=(12, 0))

        columns = ("time", "instance", "operation", "resource", "value", "status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")
        headings = {
            "time": "Time",
            "instance": "Pi-hole",
            "operation": "Operation",
            "resource": "Resource",
            "value": "Value",
            "status": "Rollback",
        }
        widths = {
            "time": 150,
            "instance": 130,
            "operation": 90,
            "resource": 150,
            "value": 330,
            "status": 160,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.after(50, self.refresh)

    @staticmethod
    def _rollback_status(entry: PiHoleAuditEntry) -> str:
        if entry.operation == "rollback":
            return f"Rollback of #{entry.related_entry_id or '?'}"
        if entry.rolled_back_at is not None:
            return "Rolled back"
        if entry.rollback_error:
            return "Previous rollback failed"
        return "Available" if entry.reversible else "Unavailable"

    @staticmethod
    def _resource_label(entry: PiHoleAuditEntry) -> str:
        labels = {
            "exact_domain": "Exact domain",
            "regex_domain": "Regex domain",
            "subscribed_list": "Subscribed list",
        }
        base = labels.get(entry.resource_kind, entry.resource_kind)
        return f"{base} · {entry.resource_type}" if entry.resource_type else base

    def refresh(self) -> None:
        self.status.set("Loading audit log …")
        future = self.executor.submit(list_pihole_audit, 500)
        future.add_done_callback(lambda item: self.after(0, self._refresh_done, item))

    def _refresh_done(self, future: Future) -> None:
        try:
            entries = future.result()
        except Exception as exc:
            self.status.set(f"Audit log unavailable: {exc}")
            return
        self._entries.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in entries:
            item_id = str(entry.id)
            self._entries[item_id] = entry
            timestamp = datetime.fromtimestamp(entry.created_at).strftime("%Y-%m-%d %H:%M:%S")
            self.tree.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    timestamp,
                    entry.instance_name or entry.instance_url or "Pi-hole",
                    entry.operation.title(),
                    self._resource_label(entry),
                    entry.resource_key,
                    self._rollback_status(entry),
                ),
            )
        self.status.set(f"{len(entries)} audit entries")

    def rollback_selected(self) -> None:
        selected = self.tree.selection()
        if len(selected) != 1:
            messagebox.showinfo("Audit log", "Select exactly one audit entry.", parent=self)
            return
        entry = self._entries.get(selected[0])
        if entry is None:
            return
        if not entry.reversible or entry.rolled_back_at is not None:
            messagebox.showinfo(
                "Rollback",
                "The selected audit entry is not available for rollback.",
                parent=self,
            )
            return
        if not messagebox.askyesno(
            "Roll back Pi-hole change",
            "Restore the Pi-hole resource to its state before this change?\n\n"
            "Rollback is refused automatically if a newer change would be overwritten.",
            parent=self,
        ):
            return
        self.status.set(f"Rolling back #{entry.id} …")
        future = self.executor.submit(rollback_pihole_audit, entry.id)
        future.add_done_callback(lambda item: self.after(0, self._rollback_done, item))

    def _rollback_done(self, future: Future) -> None:
        try:
            rollback_id = future.result()
        except Exception as exc:
            messagebox.showerror("Rollback failed", str(exc), parent=self)
            self.status.set(f"Rollback failed: {exc}")
            self.refresh()
            return
        self.status.set(f"Rollback recorded as audit entry #{rollback_id}.")
        if self.on_rollback is not None:
            self.on_rollback()
        self.refresh()
