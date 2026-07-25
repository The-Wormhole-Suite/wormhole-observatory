from __future__ import annotations

import csv
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk
from typing import Any

from pihole_manager.config import load_options
from pihole_manager.database import review_delete, review_get, review_save, staging_enqueue
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain

_COLUMNS = (
    "selected",
    "domain",
    "categories",
    "policy",
    "short",
    "details",
    "status",
)


class LLMReviewTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self.status = tk.StringVar()
        self._build_ui()
        self.reload_preferences()
        self.after(300, self._refresh_loop)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="Queue again", command=self._queue_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            toolbar, text="Allow exact", command=lambda: self._apply_selected(Policy.ALLOW)
        ).pack(side="left", padx=(12, 0))
        ttk.Button(
            toolbar, text="Deny exact", command=lambda: self._apply_selected(Policy.DENY)
        ).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Remove review", command=self._remove_selected).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(toolbar, text="Export CSV", command=self._export_csv).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(toolbar, text="Import CSV", command=self._import_csv).pack(
            side="left", padx=(6, 0)
        )
        ttk.Label(toolbar, textvariable=self.status).pack(side="right")

        self.tree = ttk.Treeview(
            self,
            columns=_COLUMNS,
            show="headings",
            selectmode="extended",
        )
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        headings = {
            "selected": "✓",
            "domain": "Domain",
            "categories": "Categories",
            "policy": "Policy",
            "short": "Short",
            "details": "Details",
            "status": "Status",
        }
        for column, heading in headings.items():
            self.tree.heading(column, text=heading)
        self.tree.column("selected", width=38, stretch=False, anchor="center")
        self.tree.column("domain", width=250, anchor="w")
        self.tree.column("categories", width=150, anchor="w")
        self.tree.column("policy", width=110, anchor="center")
        self.tree.column("short", width=260, anchor="w")
        self.tree.column("details", width=430, anchor="w")
        self.tree.column("status", width=130, anchor="center")
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)

    def reload_preferences(self) -> None:
        options = load_options()
        state = "enabled" if options.llm.enabled else "disabled"
        self.status.set(f"Background LLM analysis is {state}")

    def _refresh_loop(self) -> None:
        self.refresh()
        self.after(2_000, self._refresh_loop)

    def refresh(self) -> None:
        rows = review_get(limit=1_000)
        current_selection = {
            self.tree.set(item, "domain")
            for item in self.tree.selection()
            if self.tree.set(item, "domain")
        }
        self._rows = {str(row["domain"]): row for row in rows}
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            domain = str(row.get("domain") or "")
            checked = domain in self._checked
            self.tree.insert(
                "",
                "end",
                iid=domain,
                values=(
                    "☑" if checked else "☐",
                    domain,
                    ",".join(row.get("categories") or []),
                    row.get("policy", "unknown"),
                    row.get("short", ""),
                    row.get("details", ""),
                    row.get("status", ""),
                ),
            )
        for domain in current_selection:
            if self.tree.exists(domain):
                self.tree.selection_add(domain)
        self.reload_preferences()

    def _toggle_checkbox(self, event: tk.Event) -> None:
        if self.tree.identify_column(event.x) != "#1":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        domain = self.tree.set(item, "domain")
        if domain in self._checked:
            self._checked.remove(domain)
            self.tree.set(item, "selected", "☐")
        else:
            self._checked.add(domain)
            self.tree.set(item, "selected", "☑")

    def _selected_domains(self) -> list[str]:
        if self._checked:
            return sorted(self._checked)
        return sorted(
            {
                self.tree.set(item, "domain")
                for item in self.tree.selection()
                if self.tree.set(item, "domain")
            }
        )

    def _queue_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("LLM Review", "Select or check at least one domain.")
            return
        added = staging_enqueue(domains)
        messagebox.showinfo("LLM Review", f"Queued {added} new domain(s).")

    def _apply_selected(self, policy: Policy) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("LLM Review", "Select or check at least one domain.")
            return
        future = self.executor.submit(self._apply_domains, domains, policy, self._rows)
        future.add_done_callback(lambda item: self.after(0, self._apply_done, item, policy))
        self.status.set(f"Applying {policy.value} …")

    @staticmethod
    def _apply_domains(
        domains: list[str], policy: Policy, rows: dict[str, dict[str, Any]]
    ) -> list[str]:
        errors: list[str] = []
        for domain in domains:
            try:
                short = str(rows.get(domain, {}).get("short") or "LLM review")
                add_exact_domain(domain, policy, short)
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return errors

    def _apply_done(self, future: Future, policy: Policy) -> None:
        try:
            errors = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        self.status.set(f"Manual {policy.value} completed")
        if errors:
            messagebox.showwarning(
                "LLM Review", "Some changes failed:\n" + "\n".join(errors[:10])
            )

    def _remove_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("LLM Review", "Select or check at least one domain.")
            return
        review_delete(domains)
        self._checked.difference_update(domains)
        self.refresh()

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export LLM review",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["domain", "categories", "policy", "short", "details", "provider", "status"]
            )
            for row in self._rows.values():
                writer.writerow(
                    [
                        row.get("domain", ""),
                        ",".join(row.get("categories") or []),
                        row.get("policy", "unknown"),
                        row.get("short", ""),
                        row.get("details", ""),
                        row.get("provider", ""),
                        row.get("status", ""),
                    ]
                )

    def _import_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Import LLM review",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                domain = str(row.get("domain") or "").strip()
                if not domain:
                    continue
                review_save(
                    domain,
                    row.get("categories") or "",
                    row.get("details") or "",
                    row.get("status") or "imported",
                    policy=row.get("policy") or "unknown",
                    short=row.get("short") or "",
                    provider=row.get("provider") or "",
                )
        self.refresh()
