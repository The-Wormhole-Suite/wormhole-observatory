from __future__ import annotations

import time
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk
from typing import Any

from pihole_manager.config import load_options, save_options
from pihole_manager.database import staging_enqueue
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain, fetch_queries

_COLUMNS = ("selected", "time", "client", "domain", "type", "status")


class QueriesTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._last_timestamp = int(time.time()) - 60
        self._request_running = False
        self._layout_after_id: str | None = None
        self._build_ui()
        self.reload_preferences()
        self.after(250, self._poll_loop)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="→ LLM", command=self._queue_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            toolbar, text="Allow exact", command=lambda: self._apply_selected(Policy.ALLOW)
        ).pack(side="left", padx=(12, 0))
        ttk.Button(
            toolbar, text="Deny exact", command=lambda: self._apply_selected(Policy.DENY)
        ).pack(side="left", padx=(6, 0))

        self.auto_update = tk.BooleanVar()
        self.auto_scroll = tk.BooleanVar()
        ttk.Checkbutton(
            toolbar,
            text="Auto-update",
            variable=self.auto_update,
            command=self._save_preferences,
        ).pack(side="right")
        ttk.Checkbutton(
            toolbar,
            text="Auto-scroll",
            variable=self.auto_scroll,
            command=self._save_preferences,
        ).pack(side="right", padx=(0, 10))
        self.status = tk.StringVar(value="Idle")
        ttk.Label(toolbar, textvariable=self.status).pack(side="right", padx=(0, 14))

        self.tree = ttk.Treeview(
            self,
            columns=_COLUMNS,
            show="headings",
            selectmode="extended",
        )
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        headings = {
            "selected": "✓",
            "time": "Time",
            "client": "Client",
            "domain": "Domain",
            "type": "Type",
            "status": "Status",
        }
        for column, heading in headings.items():
            self.tree.heading(column, text=heading)
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.tree.bind("<ButtonRelease-1>", self._schedule_layout_save, add=True)
        self.tree.bind("<Configure>", self._schedule_layout_save, add=True)

        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Queue for LLM", command=self._queue_selected)
        menu.add_separator()
        menu.add_command(label="Allow exact", command=lambda: self._apply_selected(Policy.ALLOW))
        menu.add_command(label="Deny exact", command=lambda: self._apply_selected(Policy.DENY))
        self.menu = menu
        self.tree.bind("<Button-3>", self._show_context_menu)

    def reload_preferences(self) -> None:
        options = load_options().ui
        self.auto_update.set(options.auto_update_queries)
        self.auto_scroll.set(options.auto_scroll_queries)
        for column in _COLUMNS:
            width = int(options.queries_colwidths.get(column, 120))
            self.tree.column(
                column,
                width=width,
                anchor="center" if column in {"selected", "time", "type", "status"} else "w",
                stretch=column != "selected",
            )

    def _poll_loop(self) -> None:
        if self.auto_update.get() and not self._request_running:
            self.refresh()
        self.after(load_options().ui.query_refresh_ms, self._poll_loop)

    def refresh(self) -> None:
        if self._request_running:
            return
        self._request_running = True
        self.status.set("Loading …")
        future = self.executor.submit(fetch_queries, 300, self._last_timestamp)
        future.add_done_callback(lambda item: self.after(0, self._refresh_done, item))

    def _refresh_done(self, future: Future) -> None:
        self._request_running = False
        try:
            rows = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return

        added = 0
        for row in rows:
            timestamp = int(row.get("time") or 0)
            identifier = "|".join(
                (
                    str(timestamp),
                    str(row.get("client") or ""),
                    str(row.get("domain") or ""),
                    str(row.get("type") or ""),
                    str(len(self._rows)),
                )
            )
            self._rows[identifier] = row
            self._insert_row(identifier, row)
            self._last_timestamp = max(self._last_timestamp, timestamp + 1)
            added += 1

        children = self.tree.get_children()
        if len(children) > 2_000:
            for item in children[: len(children) - 2_000]:
                domain = self.tree.set(item, "domain")
                self._checked.discard(domain)
                self._rows.pop(item, None)
                self.tree.delete(item)
        if added and self.auto_scroll.get():
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])
        self.status.set(f"{added} new · {len(self.tree.get_children())} shown")

    def _insert_row(self, identifier: str, row: dict[str, Any]) -> None:
        timestamp = int(row.get("time") or 0)
        formatted = time.strftime("%H:%M:%S", time.localtime(timestamp)) if timestamp else ""
        domain = str(row.get("domain") or "")
        selected = "☑" if domain in self._checked else "☐"
        self.tree.insert(
            "",
            "end",
            iid=identifier,
            values=(
                selected,
                formatted,
                row.get("client", ""),
                domain,
                row.get("type", ""),
                row.get("status", ""),
            ),
        )

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
        domains = {
            self.tree.set(item, "domain").strip().lower()
            for item in self.tree.selection()
            if self.tree.set(item, "domain").strip()
        }
        return sorted(domains)

    def _queue_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Live Queries", "Select or check at least one domain.")
            return
        added = staging_enqueue(domains)
        messagebox.showinfo("LLM", f"Queued {added} new domain(s) for analysis.")

    def _apply_selected(self, policy: Policy) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Live Queries", "Select or check at least one domain.")
            return
        self.status.set(f"Applying {policy.value} …")
        future = self.executor.submit(self._apply_domains, domains, policy)
        future.add_done_callback(lambda item: self.after(0, self._apply_done, item, policy))

    @staticmethod
    def _apply_domains(domains: list[str], policy: Policy) -> tuple[int, list[str]]:
        successful = 0
        errors: list[str] = []
        for domain in domains:
            try:
                add_exact_domain(domain, policy, "Added from Live Queries")
                successful += 1
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return successful, errors

    def _apply_done(self, future: Future, policy: Policy) -> None:
        try:
            successful, errors = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        self.status.set(f"{policy.value}: {successful} applied")
        if errors:
            messagebox.showwarning(
                "Live Queries", "Some changes failed:\n" + "\n".join(errors[:10])
            )

    def _show_context_menu(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if item and item not in self.tree.selection():
            self.tree.selection_set(item)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _save_preferences(self) -> None:
        options = load_options()
        options.ui.auto_update_queries = self.auto_update.get()
        options.ui.auto_scroll_queries = self.auto_scroll.get()
        save_options(options)

    def _schedule_layout_save(self, _event: tk.Event | None = None) -> None:
        if self._layout_after_id:
            self.after_cancel(self._layout_after_id)
        self._layout_after_id = self.after(500, self._save_layout)

    def _save_layout(self) -> None:
        self._layout_after_id = None
        options = load_options()
        options.ui.queries_colwidths = {
            column: int(self.tree.column(column, option="width")) for column in _COLUMNS
        }
        save_options(options)
