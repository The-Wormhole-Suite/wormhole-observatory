from __future__ import annotations

import time
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk
from typing import Any

from pihole_manager.config import load_options, save_options
from pihole_manager.database import queue_domains_for_review
from pihole_manager.gui.column_visibility import ColumnVisibilityController
from pihole_manager.gui.feedback import show_toast
from pihole_manager.gui.policy_labels import action_label
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain, fetch_queries

_COLUMNS = ("selected", "time", "client", "domain", "type", "status")
_HEADINGS = {
    "selected": "✓",
    "time": "Time",
    "client": "Client",
    "domain": "Domain",
    "type": "Type",
    "status": "Status",
}


class QueriesTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._last_timestamp = time.time() - 60.0
        self._request_running = False
        self._failure_count = 0
        self._next_poll_at = 0.0
        self._build_ui()
        self.reload_preferences()
        self.after(250, self._poll_loop)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="→ Review", command=self._queue_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            toolbar, text="Whitelist exact", command=lambda: self._apply_selected(Policy.ALLOW)
        ).pack(side="left", padx=(12, 0))
        ttk.Button(
            toolbar, text="Blacklist exact", command=lambda: self._apply_selected(Policy.DENY)
        ).pack(side="left", padx=(6, 0))
        self.columns_button = ttk.Menubutton(toolbar, text="Columns")
        self.columns_button.pack(side="left", padx=(12, 0))

        self.auto_update = tk.BooleanVar()
        self.auto_scroll = tk.BooleanVar()
        self.refresh_seconds = tk.StringVar()
        self.status = tk.StringVar(value="Idle")
        preferences = ttk.Frame(toolbar)
        preferences.pack(side="right")
        ttk.Label(preferences, textvariable=self.status).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(
            preferences,
            text="Auto-scroll",
            variable=self.auto_scroll,
            command=self._save_preferences,
        ).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(
            preferences,
            text="Auto-update",
            variable=self.auto_update,
            command=self._save_preferences,
        ).pack(side="left", padx=(0, 10))
        ttk.Label(preferences, text="Refresh every").pack(side="left", padx=(0, 4))
        refresh_box = ttk.Spinbox(
            preferences,
            textvariable=self.refresh_seconds,
            from_=0.5,
            to=300.0,
            increment=0.5,
            width=6,
            command=self._save_preferences,
        )
        refresh_box.pack(side="left")
        refresh_box.bind("<Return>", lambda _event: self._save_preferences())
        refresh_box.bind("<FocusOut>", lambda _event: self._save_preferences())
        ttk.Label(preferences, text="s").pack(side="left", padx=(4, 0))

        tree_frame = ttk.Frame(self, padding=(8, 0, 8, 8))
        tree_frame.pack(fill="both", expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_frame,
            columns=_COLUMNS,
            show="headings",
            selectmode="extended",
        )
        vertical = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        for column, heading in _HEADINGS.items():
            self.tree.heading(column, text=heading)
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.column_controller = ColumnVisibilityController(
            self.columns_button,
            self.tree,
            table_key="queries",
            columns=_COLUMNS,
            headings=_HEADINGS,
        )

        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Queue for review", command=self._queue_selected)
        menu.add_separator()
        menu.add_command(
            label="Whitelist exact",
            command=lambda: self._apply_selected(Policy.ALLOW),
        )
        menu.add_command(label="Blacklist exact", command=lambda: self._apply_selected(Policy.DENY))
        self.menu = menu
        self.tree.bind("<Button-3>", self._show_context_menu)

    def reload_preferences(self) -> None:
        options = load_options().ui
        self.auto_update.set(options.auto_update_queries)
        if self.auto_update.get():
            self._next_poll_at = 0.0
        self.auto_scroll.set(options.auto_scroll_queries)
        self.refresh_seconds.set(f"{options.query_refresh_ms / 1000:g}")
        for column in _COLUMNS:
            self.tree.column(
                column,
                anchor="center" if column in {"selected", "time", "type", "status"} else "w",
                stretch=column != "selected",
            )
        self.column_controller.reload()

    def _poll_loop(self) -> None:
        now = time.monotonic()
        if self.auto_update.get() and not self._request_running and now >= self._next_poll_at:
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
            self._failure_count += 1
            base_delay = load_options().ui.query_refresh_ms / 1000
            retry_delay = min(60.0, max(base_delay, 2 ** min(self._failure_count, 6)))
            self._next_poll_at = time.monotonic() + retry_delay
            self.status.set(f"Connection failed · retry in {int(retry_delay)} s: {exc}")
            return

        self._failure_count = 0
        self._next_poll_at = 0.0
        added = 0
        for row in rows:
            timestamp = float(row.get("time") or 0)
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
            self._last_timestamp = max(self._last_timestamp, timestamp + 0.001)
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
        timestamp = float(row.get("time") or 0)
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
        if self.column_controller.displayed_column_at(event.x) != "selected":
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
            show_toast(self, "Select or check at least one domain.")
            return
        result = queue_domains_for_review(domains, source="manual_live_query")
        parts = []
        if result.queued:
            parts.append(f"{result.queued} queued")
        if result.requeued:
            parts.append(f"{result.requeued} requeued")
        if result.already_pending:
            parts.append(f"{result.already_pending} already pending")
        if result.skipped_locked:
            parts.append(f"{result.skipped_locked} protected")
        if result.skipped_filtered:
            parts.append(f"{result.skipped_filtered} filtered")
        show_toast(self, ", ".join(parts) or "No domains queued.")

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
        self.status.set(f"{action_label(policy)}: {successful} applied")
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
        try:
            refresh_seconds = max(0.5, float(self.refresh_seconds.get()))
        except ValueError:
            self.refresh_seconds.set(f"{options.ui.query_refresh_ms / 1000:g}")
            return
        options.ui.auto_update_queries = self.auto_update.get()
        if self.auto_update.get():
            self._failure_count = 0
            self._next_poll_at = 0.0
        options.ui.auto_scroll_queries = self.auto_scroll.get()
        options.ui.query_refresh_ms = round(refresh_seconds * 1000)
        self.refresh_seconds.set(f"{options.ui.query_refresh_ms / 1000:g}")
        save_options(options)
