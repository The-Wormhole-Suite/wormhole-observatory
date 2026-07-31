from __future__ import annotations

import datetime as dt
import time
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk
from typing import Any

from pihole_manager.config import load_options, save_options
from pihole_manager.database import (
    domains_without_classification,
    queue_domains_for_review,
    record_discovered_domains,
)
from pihole_manager.gui.column_visibility import ColumnVisibilityController
from pihole_manager.gui.feedback import show_toast
from pihole_manager.pihole_service import fetch_query_page

_COLUMNS = ("selected", "time", "client", "domain", "type", "status", "classified")
_HEADINGS = {
    "selected": "✓",
    "time": "Time",
    "client": "Client",
    "domain": "Domain",
    "type": "Type",
    "status": "Status",
    "classified": "Classified",
}
_DATE_FORMAT = "%Y-%m-%d %H:%M"


class HistoryTab(ttk.Frame):
    PAGE_SIZE = 500

    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self.from_text = tk.StringVar()
        self.until_text = tk.StringVar()
        self.domain_filter = tk.StringVar()
        self.client_filter = tk.StringVar()
        self.only_unclassified = tk.BooleanVar(value=False)
        self.deduplicate_domains = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Idle")
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._request_running = False
        self._page_until: float | None = None
        self._newer_stack: list[float | None] = []
        self._build_ui()
        self._set_default_range()
        self.reload_preferences()

    def _build_ui(self) -> None:
        filters = ttk.Frame(self, padding=(8, 6))
        filters.pack(fill="x")
        ttk.Label(filters, text="From").pack(side="left")
        ttk.Entry(filters, textvariable=self.from_text, width=17).pack(side="left", padx=(5, 10))
        ttk.Label(filters, text="Until").pack(side="left")
        ttk.Entry(filters, textvariable=self.until_text, width=17).pack(side="left", padx=(5, 10))
        ttk.Label(filters, text="Domain").pack(side="left")
        domain = ttk.Entry(filters, textvariable=self.domain_filter, width=22)
        domain.pack(side="left", padx=(5, 10))
        ttk.Label(filters, text="Client").pack(side="left")
        client = ttk.Entry(filters, textvariable=self.client_filter, width=18)
        client.pack(side="left", padx=(5, 10))
        ttk.Checkbutton(
            filters,
            text="Only unclassified",
            variable=self.only_unclassified,
            command=self.search,
        ).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(
            filters,
            text="Deduplicate domains",
            variable=self.deduplicate_domains,
            command=self._deduplication_changed,
        ).pack(side="left", padx=(0, 10))
        ttk.Button(filters, text="Search", command=self.search).pack(side="left")
        domain.bind("<Return>", lambda _event: self.search())
        client.bind("<Return>", lambda _event: self.search())

        actions = ttk.Frame(self, padding=(8, 0, 8, 6))
        actions.pack(fill="x")
        ttk.Button(actions, text="Queue for review", command=self._queue_selected).pack(side="left")
        ttk.Button(actions, text="Queue page", command=self._queue_page).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Newer", command=self._newer_page).pack(side="left", padx=(12, 0))
        ttk.Button(actions, text="Older", command=self._older_page).pack(side="left", padx=(6, 0))
        self.columns_button = ttk.Menubutton(actions, text="Columns")
        self.columns_button.pack(side="left", padx=(12, 0))
        ttk.Label(actions, textvariable=self.status).pack(side="right")

        tree_host = ttk.Frame(self, padding=(8, 0, 8, 8))
        tree_host.pack(fill="both", expand=True)
        tree_host.rowconfigure(0, weight=1)
        tree_host.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_host,
            columns=_COLUMNS,
            show="headings",
            selectmode="extended",
        )
        vertical = ttk.Scrollbar(tree_host, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(tree_host, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        for column, heading in _HEADINGS.items():
            self.tree.heading(column, text=heading)
            self.tree.column(
                column,
                anchor="center"
                if column in {"selected", "time", "type", "status", "classified"}
                else "w",
                stretch=column not in {"selected", "classified"},
            )
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.column_controller = ColumnVisibilityController(
            self.columns_button,
            self.tree,
            table_key="history",
            columns=_COLUMNS,
            headings=_HEADINGS,
        )

    def _set_default_range(self) -> None:
        now = dt.datetime.now()
        self.until_text.set(now.strftime(_DATE_FORMAT))
        self.from_text.set((now - dt.timedelta(days=7)).strftime(_DATE_FORMAT))

    def reload_preferences(self) -> None:
        options = load_options().ui
        self.deduplicate_domains.set(options.history_deduplicate_domains)
        self.column_controller.reload()

    def _deduplication_changed(self) -> None:
        options = load_options()
        options.ui.history_deduplicate_domains = bool(self.deduplicate_domains.get())
        save_options(options)
        self.search()

    def search(self) -> None:
        self._page_until = None
        self._newer_stack.clear()
        self._fetch_page()

    def _parse_range(self) -> tuple[float, float]:
        try:
            start = dt.datetime.strptime(self.from_text.get().strip(), _DATE_FORMAT)
            end = dt.datetime.strptime(self.until_text.get().strip(), _DATE_FORMAT)
        except ValueError as exc:
            raise ValueError("Use YYYY-MM-DD HH:MM for From and Until.") from exc
        if end <= start:
            raise ValueError("Until must be later than From.")
        return start.timestamp(), end.timestamp()

    def _fetch_page(self) -> None:
        if self._request_running:
            return
        try:
            start, end = self._parse_range()
        except ValueError as exc:
            messagebox.showerror("History", str(exc))
            return
        until = min(end, self._page_until) if self._page_until is not None else end
        self._request_running = True
        self.status.set("Loading …")
        future = self.executor.submit(
            self._load_page,
            start,
            until,
            self.domain_filter.get().strip() or None,
            self.client_filter.get().strip() or None,
            bool(self.only_unclassified.get()),
            bool(self.deduplicate_domains.get()),
        )
        future.add_done_callback(lambda item: self.after(0, self._fetch_done, item))

    @staticmethod
    def _load_page(
        start: float,
        until: float,
        domain: str | None,
        client: str | None,
        only_unclassified: bool,
        deduplicate_domains: bool,
    ) -> tuple[list[dict[str, Any]], set[str], int]:
        page = fetch_query_page(
            HistoryTab.PAGE_SIZE,
            start,
            until,
            domain=domain,
            client=client,
        )
        rows = sorted(page.rows, key=lambda row: float(row.get("time") or 0), reverse=True)
        source_count = len(rows)
        record_discovered_domains(rows)
        domains = {str(row.get("domain") or "").strip().lower() for row in rows}
        domains.discard("")
        unclassified = domains_without_classification(domains)
        if only_unclassified:
            rows = [
                row for row in rows if str(row.get("domain") or "").strip().lower() in unclassified
            ]
        if deduplicate_domains:
            rows = _deduplicate_rows(rows)
        return rows, unclassified, source_count

    def _fetch_done(self, future: Future) -> None:
        self._request_running = False
        try:
            rows, unclassified, source_count = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        self._rows.clear()
        self._checked.clear()
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(rows):
            timestamp = float(row.get("time") or 0)
            domain = str(row.get("domain") or "").strip().lower()
            identifier = f"{timestamp}|{domain}|{row.get('client', '')}|{index}"
            self._rows[identifier] = row
            self.tree.insert(
                "",
                "end",
                iid=identifier,
                values=(
                    "☐",
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    if timestamp
                    else "",
                    row.get("client", ""),
                    domain,
                    row.get("type", ""),
                    row.get("status", ""),
                    "No" if domain in unclassified else "Yes",
                ),
            )
        suffix = ""
        if source_count != len(rows):
            suffix = f" · {source_count} source rows"
        self.status.set(f"{len(rows)} shown · {len(unclassified)} unclassified domains{suffix}")

    def _toggle_checkbox(self, event: tk.Event) -> None:
        if self.column_controller.displayed_column_at(event.x) != "selected":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        domain = self.tree.set(item, "domain").strip().lower()
        checked = domain not in self._checked
        if checked:
            self._checked.add(domain)
        else:
            self._checked.discard(domain)
        marker = "☑" if checked else "☐"
        for row_id in self.tree.get_children():
            if self.tree.set(row_id, "domain").strip().lower() == domain:
                self.tree.set(row_id, "selected", marker)

    def _selected_domains(self) -> list[str]:
        if self._checked:
            return sorted(self._checked)
        return sorted(
            {
                self.tree.set(item, "domain").strip().lower()
                for item in self.tree.selection()
                if self.tree.set(item, "domain").strip()
            }
        )

    def _queue_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        self._show_queue_result(queue_domains_for_review(domains, source="manual_history"))

    def _queue_page(self) -> None:
        domains = {
            str(row.get("domain") or "").strip().lower()
            for row in self._rows.values()
            if str(row.get("domain") or "").strip()
        }
        if not domains:
            show_toast(self, "The current page contains no domains.")
            return
        self._show_queue_result(queue_domains_for_review(domains, source="manual_history_page"))

    def _show_queue_result(self, result: Any) -> None:
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

    def _older_page(self) -> None:
        if not self._rows:
            return
        oldest = min(float(row.get("time") or 0) for row in self._rows.values())
        self._newer_stack.append(self._page_until)
        self._page_until = max(0.0, oldest - 0.001)
        self._fetch_page()

    def _newer_page(self) -> None:
        if not self._newer_stack:
            return
        self._page_until = self._newer_stack.pop()
        self._fetch_page()


def _deduplicate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        domain = str(row.get("domain") or "").strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        output.append(row)
    return output
