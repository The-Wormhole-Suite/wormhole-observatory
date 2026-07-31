from __future__ import annotations

import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any

from pihole_manager.config import load_options, save_options
from pihole_manager.database import (
    filter_unclassified_domains,
    list_domain_locks,
    queue_domains_for_review,
    remove_domain_lock,
    review_get,
    set_domain_lock,
)
from pihole_manager.gui.column_visibility import ColumnVisibilityController
from pihole_manager.gui.domain_details import show_domain_details
from pihole_manager.gui.feedback import show_toast
from pihole_manager.pihole_service import (
    add_exact_domain,
    delete_exact_domain,
    fetch_exact_domains,
    get_client,
)

_COLUMNS = ("selected", "locked", "domain", "enabled", "comment", "tags", "details")
_HEADINGS = {
    "selected": "✓",
    "locked": "Lock",
    "domain": "Domain",
    "enabled": "Enabled",
    "comment": "Pi-hole comment",
    "tags": "Tags",
    "details": "Classification summary",
}


class ListsTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self.list_type = tk.StringVar(value="deny")
        self.search_text = tk.StringVar()
        self.status = tk.StringVar(value="Idle")
        self.only_unreviewed = tk.BooleanVar(value=load_options().ui.lists_queue_only_unreviewed)
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._request_running = False
        self._build_ui()
        self.after(200, self.refresh)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Radiobutton(
            toolbar,
            text="Whitelist",
            value="allow",
            variable=self.list_type,
            command=self._change_type,
        ).pack(side="left")
        ttk.Radiobutton(
            toolbar,
            text="Blacklist",
            value="deny",
            variable=self.list_type,
            command=self._change_type,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left", padx=(12, 0))
        ttk.Button(toolbar, text="Add", command=self._add_domain).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Delete", command=self._delete_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Lock", command=self._lock_selected).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(toolbar, text="Unlock", command=self._unlock_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Details", command=self._show_selected_details).pack(
            side="left", padx=(12, 0)
        )
        self.columns_button = ttk.Menubutton(toolbar, text="Columns")
        self.columns_button.pack(side="left", padx=(12, 0))

        ttk.Entry(toolbar, textvariable=self.search_text, width=28).pack(side="left", padx=(20, 6))
        ttk.Button(toolbar, text="Search both lists", command=self._search).pack(side="left")
        ttk.Label(toolbar, textvariable=self.status).pack(side="right")

        queue_bar = ttk.Frame(self, padding=(8, 0, 8, 6))
        queue_bar.pack(fill="x")
        ttk.Button(
            queue_bar,
            text="Queue selected for review",
            command=self._queue_selected_for_review,
        ).pack(side="left")
        self.queue_all_button = ttk.Button(
            queue_bar,
            text="Queue entire blacklist for review",
            command=self._queue_entire_list_for_review,
        )
        self.queue_all_button.pack(side="left", padx=(6, 0))
        ttk.Checkbutton(
            queue_bar,
            text="Only domains not reviewed yet",
            variable=self.only_unreviewed,
            command=self._save_queue_preference,
        ).pack(side="left", padx=(14, 0))

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
        self.tree.column("selected", width=38, stretch=False, anchor="center")
        self.tree.column("locked", width=58, stretch=False, anchor="center")
        self.tree.column("domain", width=290, anchor="w")
        self.tree.column("enabled", width=70, anchor="center")
        self.tree.column("comment", width=260, anchor="w")
        self.tree.column("tags", width=230, anchor="w")
        self.tree.column("details", width=430, anchor="w")
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.tree.bind("<Double-1>", self._double_click)
        self.column_controller = ColumnVisibilityController(
            self.columns_button,
            self.tree,
            table_key="lists",
            columns=_COLUMNS,
            headings=_HEADINGS,
        )

    def reload_preferences(self) -> None:
        self.column_controller.reload()

    def _change_type(self) -> None:
        self._checked.clear()
        self.queue_all_button.configure(text=f"Queue entire {self._list_label()} for review")
        self.refresh()

    def refresh(self) -> None:
        if self._request_running:
            return
        self._request_running = True
        selected_type = self.list_type.get()
        self.status.set(f"Loading {self._list_label(selected_type)} …")
        future = self.executor.submit(fetch_exact_domains, selected_type)
        future.add_done_callback(
            lambda item: self.after(0, self._load_done, item, selected_type, None)
        )

    def _load_done(
        self,
        future: Future,
        selected_type: str,
        highlighted: list[str] | None,
    ) -> None:
        self._request_running = False
        try:
            rows = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        if selected_type != self.list_type.get():
            return
        self._populate(rows, highlighted or [])

    def _populate(self, rows: list[dict[str, Any]], highlighted: list[str]) -> None:
        reviews = {str(row["domain"]): row for row in review_get(limit=10_000)}
        locks = {str(row["domain"]): row for row in list_domain_locks()}
        self._rows = {str(row["domain"]): row for row in rows}
        self._checked.intersection_update(self._rows)
        self.tree.delete(*self.tree.get_children())
        first_match: str | None = None
        highlighted_set = set(highlighted)
        for row in sorted(rows, key=lambda item: str(item.get("domain") or "")):
            domain = str(row.get("domain") or "")
            review = reviews.get(domain, {})
            lock = locks.get(domain)
            tags = ",".join(review.get("tags") or review.get("categories") or [])
            short = str(review.get("short") or "")
            service = str(review.get("service") or "")
            summary = " · ".join(value for value in (service, short) if value)
            checked = domain in self._checked or domain in highlighted_set
            if checked:
                self._checked.add(domain)
            item = self.tree.insert(
                "",
                "end",
                iid=domain,
                values=(
                    "☑" if checked else "☐",
                    "🔒" if lock and lock["list_type"] == self.list_type.get() else "",
                    domain,
                    "yes" if row.get("enabled", True) else "no",
                    row.get("comment", ""),
                    tags,
                    summary,
                ),
            )
            if domain in highlighted_set and first_match is None:
                first_match = item
        if first_match:
            self.tree.selection_set(first_match)
            self.tree.focus(first_match)
            self.tree.see(first_match)
        self.status.set(f"{len(rows)} {self._list_label()} entries")

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
        visible_checked = self._checked.intersection(self._rows)
        if visible_checked:
            return sorted(visible_checked)
        return sorted(
            {
                self.tree.set(item, "domain")
                for item in self.tree.selection()
                if self.tree.set(item, "domain")
            }
        )

    def _list_label(self, list_type: str | None = None) -> str:
        selected = list_type or self.list_type.get()
        return "whitelist" if selected == "allow" else "blacklist"

    def _queue_selected_for_review(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        self._queue_domains(domains)

    def _queue_entire_list_for_review(self) -> None:
        self._queue_domains(sorted(self._rows))

    def _queue_domains(self, domains: list[str]) -> None:
        if not domains:
            show_toast(self, f"The {self._list_label()} is empty.")
            return
        self.status.set("Queueing domains for review …")
        future = self.executor.submit(
            self._queue_domains_worker,
            domains,
            self.only_unreviewed.get(),
            f"manual_{self._list_label()}",
        )
        future.add_done_callback(lambda item: self.after(0, self._queue_done, item))

    @staticmethod
    def _queue_domains_worker(
        domains: list[str],
        only_unreviewed: bool,
        source: str,
    ) -> tuple[int, Any]:
        requested = len(domains)
        selected = filter_unclassified_domains(domains) if only_unreviewed else domains
        skipped_reviewed = requested - len(selected)
        result = queue_domains_for_review(selected, source=source)
        return skipped_reviewed, result

    def _queue_done(self, future: Future) -> None:
        try:
            skipped_reviewed, result = future.result()
        except Exception as exc:
            self.status.set(f"Queue error: {exc}")
            show_toast(self, f"Could not queue domains: {exc}")
            return
        parts: list[str] = []
        if result.queued:
            parts.append(f"{result.queued} queued")
        if result.requeued:
            parts.append(f"{result.requeued} requeued")
        if result.already_pending:
            parts.append(f"{result.already_pending} already pending")
        if skipped_reviewed:
            parts.append(f"{skipped_reviewed} already reviewed")
        if result.skipped_locked:
            parts.append(f"{result.skipped_locked} protected")
        if result.skipped_filtered:
            parts.append(f"{result.skipped_filtered} filtered")
        message = ", ".join(parts) or "No domains queued."
        self.status.set(message)
        show_toast(self, message)

    def _save_queue_preference(self) -> None:
        options = load_options()
        options.ui.lists_queue_only_unreviewed = self.only_unreviewed.get()
        save_options(options)

    def _add_domain(self) -> None:
        domain = simpledialog.askstring(
            "Add domain", f"Domain to add to the {self._list_label()}:", parent=self
        )
        if not domain:
            return
        comment = simpledialog.askstring("Comment", "Optional comment:", parent=self) or ""
        selected_type = self.list_type.get()
        self.status.set("Adding domain …")
        future = self.executor.submit(add_exact_domain, domain.strip(), selected_type, comment)
        future.add_done_callback(lambda item: self.after(0, self._mutation_done, item))

    def _delete_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Lists", "Select or check at least one domain.")
            return
        if not messagebox.askyesno(
            "Delete",
            f"Delete {len(domains)} domain(s) from the {self._list_label()}? "
            "Protected entries will be rejected.",
        ):
            return
        selected_type = self.list_type.get()
        self.status.set("Deleting …")
        future = self.executor.submit(self._delete_domains, domains, selected_type)
        future.add_done_callback(lambda item: self.after(0, self._delete_done, item))

    @staticmethod
    def _delete_domains(domains: list[str], selected_type: str) -> list[str]:
        errors: list[str] = []
        for domain in domains:
            try:
                delete_exact_domain(domain, selected_type)
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return errors

    def _delete_done(self, future: Future) -> None:
        try:
            errors = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        self._checked.clear()
        if errors:
            messagebox.showwarning("Lists", "Some deletions failed:\n" + "\n".join(errors[:10]))
        self.refresh()

    def _lock_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Lists", "Select or check at least one domain.")
            return
        reason = simpledialog.askstring(
            "Protect entries",
            "Optional reason for protecting these entries:",
            parent=self,
        )
        if reason is None:
            return
        for domain in domains:
            set_domain_lock(domain, self.list_type.get(), reason)
        self.refresh()

    def _unlock_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Lists", "Select or check at least one domain.")
            return
        for domain in domains:
            remove_domain_lock(domain)
        self.refresh()

    def _mutation_done(self, future: Future) -> None:
        try:
            future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            messagebox.showerror("Lists", str(exc))
            return
        self.refresh()

    def _double_click(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if self.column_controller.displayed_column_at(event.x) == "comment":
            self._edit_comment_for(item)
        else:
            self._show_details(item)

    def _edit_comment_for(self, domain: str) -> None:
        row = self._rows.get(domain)
        if not row:
            return
        current = str(row.get("comment") or "")
        comment = simpledialog.askstring(
            "Edit comment", f"Comment for {domain}:", initialvalue=current, parent=self
        )
        if comment is None:
            return
        selected_type = self.list_type.get()
        future = self.executor.submit(
            get_client().domain_management.update_domain,
            domain,
            selected_type,
            "exact",
            comment=comment,
            groups=row.get("groups") or [],
            enabled=bool(row.get("enabled", True)),
        )
        future.add_done_callback(lambda item: self.after(0, self._mutation_done, item))

    def _show_selected_details(self) -> None:
        domains = self._selected_domains()
        if domains:
            self._show_details(domains[0])

    def _show_details(self, domain: str) -> None:
        show_domain_details(self, domain)

    def _search(self) -> None:
        query = self.search_text.get().strip().lower()
        if not query or self._request_running:
            return
        self._request_running = True
        self.status.set("Searching whitelist and blacklist …")
        future = self.executor.submit(self._search_both, query)
        future.add_done_callback(lambda item: self.after(0, self._search_done, item, query))

    @staticmethod
    def _search_both(query: str) -> tuple[str | None, list[dict[str, Any]], list[str]]:
        for selected_type in ("allow", "deny"):
            rows = fetch_exact_domains(selected_type)
            matches = [
                str(row.get("domain") or "")
                for row in rows
                if query in str(row.get("domain") or "").lower()
            ]
            if matches:
                return selected_type, rows, matches
        return None, [], []

    def _search_done(self, future: Future, query: str) -> None:
        self._request_running = False
        try:
            selected_type, rows, matches = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        if selected_type is None:
            self.status.set(f"No exact-list match for {query}")
            messagebox.showinfo("Lists", "No matching exact whitelist/blacklist entry was found.")
            return
        if selected_type != self.list_type.get():
            self._checked.clear()
        self.list_type.set(selected_type)
        self._populate(rows, matches)
        self.status.set(f"Found {len(matches)} match(es) in {self._list_label(selected_type)}")
