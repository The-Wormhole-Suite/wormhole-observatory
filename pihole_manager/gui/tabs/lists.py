from __future__ import annotations

import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any

from pihole_manager.database import review_get
from pihole_manager.pihole_service import (
    add_exact_domain,
    delete_exact_domain,
    fetch_exact_domains,
    get_client,
)

_COLUMNS = ("selected", "domain", "enabled", "comment", "details")


class ListsTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self.list_type = tk.StringVar(value="deny")
        self.search_text = tk.StringVar()
        self.status = tk.StringVar(value="Idle")
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._request_running = False
        self._loaded_type = ""
        self._build_ui()
        self.after(200, self.refresh)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Radiobutton(
            toolbar,
            text="Allow",
            value="allow",
            variable=self.list_type,
            command=self._change_type,
        ).pack(side="left")
        ttk.Radiobutton(
            toolbar,
            text="Deny",
            value="deny",
            variable=self.list_type,
            command=self._change_type,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left", padx=(12, 0))
        ttk.Button(toolbar, text="Add", command=self._add_domain).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Delete", command=self._delete_selected).pack(
            side="left", padx=(6, 0)
        )

        ttk.Entry(toolbar, textvariable=self.search_text, width=34).pack(
            side="left", padx=(20, 6)
        )
        ttk.Button(toolbar, text="Search both lists", command=self._search).pack(side="left")
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
            "enabled": "Enabled",
            "comment": "Comment",
            "details": "LLM details",
        }
        for column, heading in headings.items():
            self.tree.heading(column, text=heading)
        self.tree.column("selected", width=38, stretch=False, anchor="center")
        self.tree.column("domain", width=310, anchor="w")
        self.tree.column("enabled", width=80, anchor="center")
        self.tree.column("comment", width=300, anchor="w")
        self.tree.column("details", width=480, anchor="w")
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.tree.bind("<Double-1>", self._edit_comment)

    def _change_type(self) -> None:
        self._checked.clear()
        self.refresh()

    def refresh(self) -> None:
        if self._request_running:
            return
        self._request_running = True
        selected_type = self.list_type.get()
        self.status.set(f"Loading {selected_type} list …")
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
        self._loaded_type = selected_type

    def _populate(self, rows: list[dict[str, Any]], highlighted: list[str]) -> None:
        reviews = {str(row["domain"]): row for row in review_get(limit=5_000)}
        self._rows = {str(row["domain"]): row for row in rows}
        self._checked.intersection_update(self._rows)
        self.tree.delete(*self.tree.get_children())
        first_match: str | None = None
        highlighted_set = set(highlighted)
        for row in sorted(rows, key=lambda item: str(item.get("domain") or "")):
            domain = str(row.get("domain") or "")
            review = reviews.get(domain, {})
            short = str(review.get("short") or "")
            details = str(review.get("details") or "")
            category = ",".join(review.get("categories") or [])
            summary = " · ".join(value for value in (category, short, details) if value)
            checked = domain in self._checked or domain in highlighted_set
            if checked:
                self._checked.add(domain)
            item = self.tree.insert(
                "",
                "end",
                iid=domain,
                values=(
                    "☑" if checked else "☐",
                    domain,
                    "yes" if row.get("enabled", True) else "no",
                    row.get("comment", ""),
                    summary,
                ),
            )
            if domain in highlighted_set and first_match is None:
                first_match = item
        if first_match:
            self.tree.selection_set(first_match)
            self.tree.focus(first_match)
            self.tree.see(first_match)
        self.status.set(f"{len(rows)} {self.list_type.get()} entries")

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

    def _add_domain(self) -> None:
        domain = simpledialog.askstring(
            "Add domain", f"Domain to add to the {self.list_type.get()} list:", parent=self
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
            "Delete", f"Delete {len(domains)} domain(s) from the {self.list_type.get()} list?"
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

    def _mutation_done(self, future: Future) -> None:
        try:
            future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            messagebox.showerror("Lists", str(exc))
            return
        self.refresh()

    def _edit_comment(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if not item:
            return
        domain = self.tree.set(item, "domain")
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

    def _search(self) -> None:
        query = self.search_text.get().strip().lower()
        if not query:
            return
        if self._request_running:
            return
        self._request_running = True
        self.status.set("Searching allow and deny lists …")
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
            messagebox.showinfo("Lists", "No matching exact allow/deny entry was found.")
            return
        if selected_type != self.list_type.get():
            self._checked.clear()
        self.list_type.set(selected_type)
        self._populate(rows, matches)
        self._loaded_type = selected_type
        self.status.set(f"Found {len(matches)} match(es) in {selected_type}")
