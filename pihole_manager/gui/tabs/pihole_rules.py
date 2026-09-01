from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any

from pihole_manager.gui.group_assignment import choose_groups
from pihole_manager.gui.tabs.list_audit import ListAuditTab
from pihole_manager.pihole_rules import (
    add_regex_domain,
    add_subscribed_list,
    delete_regex_domain,
    delete_subscribed_list,
    fetch_regex_domains,
    fetch_subscribed_lists,
    update_regex_domain,
    update_subscribed_list,
)
from pihole_manager.pihole_service import fetch_groups
from pihole_manager.rule_conflicts import scan_rule_conflicts

FetchFunction = Callable[[str], list[dict[str, Any]]]
AddFunction = Callable[..., Any]
UpdateFunction = Callable[..., Any]
DeleteFunction = Callable[[str, str], Any]


class _ManagedRuleView(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        executor: ThreadPoolExecutor,
        *,
        key: str,
        type_values: tuple[str, str],
        type_labels: dict[str, str],
        fetch_function: FetchFunction,
        add_function: AddFunction,
        update_function: UpdateFunction,
        delete_function: DeleteFunction,
        item_label: str,
        add_prompt: str,
    ) -> None:
        super().__init__(master)
        self.executor = executor
        self.key = key
        self.type_values = type_values
        self.type_labels = type_labels
        self.fetch_function = fetch_function
        self.add_function = add_function
        self.update_function = update_function
        self.delete_function = delete_function
        self.item_label = item_label
        self.add_prompt = add_prompt
        self.rule_type = tk.StringVar(value=type_values[0])
        self.search = tk.StringVar()
        self.status = tk.StringVar(value="Ready.")
        self._rows: dict[str, dict[str, Any]] = {}
        self._groups: list[dict[str, Any]] = []
        self._loading = False
        self._build_ui()

    def _build_ui(self) -> None:
        controls = ttk.Frame(self, padding=10)
        controls.pack(fill="x")
        ttk.Label(controls, text="Type").pack(side="left")
        type_combo = ttk.Combobox(
            controls,
            textvariable=self.rule_type,
            values=self.type_values,
            state="readonly",
            width=12,
        )
        type_combo.pack(side="left", padx=(6, 12))
        type_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh())
        ttk.Label(controls, text="Search").pack(side="left")
        search_entry = ttk.Entry(controls, textvariable=self.search, width=34)
        search_entry.pack(side="left", padx=(6, 12), fill="x", expand=True)
        self.search.trace_add("write", lambda *_args: self._render())
        ttk.Button(controls, text="Refresh", command=self.refresh).pack(side="left")

        actions = ttk.Frame(self, padding=(10, 0, 10, 8))
        actions.pack(fill="x")
        ttk.Button(actions, text="Add", command=self._add).pack(side="left")
        ttk.Button(actions, text="Edit comment", command=self._edit_comment).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Assign groups", command=self._assign_groups).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Enable", command=lambda: self._set_enabled(True)).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Disable", command=lambda: self._set_enabled(False)).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Delete", command=self._delete).pack(side="right")

        columns = ("value", "enabled", "groups", "comment")
        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        self.tree.heading("value", text=self.item_label)
        self.tree.heading("enabled", text="Enabled")
        self.tree.heading("groups", text="Groups")
        self.tree.heading("comment", text="Comment")
        self.tree.column("value", width=390)
        self.tree.column("enabled", width=80, anchor="center", stretch=False)
        self.tree.column("groups", width=130, stretch=False)
        self.tree.column("comment", width=330)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 4))
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=(0, 4))
        ttk.Label(self, textvariable=self.status, padding=(10, 4, 10, 10)).pack(
            side="bottom", fill="x"
        )

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        current_type = self.rule_type.get()
        self.status.set(f"Loading {self.type_labels[current_type]} …")
        future = self.executor.submit(self.fetch_function, current_type)
        future.add_done_callback(lambda result: self.after(0, self._loaded, result))

    def _loaded(self, future: Future) -> None:
        self._loading = False
        try:
            rows = future.result()
        except Exception as exc:
            self.status.set(f"Could not load entries: {exc}")
            return
        self._rows = {str(row[self.key]): row for row in rows if row.get(self.key)}
        self._render()
        self.status.set(f"Loaded {len(self._rows)} entries.")

    def _render(self) -> None:
        selected = {self.tree.item(item, "values")[0] for item in self.tree.selection()}
        for item in self.tree.get_children():
            self.tree.delete(item)
        query = self.search.get().strip().casefold()
        for value in sorted(self._rows, key=str.casefold):
            row = self._rows[value]
            groups = ", ".join(str(group) for group in row.get("groups") or []) or "—"
            searchable = f"{value} {row.get('comment', '')} {groups}".casefold()
            if query and query not in searchable:
                continue
            item = self.tree.insert(
                "",
                "end",
                values=(
                    value,
                    "Yes" if row.get("enabled", True) else "No",
                    groups,
                    str(row.get("comment") or ""),
                ),
            )
            if value in selected:
                self.tree.selection_add(item)

    def _selected_values(self) -> list[str]:
        return [str(self.tree.item(item, "values")[0]) for item in self.tree.selection()]

    def _add(self) -> None:
        value = simpledialog.askstring(self.item_label, self.add_prompt, parent=self)
        if value is None:
            return
        value = value.strip()
        if not value:
            return
        comment = simpledialog.askstring(
            self.item_label,
            "Optional comment:",
            parent=self,
        )
        self.status.set("Adding …")
        future = self.executor.submit(
            self.add_function,
            value,
            self.rule_type.get(),
            comment=(comment or "").strip(),
        )
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

    def _edit_comment(self) -> None:
        selected = self._selected_values()
        if len(selected) != 1:
            messagebox.showinfo(self.item_label, "Select exactly one entry.", parent=self)
            return
        value = selected[0]
        row = self._rows[value]
        comment = simpledialog.askstring(
            self.item_label,
            "Comment:",
            initialvalue=str(row.get("comment") or ""),
            parent=self,
        )
        if comment is None:
            return
        self._update_rows([value], comment=comment.strip())

    def _assign_groups(self) -> None:
        selected = self._selected_values()
        if not selected:
            messagebox.showinfo(self.item_label, "Select at least one entry.", parent=self)
            return
        self.status.set("Loading groups …")
        future = self.executor.submit(fetch_groups)
        future.add_done_callback(
            lambda result: self.after(0, self._groups_loaded_for_assignment, result, selected)
        )

    def _groups_loaded_for_assignment(self, future: Future, selected: list[str]) -> None:
        try:
            self._groups = future.result()
        except Exception as exc:
            self.status.set(f"Could not load groups: {exc}")
            return
        common: set[int] | None = None
        for value in selected:
            groups = {int(group) for group in self._rows[value].get("groups") or []}
            common = groups if common is None else common & groups
        chosen = choose_groups(
            self,
            self._groups,
            common or set(),
            title=f"Assign {self.item_label.lower()} groups",
            description=(
                f"Apply the selected Pi-hole groups to {len(selected)} selected "
                f"{self.item_label.lower()} entr{'y' if len(selected) == 1 else 'ies'}."
            ),
        )
        if chosen is None:
            self.status.set("Group assignment cancelled.")
            return
        self._update_rows(selected, groups=chosen)

    def _set_enabled(self, enabled: bool) -> None:
        selected = self._selected_values()
        if not selected:
            messagebox.showinfo(self.item_label, "Select at least one entry.", parent=self)
            return
        self._update_rows(selected, enabled=enabled)

    def _update_rows(
        self,
        values: list[str],
        *,
        comment: str | None = None,
        groups: list[int] | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.status.set("Updating …")
        current_type = self.rule_type.get()
        future = self.executor.submit(
            self._update_worker,
            values,
            current_type,
            comment,
            groups,
            enabled,
        )
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

    def _update_worker(
        self,
        values: list[str],
        rule_type: str,
        comment: str | None,
        groups: list[int] | None,
        enabled: bool | None,
    ) -> None:
        for value in values:
            row = self._rows[value]
            self.update_function(
                value,
                rule_type,
                comment=str(row.get("comment") or "") if comment is None else comment,
                groups=list(row.get("groups") or []) if groups is None else groups,
                enabled=bool(row.get("enabled", True)) if enabled is None else enabled,
            )

    def _delete(self) -> None:
        selected = self._selected_values()
        if not selected:
            messagebox.showinfo(self.item_label, "Select at least one entry.", parent=self)
            return
        if not messagebox.askyesno(
            "Delete",
            f"Delete {len(selected)} selected entr{'y' if len(selected) == 1 else 'ies'}?",
            parent=self,
        ):
            return
        current_type = self.rule_type.get()
        self.status.set("Deleting …")
        future = self.executor.submit(self._delete_worker, selected, current_type)
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

    def _delete_worker(self, values: list[str], rule_type: str) -> None:
        for value in values:
            self.delete_function(value, rule_type)

    def _mutation_done(self, future: Future) -> None:
        try:
            future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            messagebox.showerror(self.item_label, str(exc), parent=self)
            return
        self.refresh()


class _ConflictView(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self.status = tk.StringVar(value="Scan active Pi-hole rules for conflicts.")

        controls = ttk.Frame(self, padding=10)
        controls.pack(fill="x")
        ttk.Button(controls, text="Scan conflicts", command=self.refresh).pack(side="left")
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=(10, 0))

        columns = ("severity", "kind", "subject", "details")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("kind", text="Conflict")
        self.tree.heading("subject", text="Domain / rule")
        self.tree.heading("details", text="Details")
        self.tree.column("severity", width=90, stretch=False)
        self.tree.column("kind", width=180, stretch=False)
        self.tree.column("subject", width=260)
        self.tree.column("details", width=520)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))

    def refresh(self) -> None:
        self.status.set("Scanning …")
        future = self.executor.submit(scan_rule_conflicts)
        future.add_done_callback(lambda result: self.after(0, self._loaded, result))

    def _loaded(self, future: Future) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            conflicts = future.result()
        except Exception as exc:
            self.status.set(f"Scan failed: {exc}")
            return
        for conflict in conflicts:
            self.tree.insert(
                "",
                "end",
                values=(
                    conflict.severity,
                    conflict.kind.replace("_", " ").title(),
                    conflict.subject,
                    conflict.details,
                ),
            )
        if conflicts:
            self.status.set(f"Found {len(conflicts)} conflict(s).")
        else:
            self.status.set("No active rule conflicts found.")


class PiHoleRulesTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.regex_view = _ManagedRuleView(
            notebook,
            executor,
            key="domain",
            type_values=("allow", "deny"),
            type_labels={"allow": "allow regex rules", "deny": "deny regex rules"},
            fetch_function=fetch_regex_domains,
            add_function=add_regex_domain,
            update_function=update_regex_domain,
            delete_function=delete_regex_domain,
            item_label="Regex rule",
            add_prompt="Regular expression to add:",
        )
        self.subscription_view = _ManagedRuleView(
            notebook,
            executor,
            key="address",
            type_values=("allow", "block"),
            type_labels={"allow": "allow subscriptions", "block": "block subscriptions"},
            fetch_function=fetch_subscribed_lists,
            add_function=add_subscribed_list,
            update_function=update_subscribed_list,
            delete_function=delete_subscribed_list,
            item_label="Subscribed list",
            add_prompt="List URL/address to add:",
        )
        notebook.add(self.regex_view, text="Regex rules")
        self.conflict_view = _ConflictView(notebook, executor)
        notebook.add(self.subscription_view, text="Subscribed lists")
        notebook.add(self.conflict_view, text="Conflicts")
        self.list_audit_view = ListAuditTab(notebook, executor)
        notebook.add(self.list_audit_view, text="List audit")

    def refresh(self) -> None:
        self.regex_view.refresh()
        self.subscription_view.refresh()
        self.list_audit_view.refresh_status()
