from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, simpledialog, ttk
from typing import Any

from pihole_manager.gui.group_assignment import choose_groups
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
        type_values: tuple[str, ...],
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
        self.search_text = tk.StringVar()
        self.status = tk.StringVar(value="Not loaded")
        self._rows: dict[str, dict[str, Any]] = {}
        self._request_running = False
        self._build_ui()
        self.after(0, self.refresh)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="Type").pack(side="left")
        type_combo = ttk.Combobox(
            toolbar,
            textvariable=self.rule_type,
            values=self.type_values,
            state="readonly",
            width=10,
        )
        type_combo.pack(side="left", padx=(6, 12))
        type_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh())
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="Add", command=self._add).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Edit comment", command=self._edit_comment).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Groups", command=self._edit_groups).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Toggle enabled", command=self._toggle_enabled).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Delete", command=self._delete).pack(side="left", padx=(6, 0))

        search = ttk.Entry(toolbar, textvariable=self.search_text, width=28)
        search.pack(side="left", padx=(18, 6))
        search.bind("<KeyRelease>", lambda _event: self._populate())
        ttk.Label(toolbar, textvariable=self.status).pack(side="right")

        tree_frame = ttk.Frame(self, padding=(8, 0, 8, 8))
        tree_frame.pack(fill="both", expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("value", "enabled", "groups", "comment"),
            show="headings",
            selectmode="extended",
        )
        self.tree.heading("value", text=self.item_label)
        self.tree.heading("enabled", text="Enabled")
        self.tree.heading("groups", text="Groups")
        self.tree.heading("comment", text="Comment")
        self.tree.column("value", width=420, anchor="w")
        self.tree.column("enabled", width=80, stretch=False, anchor="center")
        self.tree.column("groups", width=120, anchor="w")
        self.tree.column("comment", width=320, anchor="w")
        vertical = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<Double-1>", lambda _event: self._edit_comment())

    def refresh(self) -> None:
        if self._request_running:
            return
        self._request_running = True
        current_type = self.rule_type.get()
        self.status.set(f"Loading {self.type_labels[current_type]} …")
        future = self.executor.submit(self.fetch_function, current_type)
        future.add_done_callback(
            lambda result: self.after(0, self._refresh_done, result, current_type)
        )

    def _refresh_done(self, future: Future, requested_type: str) -> None:
        self._request_running = False
        try:
            rows = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        if requested_type != self.rule_type.get():
            return
        self._rows = {str(row[self.key]): row for row in rows if row.get(self.key)}
        self._populate()

    def _populate(self) -> None:
        query = self.search_text.get().strip().casefold()
        selected = set(self._selected_values())
        self.tree.delete(*self.tree.get_children())
        visible = 0
        for value, row in sorted(self._rows.items(), key=lambda item: item[0].casefold()):
            haystack = f"{value} {row.get('comment', '')}".casefold()
            if query and query not in haystack:
                continue
            visible += 1
            groups = ", ".join(str(item) for item in row.get("groups") or []) or "default"
            self.tree.insert(
                "",
                "end",
                iid=value,
                values=(
                    value,
                    "yes" if row.get("enabled", True) else "no",
                    groups,
                    row.get("comment", ""),
                ),
            )
            if value in selected:
                self.tree.selection_add(value)
        total = len(self._rows)
        self.status.set(f"{visible} shown · {total} total")

    def _selected_values(self) -> list[str]:
        return [str(item) for item in self.tree.selection() if str(item) in self._rows]

    def _single_selection(self) -> tuple[str, dict[str, Any]] | None:
        selected = self._selected_values()
        if len(selected) != 1:
            messagebox.showinfo(
                self.item_label,
                f"Select exactly one {self.item_label.lower()}.",
                parent=self,
            )
            return None
        value = selected[0]
        return value, self._rows[value]

    def _add(self) -> None:
        value = simpledialog.askstring(
            f"Add {self.item_label}",
            self.add_prompt,
            parent=self,
        )
        if not value or not value.strip():
            return
        comment = simpledialog.askstring("Comment", "Optional comment:", parent=self)
        if comment is None:
            return
        current_type = self.rule_type.get()
        self.status.set(f"Adding {self.item_label.lower()} …")
        future = self.executor.submit(
            self.add_function,
            value.strip(),
            current_type,
            comment=comment,
            groups=[],
            enabled=True,
        )
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

    def _edit_comment(self) -> None:
        selection = self._single_selection()
        if selection is None:
            return
        value, row = selection
        comment = simpledialog.askstring(
            "Edit comment",
            f"Comment for {value}:",
            initialvalue=str(row.get("comment") or ""),
            parent=self,
        )
        if comment is None:
            return
        self._submit_update(value, row, comment=comment)

    def _edit_groups(self) -> None:
        selection = self._single_selection()
        if selection is None or self._request_running:
            return
        value, row = selection
        self._request_running = True
        self.status.set("Loading Pi-hole groups …")
        future = self.executor.submit(fetch_groups)
        future.add_done_callback(
            lambda result: self.after(0, self._groups_loaded, result, value, row)
        )

    def _groups_loaded(
        self,
        future: Future,
        value: str,
        row: dict[str, Any],
    ) -> None:
        self._request_running = False
        try:
            groups = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        selected = choose_groups(
            self,
            groups,
            row.get("groups") or [],
            title=f"Groups for {self.item_label}",
        )
        if selected is None:
            self.status.set("Group assignment unchanged.")
            return
        self._submit_update(value, row, groups=selected)

    def _toggle_enabled(self) -> None:
        selected = self._selected_values()
        if not selected:
            messagebox.showinfo(self.item_label, "Select at least one entry.", parent=self)
            return
        rows = [(value, self._rows[value]) for value in selected]
        self.status.set("Updating enabled state …")
        future = self.executor.submit(self._toggle_worker, rows, self.rule_type.get())
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

    def _toggle_worker(self, rows: list[tuple[str, dict[str, Any]]], rule_type: str) -> None:
        for value, row in rows:
            self.update_function(
                value,
                rule_type,
                comment=str(row.get("comment") or ""),
                groups=row.get("groups") or [],
                enabled=not bool(row.get("enabled", True)),
            )

    def _submit_update(
        self,
        value: str,
        row: dict[str, Any],
        *,
        comment: str | None = None,
        groups: list[int] | None = None,
    ) -> None:
        self.status.set(f"Updating {self.item_label.lower()} …")
        future = self.executor.submit(
            self.update_function,
            value,
            self.rule_type.get(),
            comment=str(row.get("comment") or "") if comment is None else comment,
            groups=row.get("groups") or [] if groups is None else groups,
            enabled=bool(row.get("enabled", True)),
        )
        future.add_done_callback(lambda result: self.after(0, self._mutation_done, result))

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
        notebook.add(self.subscription_view, text="Subscribed lists")

    def refresh(self) -> None:
        self.regex_view.refresh()
        self.subscription_view.refresh()
