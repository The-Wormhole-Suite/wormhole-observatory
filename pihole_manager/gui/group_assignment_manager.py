from __future__ import annotations

import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk
from typing import Any

from pihole_manager.pihole_service import (
    fetch_exact_domains,
    fetch_groups,
    fetch_subscribed_lists,
    update_exact_domain_groups,
    update_subscribed_list_groups,
)

_ITEM_TYPES = {
    "Whitelist domain": ("domain", "allow"),
    "Blacklist domain": ("domain", "deny"),
    "Allow subscribed list": ("list", "allow"),
    "Block subscribed list": ("list", "block"),
}


class GroupAssignmentManager(tk.Toplevel):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.title("Pi-hole group assignments")
        self.transient(master.winfo_toplevel())
        self.geometry("760x520")
        self.minsize(620, 420)
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="group-assignment")
        self.item_type = tk.StringVar(value="Whitelist domain")
        self.item_value = tk.StringVar()
        self.status = tk.StringVar(value="Loading Pi-hole groups …")
        self._groups: list[dict[str, Any]] = []
        self._rows: dict[str, dict[str, Any]] = {}
        self._loading = False
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(0, self.refresh)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

        ttk.Label(
            frame,
            text=(
                "Assign existing exact domains or subscribed lists to Pi-hole groups. "
                "Changing groups preserves the item's comment and enabled state."
            ),
            wraplength=720,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        ttk.Label(frame, text="Item type").grid(row=1, column=0, sticky="w")
        type_combo = ttk.Combobox(
            frame,
            textvariable=self.item_type,
            values=tuple(_ITEM_TYPES),
            state="readonly",
            width=24,
        )
        type_combo.grid(row=1, column=1, sticky="w", padx=(10, 0))
        type_combo.bind("<<ComboboxSelected>>", lambda _event: self._load_items())
        ttk.Button(frame, text="Refresh", command=self.refresh).grid(
            row=1, column=2, sticky="e", padx=(10, 0)
        )

        ttk.Label(frame, text="Item").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.item_combo = ttk.Combobox(frame, textvariable=self.item_value, state="readonly")
        self.item_combo.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(10, 0))
        self.item_combo.bind("<<ComboboxSelected>>", lambda _event: self._sync_selection())

        groups_frame = ttk.LabelFrame(frame, text="Groups", padding=8)
        groups_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(12, 0))
        groups_frame.rowconfigure(0, weight=1)
        groups_frame.columnconfigure(0, weight=1)
        self.group_list = tk.Listbox(groups_frame, selectmode=tk.MULTIPLE, exportselection=False)
        scrollbar = ttk.Scrollbar(groups_frame, orient="vertical", command=self.group_list.yview)
        self.group_list.configure(yscrollcommand=scrollbar.set)
        self.group_list.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        controls = ttk.Frame(groups_frame)
        controls.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(controls, text="All", command=lambda: self.group_list.selection_set(0, "end")).pack(
            side="left"
        )
        ttk.Button(controls, text="None", command=lambda: self.group_list.selection_clear(0, "end")).pack(
            side="left", padx=(6, 0)
        )
        self.apply_button = ttk.Button(controls, text="Apply groups", command=self._apply)
        self.apply_button.pack(side="right")

        ttk.Label(frame, textvariable=self.status, wraplength=720).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(10, 0)
        )

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.apply_button.state(["disabled"])
        self.status.set("Loading Pi-hole groups …")
        future = self.executor.submit(fetch_groups)
        future.add_done_callback(lambda item: self.after(0, self._groups_loaded, item))

    def _groups_loaded(self, future: Future) -> None:
        try:
            self._groups = future.result()
        except Exception as exc:
            self._loading = False
            self.status.set(f"Could not load groups: {exc}")
            return
        self.group_list.delete(0, "end")
        for group in self._groups:
            label = str(group["name"])
            if not group.get("enabled", True):
                label += " (disabled)"
            self.group_list.insert("end", f"{label}  [#{group['id']}]")
        self._loading = False
        self._load_items()

    def _load_items(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.apply_button.state(["disabled"])
        self.item_value.set("")
        self.item_combo.configure(values=())
        kind, value = _ITEM_TYPES[self.item_type.get()]
        self.status.set(f"Loading {self.item_type.get().lower()} entries …")
        if kind == "domain":
            future = self.executor.submit(fetch_exact_domains, value)
        else:
            future = self.executor.submit(fetch_subscribed_lists, value)
        future.add_done_callback(lambda item: self.after(0, self._items_loaded, item, kind))

    def _items_loaded(self, future: Future, kind: str) -> None:
        self._loading = False
        try:
            rows = future.result()
        except Exception as exc:
            self.status.set(f"Could not load items: {exc}")
            return
        key = "domain" if kind == "domain" else "address"
        self._rows = {str(row[key]): row for row in rows if row.get(key)}
        values = sorted(self._rows, key=str.casefold)
        self.item_combo.configure(values=values)
        if values:
            self.item_value.set(values[0])
            self._sync_selection()
            self.apply_button.state(["!disabled"])
            self.status.set(f"Loaded {len(values)} item(s) and {len(self._groups)} group(s).")
        else:
            self.group_list.selection_clear(0, "end")
            self.status.set("No matching Pi-hole items were returned.")

    def _sync_selection(self) -> None:
        row = self._rows.get(self.item_value.get())
        self.group_list.selection_clear(0, "end")
        if not row:
            return
        selected = set()
        for value in row.get("groups") or []:
            try:
                selected.add(int(value))
            except (TypeError, ValueError):
                continue
        for index, group in enumerate(self._groups):
            if int(group["id"]) in selected:
                self.group_list.selection_set(index)

    def _apply(self) -> None:
        item = self.item_value.get()
        row = self._rows.get(item)
        if not row:
            return
        group_ids = [int(self._groups[index]["id"]) for index in self.group_list.curselection()]
        kind, value = _ITEM_TYPES[self.item_type.get()]
        self.apply_button.state(["disabled"])
        self.status.set("Updating group assignment …")
        if kind == "domain":
            future = self.executor.submit(
                update_exact_domain_groups,
                item,
                value,
                group_ids,
                comment=str(row.get("comment") or ""),
                enabled=bool(row.get("enabled", True)),
            )
        else:
            future = self.executor.submit(
                update_subscribed_list_groups,
                item,
                value,
                group_ids,
                comment=str(row.get("comment") or ""),
                enabled=bool(row.get("enabled", True)),
            )
        future.add_done_callback(lambda result: self.after(0, self._apply_done, result))

    def _apply_done(self, future: Future) -> None:
        try:
            future.result()
        except Exception as exc:
            self.apply_button.state(["!disabled"])
            self.status.set(f"Could not update groups: {exc}")
            messagebox.showerror("Pi-hole groups", str(exc), parent=self)
            return
        self.status.set("Group assignment updated.")
        self._load_items()

    def _close(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def show_group_assignment_manager(parent: tk.Misc) -> None:
    GroupAssignmentManager(parent)
