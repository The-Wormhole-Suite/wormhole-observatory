from __future__ import annotations

import tkinter as tk
from collections.abc import Iterable, Mapping
from tkinter import ttk

from pihole_manager.config import load_options, save_options


class ColumnVisibilityController:
    def __init__(
        self,
        button: ttk.Menubutton,
        tree: ttk.Treeview,
        *,
        table_key: str,
        columns: Iterable[str],
        headings: Mapping[str, str],
        mandatory: Iterable[str] = ("domain",),
    ) -> None:
        self.button = button
        self.tree = tree
        self.table_key = table_key
        self.columns = tuple(columns)
        self.headings = dict(headings)
        self.mandatory = frozenset(mandatory)
        self.variables: dict[str, tk.BooleanVar] = {}
        self.order = list(self.columns)
        self._layout_after_id: str | None = None
        self._drag_column: str | None = None

        self.menu = tk.Menu(button, tearoff=False)
        self.button.configure(menu=self.menu)
        for column in self.columns:
            variable = tk.BooleanVar(value=True)
            self.variables[column] = variable
            self.menu.add_checkbutton(
                label=self.headings.get(column, column),
                variable=variable,
                command=self._apply_and_save,
            )
            if column in self.mandatory:
                self.menu.entryconfigure("end", state="disabled")

        self.menu.add_separator()
        self.menu.add_command(label="Reorder columns…", command=self._show_reorder_dialog)
        self.menu.add_command(label="Show all", command=self.show_all)
        self.menu.add_command(label="Reset columns", command=self.reset)

        self.tree.bind("<ButtonPress-1>", self._heading_drag_start, add=True)
        self.tree.bind("<ButtonRelease-1>", self._heading_drag_end, add=True)
        self.tree.bind("<ButtonRelease-1>", self._schedule_layout_save, add=True)
        self.tree.bind("<Configure>", self._schedule_layout_save, add=True)
        self.reload()

    def reload(self) -> None:
        options = load_options().ui
        defaults = type(options)()
        visible = options.table_visible_columns.get(
            self.table_key,
            defaults.table_visible_columns.get(self.table_key, list(self.columns)),
        )
        configured_order = options.table_column_order.get(
            self.table_key,
            defaults.table_column_order.get(self.table_key, list(self.columns)),
        )
        self.order = self._normalized_order(configured_order)
        visible_set = set(visible) | self.mandatory
        for column, variable in self.variables.items():
            variable.set(column in visible_set)

        widths = options.table_column_widths.get(
            self.table_key,
            defaults.table_column_widths.get(self.table_key, {}),
        )
        for column in self.columns:
            width = max(20, int(widths.get(column, self.tree.column(column, option="width"))))
            self.tree.column(column, width=width)
        self._apply()

    def show_all(self) -> None:
        for variable in self.variables.values():
            variable.set(True)
        self._apply_and_save()

    def reset(self) -> None:
        options = load_options()
        defaults = type(options.ui)()
        options.ui.table_visible_columns[self.table_key] = list(
            defaults.table_visible_columns.get(self.table_key, self.columns)
        )
        options.ui.table_column_order[self.table_key] = list(
            defaults.table_column_order.get(self.table_key, self.columns)
        )
        options.ui.table_column_widths[self.table_key] = dict(
            defaults.table_column_widths.get(self.table_key, {})
        )
        save_options(options)
        self.reload()

    def displayed_column_at(self, x: int) -> str | None:
        identifier = self.tree.identify_column(x)
        if not identifier.startswith("#"):
            return None
        try:
            index = int(identifier[1:]) - 1
        except ValueError:
            return None
        displayed = self.visible_columns()
        if 0 <= index < len(displayed):
            return displayed[index]
        return None

    def visible_columns(self) -> list[str]:
        configured = self.tree.cget("displaycolumns")
        values = self.tree.tk.splitlist(configured) if isinstance(configured, str) else configured
        if not values or values == ("#all",):
            return list(self.columns)
        return [str(value) for value in values]

    def _normalized_order(self, values: Iterable[str]) -> list[str]:
        configured = [str(value) for value in values if str(value) in self.columns]
        return list(dict.fromkeys([*configured, *self.columns]))

    def _apply(self) -> None:
        visible = [
            column
            for column in self.order
            if self.variables[column].get() or column in self.mandatory
        ]
        self.tree.configure(displaycolumns=visible)

    def _apply_and_save(self) -> None:
        self._apply()
        self._save_layout()

    def _heading_drag_start(self, event: tk.Event) -> None:
        if self.tree.identify_region(event.x, event.y) != "heading":
            self._drag_column = None
            return
        self._drag_column = self.displayed_column_at(event.x)

    def _heading_drag_end(self, event: tk.Event) -> None:
        source = self._drag_column
        self._drag_column = None
        if not source or self.tree.identify_region(event.x, event.y) != "heading":
            return
        target = self.displayed_column_at(event.x)
        if not target or target == source:
            return
        order = list(self.order)
        order.remove(source)
        target_index = order.index(target)
        order.insert(target_index, source)
        self.order = order
        self._apply_and_save()

    def _show_reorder_dialog(self) -> None:
        dialog = tk.Toplevel(self.tree)
        dialog.title("Reorder columns")
        dialog.transient(self.tree.winfo_toplevel())
        dialog.grab_set()
        dialog.geometry("360x430")

        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text="Drag table headings or move columns here.",
        ).pack(anchor="w", pady=(0, 8))
        listbox = tk.Listbox(frame, exportselection=False)
        listbox.pack(fill="both", expand=True)
        for column in self.order:
            listbox.insert("end", self.headings.get(column, column))

        def move(delta: int) -> None:
            selection = listbox.curselection()
            if not selection:
                return
            index = int(selection[0])
            target = index + delta
            if target < 0 or target >= len(self.order):
                return
            self.order[index], self.order[target] = self.order[target], self.order[index]
            value = listbox.get(index)
            listbox.delete(index)
            listbox.insert(target, value)
            listbox.selection_set(target)
            listbox.activate(target)

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Move up", command=lambda: move(-1)).pack(side="left")
        ttk.Button(buttons, text="Move down", command=lambda: move(1)).pack(
            side="left", padx=(6, 0)
        )

        def save() -> None:
            self._apply_and_save()
            dialog.destroy()

        ttk.Button(buttons, text="Apply", command=save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0, 6))

    def _schedule_layout_save(self, _event: tk.Event | None = None) -> None:
        if self._layout_after_id:
            self.tree.after_cancel(self._layout_after_id)
        self._layout_after_id = self.tree.after(600, self._save_layout)

    def _save_layout(self) -> None:
        self._layout_after_id = None
        options = load_options()
        options.ui.table_column_widths[self.table_key] = {
            column: int(self.tree.column(column, option="width")) for column in self.columns
        }
        options.ui.table_visible_columns[self.table_key] = self.visible_columns()
        options.ui.table_column_order[self.table_key] = list(self.order)
        if self.table_key == "queries":
            options.ui.queries_colwidths = dict(options.ui.table_column_widths[self.table_key])
        save_options(options)
