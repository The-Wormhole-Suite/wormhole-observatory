from __future__ import annotations

from collections.abc import Callable, Mapping
from tkinter import ttk
from typing import Any

SortParser = Callable[[str], Any]


class TreeSortController:
    """Add stable click-to-sort behavior without interfering with heading dragging."""

    def __init__(
        self,
        tree: ttk.Treeview,
        *,
        headings: Mapping[str, str],
        parsers: Mapping[str, SortParser],
        default_column: str,
    ) -> None:
        self.tree = tree
        self.headings = dict(headings)
        self.parsers = dict(parsers)
        self.default_column = default_column
        self.column = default_column
        self.descending = False
        self._pressed_column: str | None = None
        self._pressed_x = 0
        self._pressed_y = 0
        self.tree.bind("<ButtonPress-1>", self._press, add=True)
        self.tree.bind("<ButtonRelease-1>", self._release, add=True)
        self._update_headings()

    def sort_by(self, column: str) -> None:
        if column not in self.parsers:
            return
        if column == self.column:
            self.descending = not self.descending
        else:
            self.column = column
            self.descending = False
        self.apply()

    def reset(self) -> None:
        self.column = self.default_column
        self.descending = False
        self.apply()

    def apply(self) -> None:
        parser = self.parsers[self.column]
        items = list(self.tree.get_children(""))
        items.sort(
            key=lambda item: parser(self.tree.set(item, self.column)),
            reverse=self.descending,
        )
        for position, item in enumerate(items):
            self.tree.move(item, "", position)
        self._update_headings()

    def _press(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) != "heading":
            self._pressed_column = None
            return
        self._pressed_column = self._displayed_column_at(event.x)
        self._pressed_x = int(event.x)
        self._pressed_y = int(event.y)

    def _release(self, event) -> None:
        column = self._pressed_column
        self._pressed_column = None
        if column not in self.parsers:
            return
        if self.tree.identify_region(event.x, event.y) != "heading":
            return
        if self._displayed_column_at(event.x) != column:
            return
        if abs(int(event.x) - self._pressed_x) > 4 or abs(int(event.y) - self._pressed_y) > 4:
            return
        self.sort_by(column)

    def _displayed_column_at(self, x: int) -> str | None:
        identifier = self.tree.identify_column(x)
        if not identifier.startswith("#"):
            return None
        try:
            index = int(identifier[1:]) - 1
        except ValueError:
            return None
        configured = self.tree.cget("displaycolumns")
        displayed = self.tree.tk.splitlist(configured) if configured else ()
        if not displayed or displayed == ("#all",):
            displayed = self.tree.tk.splitlist(self.tree.cget("columns"))
        if 0 <= index < len(displayed):
            return str(displayed[index])
        return None

    def _update_headings(self) -> None:
        for column in self.parsers:
            label = self.headings.get(column, column)
            if column == self.column:
                label += " ▼" if self.descending else " ▲"
            self.tree.heading(column, text=label)
