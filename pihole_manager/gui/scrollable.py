from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class ScrollableFrame(ttk.Frame):
    """A vertically scrollable container for settings pages."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._wheel_bound: set[str] = set()

        background = self._frame_background()
        self.canvas = tk.Canvas(
            self,
            borderwidth=0,
            highlightthickness=0,
            background=background,
        )
        self.scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview,
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.content = ttk.Frame(self.canvas)
        self._window = self.canvas.create_window(
            (0, 0),
            window=self.content,
            anchor="nw",
        )
        self.content.bind("<Configure>", self._content_changed)
        self.canvas.bind("<Configure>", self._canvas_changed)
        self.after_idle(self._bind_mousewheel_widgets)

    def refresh_theme(self) -> None:
        self.canvas.configure(background=self._frame_background())

    def _frame_background(self) -> str:
        return ttk.Style(self).lookup("TFrame", "background") or "#f0f0f0"

    def _content_changed(self, _event: tk.Event) -> None:
        self._resize_window()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._update_scrollbar_visibility()
        self._bind_mousewheel_widgets()

    def _canvas_changed(self, _event: tk.Event) -> None:
        self._resize_window()
        self._update_scrollbar_visibility()

    def _resize_window(self) -> None:
        width = max(1, self.canvas.winfo_width())
        height = max(self.canvas.winfo_height(), self.content.winfo_reqheight())
        self.canvas.itemconfigure(self._window, width=width, height=height)

    def _update_scrollbar_visibility(self) -> None:
        required = self.content.winfo_reqheight() > self.canvas.winfo_height()
        if required:
            self.scrollbar.grid()
        else:
            self.scrollbar.grid_remove()
            self.canvas.yview_moveto(0.0)

    def _bind_mousewheel_widgets(self) -> None:
        pending: list[tk.Misc] = [self.canvas, self.content]
        while pending:
            widget = pending.pop()
            key = str(widget)
            if key not in self._wheel_bound:
                widget.bind("<MouseWheel>", self._on_mousewheel, add="+")
                widget.bind("<Button-4>", self._on_mousewheel, add="+")
                widget.bind("<Button-5>", self._on_mousewheel, add="+")
                self._wheel_bound.add(key)
            pending.extend(widget.winfo_children())

    def _on_mousewheel(self, event: tk.Event) -> str:
        if getattr(event, "num", None) == 4:
            units = -1
        elif getattr(event, "num", None) == 5:
            units = 1
        else:
            delta = int(getattr(event, "delta", 0))
            if delta == 0:
                return "break"
            units = -max(1, abs(delta) // 120) if delta > 0 else max(1, abs(delta) // 120)
        self.canvas.yview_scroll(units, "units")
        return "break"
