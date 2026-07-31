from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any


class _HoverTooltip:
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.window: tk.Toplevel | None = None
        self._after_id: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<Button-1>", self._toggle, add="+")

    def _schedule(self, _event: tk.Event | None = None) -> None:
        self.cancel()
        self._after_id = self.widget.after(350, self.show)

    def cancel(self) -> None:
        if self._after_id is not None:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def show(self) -> None:
        self.cancel()
        if self.window is not None or not self.widget.winfo_viewable():
            return
        x = self.widget.winfo_rootx() + self.widget.winfo_width() + 6
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 2
        window = tk.Toplevel(self.widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(
            window,
            text=self.text,
            justify="left",
            wraplength=460,
            padding=(10, 7),
            relief="solid",
            borderwidth=1,
        )
        label.pack()
        self.window = window

    def hide(self, _event: tk.Event | None = None) -> None:
        self.cancel()
        if self.window is not None:
            self.window.destroy()
            self.window = None

    def _toggle(self, _event: tk.Event | None = None) -> None:
        if self.window is None:
            self.show()
        else:
            self.hide()


class TooltipSupport:
    def _init_tooltips(self) -> None:
        self._tooltip_icons: list[ttk.Label] = []
        self._tooltip_layouts: dict[ttk.Label, tuple[str, dict[str, Any]]] = {}
        self._tooltips_enabled = True

    def _info_button(
        self,
        parent: tk.Misc,
        title: str,
        text: str,
    ) -> ttk.Label:
        del title
        icon = ttk.Label(
            parent,
            text="ℹ",
            cursor="hand2",
            anchor="center",
            width=2,
        )
        _HoverTooltip(icon, text)
        self._tooltip_icons.append(icon)
        return icon

    def set_tooltips_enabled(self, enabled: bool) -> None:
        self._tooltips_enabled = bool(enabled)
        self.update_idletasks()
        for icon in self._tooltip_icons:
            manager = icon.winfo_manager()
            if manager and icon not in self._tooltip_layouts:
                if manager == "grid":
                    self._tooltip_layouts[icon] = (manager, dict(icon.grid_info()))
                elif manager == "pack":
                    self._tooltip_layouts[icon] = (manager, dict(icon.pack_info()))

            if self._tooltips_enabled:
                if icon.winfo_manager():
                    continue
                saved = self._tooltip_layouts.get(icon)
                if saved is None:
                    continue
                manager, info = saved
                clean_info = {key: value for key, value in info.items() if key != "in"}
                if manager == "grid":
                    icon.grid(**clean_info)
                elif manager == "pack":
                    icon.pack(**clean_info)
            elif manager == "grid":
                icon.grid_remove()
            elif manager == "pack":
                icon.pack_forget()
