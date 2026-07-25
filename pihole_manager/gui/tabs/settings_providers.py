from __future__ import annotations

import copy
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.config import LLMProviderOptions, Options


class ProvidersSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=10)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.options: Options | None = None
        self.index = 0

        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.listbox = tk.Listbox(left, width=28, exportselection=False)
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._selected)
        buttons = ttk.Frame(left)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Add", command=self._add).pack(side="left")
        ttk.Button(buttons, text="Duplicate", command=self._duplicate).pack(
            side="left", padx=4
        )
        ttk.Button(buttons, text="Remove", command=self._remove).pack(side="left")

        editor = ttk.LabelFrame(self, text="Provider", padding=10)
        editor.grid(row=0, column=1, sticky="nsew")
        editor.columnconfigure(1, weight=1)
        self.name = tk.StringVar()
        self.base_url = tk.StringVar()
        self.api_key = tk.StringVar()
        self.model = tk.StringVar()
        self.temperature = tk.StringVar()
        self.timeout = tk.StringVar()
        for row, (label, variable, secret) in enumerate(
            (
                ("Name", self.name, False),
                ("Base URL", self.base_url, False),
                ("API key", self.api_key, True),
                ("Model", self.model, False),
                ("Temperature", self.temperature, False),
                ("Timeout", self.timeout, False),
            )
        ):
            ttk.Label(editor, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(editor, textvariable=variable, show="•" if secret else "").grid(
                row=row, column=1, sticky="ew", padx=(10, 0), pady=4
            )
        ttk.Button(editor, text="Apply changes", command=self._apply_clicked).grid(
            row=6, column=1, sticky="e", pady=(12, 0)
        )

    def load(self, options: Options) -> None:
        self.options = options
        self._reload(options.llm.active_provider_index)

    def store(self, options: Options) -> bool:
        if self.options is not options:
            self.options = options
        if not self._store_current():
            return False
        options.llm.active_provider_index = self.index
        return True

    def _reload(self, selected: int) -> None:
        assert self.options is not None
        self.listbox.delete(0, "end")
        for provider in self.options.llm_providers:
            self.listbox.insert("end", provider.name or "Unnamed provider")
        self.index = min(max(0, selected), len(self.options.llm_providers) - 1)
        self.listbox.selection_set(self.index)
        self._load_current()

    def _load_current(self) -> None:
        assert self.options is not None
        provider = self.options.llm_providers[self.index]
        self.name.set(provider.name)
        self.base_url.set(provider.base_url)
        self.api_key.set(provider.api_key)
        self.model.set(provider.model)
        self.temperature.set(str(provider.temperature))
        self.timeout.set(str(provider.timeout_sec))

    def _store_current(self) -> bool:
        assert self.options is not None
        try:
            temperature = float(self.temperature.get())
            timeout = max(1.0, float(self.timeout.get()))
        except ValueError:
            messagebox.showerror("Provider", "Temperature and timeout must be numbers.")
            return False
        provider = self.options.llm_providers[self.index]
        provider.name = self.name.get().strip() or "Unnamed provider"
        provider.base_url = self.base_url.get().strip()
        provider.api_key = self.api_key.get().strip()
        provider.model = self.model.get().strip()
        provider.temperature = temperature
        provider.timeout_sec = timeout
        self.listbox.delete(self.index)
        self.listbox.insert(self.index, provider.name)
        self.listbox.selection_set(self.index)
        return True

    def _selected(self, _event: tk.Event | None = None) -> None:
        selection = self.listbox.curselection()
        if not selection or int(selection[0]) == self.index:
            return
        selected = int(selection[0])
        if not self._store_current():
            self.listbox.selection_clear(0, "end")
            self.listbox.selection_set(self.index)
            return
        self.index = selected
        self._load_current()

    def _apply_clicked(self) -> None:
        if self._store_current():
            messagebox.showinfo("Provider", "Provider changes applied in memory.")

    def _add(self) -> None:
        assert self.options is not None
        name = simpledialog.askstring("Provider", "Provider name:", parent=self)
        if not name or not self._store_current():
            return
        self.options.llm_providers.append(LLMProviderOptions(name=name.strip()))
        self._reload(len(self.options.llm_providers) - 1)

    def _duplicate(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        duplicate = copy.deepcopy(self.options.llm_providers[self.index])
        duplicate.name = f"{duplicate.name} (copy)"
        self.options.llm_providers.insert(self.index + 1, duplicate)
        self._reload(self.index + 1)

    def _remove(self) -> None:
        assert self.options is not None
        if len(self.options.llm_providers) <= 1:
            messagebox.showwarning("Provider", "At least one provider must remain.")
            return
        del self.options.llm_providers[self.index]
        self._reload(min(self.index, len(self.options.llm_providers) - 1))
