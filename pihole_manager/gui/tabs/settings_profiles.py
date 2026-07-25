from __future__ import annotations

import copy
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.config import Options, PromptProfileOptions


class ProfilesSettingsPage(ttk.Frame):
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

        editor = ttk.LabelFrame(self, text="Prompt profile", padding=10)
        editor.grid(row=0, column=1, sticky="nsew")
        editor.columnconfigure(0, weight=1)
        editor.rowconfigure(2, weight=1)
        editor.rowconfigure(4, weight=1)
        self.name = tk.StringVar()
        ttk.Label(editor, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Entry(editor, textvariable=self.name).grid(row=0, column=1, sticky="ew")
        ttk.Label(editor, text="System prompt").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(10, 4)
        )
        self.system = tk.Text(editor, height=8, wrap="word")
        self.system.grid(row=2, column=0, columnspan=2, sticky="nsew")
        ttk.Label(editor, text="User template").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(10, 4)
        )
        self.user_template = tk.Text(editor, height=8, wrap="word")
        self.user_template.grid(row=4, column=0, columnspan=2, sticky="nsew")
        ttk.Button(editor, text="Apply changes", command=self._apply_clicked).grid(
            row=5, column=1, sticky="e", pady=(10, 0)
        )

    def load(self, options: Options) -> None:
        self.options = options
        self._reload(options.llm.active_profile_index)

    def store(self, options: Options) -> bool:
        if self.options is not options:
            self.options = options
        if not self._store_current():
            return False
        options.llm.active_profile_index = self.index
        return True

    def _reload(self, selected: int) -> None:
        assert self.options is not None
        self.listbox.delete(0, "end")
        for profile in self.options.prompt_profiles:
            self.listbox.insert("end", profile.name or "Unnamed profile")
        self.index = min(max(0, selected), len(self.options.prompt_profiles) - 1)
        self.listbox.selection_set(self.index)
        self._load_current()

    def _load_current(self) -> None:
        assert self.options is not None
        profile = self.options.prompt_profiles[self.index]
        self.name.set(profile.name)
        self.system.delete("1.0", "end")
        self.system.insert("1.0", profile.system)
        self.user_template.delete("1.0", "end")
        self.user_template.insert("1.0", profile.user_template)

    def _store_current(self) -> bool:
        assert self.options is not None
        template = self.user_template.get("1.0", "end").strip()
        if "{domain}" not in template:
            messagebox.showerror("Profile", "The user template must contain {domain}.")
            return False
        profile = self.options.prompt_profiles[self.index]
        profile.name = self.name.get().strip() or "Unnamed profile"
        profile.system = self.system.get("1.0", "end").strip()
        profile.user_template = template
        self.listbox.delete(self.index)
        self.listbox.insert(self.index, profile.name)
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
            messagebox.showinfo("Profile", "Profile changes applied in memory.")

    def _add(self) -> None:
        assert self.options is not None
        name = simpledialog.askstring("Profile", "Profile name:", parent=self)
        if not name or not self._store_current():
            return
        self.options.prompt_profiles.append(PromptProfileOptions(name=name.strip()))
        self._reload(len(self.options.prompt_profiles) - 1)

    def _duplicate(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        duplicate = copy.deepcopy(self.options.prompt_profiles[self.index])
        duplicate.name = f"{duplicate.name} (copy)"
        self.options.prompt_profiles.insert(self.index + 1, duplicate)
        self._reload(self.index + 1)

    def _remove(self) -> None:
        assert self.options is not None
        if len(self.options.prompt_profiles) <= 1:
            messagebox.showwarning("Profile", "At least one profile must remain.")
            return
        del self.options.prompt_profiles[self.index]
        self._reload(min(self.index, len(self.options.prompt_profiles) - 1))
