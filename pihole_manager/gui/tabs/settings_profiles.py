from __future__ import annotations

import copy
import json
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.config import Options, PromptProfileOptions
from pihole_manager.gui.tooltips import TooltipSupport
from pihole_manager.llm import build_batch_messages


class ProfilesSettingsPage(TooltipSupport, ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        ttk.Frame.__init__(self, master, padding=10)
        self._init_tooltips()
        self._change_callback: Callable[[], None] | None = None
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
        ttk.Button(buttons, text="Duplicate", command=self._duplicate).pack(side="left", padx=4)
        ttk.Button(buttons, text="Remove", command=self._remove).pack(side="left")

        editor = ttk.LabelFrame(self, text="Prompt profile", padding=10)
        editor.grid(row=0, column=1, sticky="nsew")
        editor.columnconfigure(0, weight=1)
        editor.rowconfigure(3, weight=1)
        editor.rowconfigure(5, weight=1)
        self.name = tk.StringVar()
        ttk.Label(editor, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Entry(editor, textvariable=self.name).grid(row=0, column=1, sticky="ew")
        profile_help = ttk.Frame(editor)
        profile_help.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 4))
        profile_help.columnconfigure(0, weight=1)
        ttk.Label(
            profile_help,
            text=(
                "Profiles control analysis behavior. The immutable technical contract, "
                "allowed tags, policies, and JSON schema are appended automatically."
            ),
            wraplength=760,
        ).grid(row=0, column=0, sticky="w")
        self._info_button(
            profile_help,
            "Prompt profile",
            "The editable profile influences analysis style and priorities. The application "
            "always appends the strict JSON contract separately, so the parser does not depend "
            "on users preserving schema instructions in this text.",
        ).grid(row=0, column=1, padx=(6, 0))
        ttk.Label(editor, text="System prompt").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(6, 4)
        )
        self.system = tk.Text(editor, height=8, wrap="word")
        self.system.grid(row=3, column=0, columnspan=2, sticky="nsew")
        template_help = ttk.Frame(editor)
        template_help.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 4))
        template_help.columnconfigure(0, weight=1)
        ttk.Label(
            template_help,
            text=(
                "User template — must contain {domain_dossiers}. Other variables: "
                "{domain}, {domains}, {tags}, {policies}, {schema}."
            ),
            wraplength=760,
        ).grid(row=0, column=0, sticky="w")
        self._info_button(
            template_help,
            "Domain dossiers",
            "The placeholder is replaced by structured query observations, cached research "
            "findings, and lock state for every domain in the current batch.",
        ).grid(row=0, column=1, padx=(6, 0))
        self.user_template = tk.Text(editor, height=8, wrap="word")
        self.user_template.grid(row=5, column=0, columnspan=2, sticky="nsew")
        actions = ttk.Frame(editor)
        actions.grid(row=6, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(actions, text="Preview effective prompt", command=self._preview).pack(
            side="left"
        )

    def set_change_callback(self, callback: Callable[[], None]) -> None:
        self._change_callback = callback

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

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

    def _profile_from_editor(self) -> PromptProfileOptions | None:
        template = self.user_template.get("1.0", "end").strip()
        if "{domain_dossiers}" not in template:
            messagebox.showerror(
                "Profile",
                "The user template must contain {domain_dossiers} so every batch receives "
                "the complete structured evidence.",
            )
            return None
        return PromptProfileOptions(
            name=self.name.get().strip() or "Unnamed profile",
            system=self.system.get("1.0", "end").strip(),
            user_template=template,
        )

    def _store_current(self) -> bool:
        assert self.options is not None
        edited = self._profile_from_editor()
        if edited is None:
            return False
        profile = self.options.prompt_profiles[self.index]
        profile.name = edited.name
        profile.system = edited.system
        profile.user_template = edited.user_template
        self.listbox.delete(self.index)
        self.listbox.insert(self.index, profile.name)
        self.listbox.selection_set(self.index)
        return True

    def _preview(self) -> None:
        edited = self._profile_from_editor()
        if edited is None:
            return
        sample = {
            "domain": "telemetry.example.com",
            "query_context": {
                "query_count": 42,
                "clients": ["phone"],
                "first_seen": 1_700_000_000,
                "last_seen": 1_700_003_600,
            },
            "research": {
                "findings": [
                    {
                        "provider": "Example source",
                        "kind": "structured_evidence",
                        "title": "Example evidence",
                        "summary": "Example evidence supplied to the model.",
                    }
                ]
            },
            "lock": None,
        }
        try:
            messages = build_batch_messages(edited, [sample])
        except (KeyError, ValueError) as exc:
            messagebox.showerror("Prompt preview", str(exc))
            return
        window = tk.Toplevel(self)
        window.title("Effective prompt preview")
        window.geometry("900x700")
        text = tk.Text(window, wrap="word")
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.insert("1.0", json.dumps(messages, ensure_ascii=False, indent=2))
        text.configure(state="disabled")

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

    def _add(self) -> None:
        assert self.options is not None
        name = simpledialog.askstring("Profile", "Profile name:", parent=self)
        if not name or not self._store_current():
            return
        self.options.prompt_profiles.append(PromptProfileOptions(name=name.strip()))
        self._reload(len(self.options.prompt_profiles) - 1)
        self._changed()

    def _duplicate(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        duplicate = copy.deepcopy(self.options.prompt_profiles[self.index])
        duplicate.name = f"{duplicate.name} (copy)"
        self.options.prompt_profiles.insert(self.index + 1, duplicate)
        self._reload(self.index + 1)
        self._changed()

    def _remove(self) -> None:
        assert self.options is not None
        if len(self.options.prompt_profiles) <= 1:
            messagebox.showwarning("Profile", "At least one profile must remain.")
            return
        del self.options.prompt_profiles[self.index]
        self._reload(min(self.index, len(self.options.prompt_profiles) - 1))
        self._changed()
