from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from tkinter import messagebox, ttk

from pihole_manager.config import load_options, save_options
from pihole_manager.gui.tabs.settings_application import ApplicationSettingsPage
from pihole_manager.gui.tabs.settings_automation import AutomationSettingsPage
from pihole_manager.gui.tabs.settings_pihole import PiHoleSettingsPage
from pihole_manager.gui.tabs.settings_profiles import ProfilesSettingsPage
from pihole_manager.gui.tabs.settings_providers import ProvidersSettingsPage
from pihole_manager.logging_setup import setup_logging
from pihole_manager.pihole_service import configure_client


class SettingsTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        executor: ThreadPoolExecutor,
        on_saved: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master)
        self.executor = executor
        self.on_saved = on_saved
        self.options = load_options()
        self._build_ui()
        self._load_pages()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(10, 8))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Reload", command=self._reload).pack(side="left")
        ttk.Button(toolbar, text="Save all", command=self._save_all).pack(side="right")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.pages = [
            PiHoleSettingsPage(notebook, self.executor),
            AutomationSettingsPage(notebook),
            ProvidersSettingsPage(notebook),
            ProfilesSettingsPage(notebook),
            ApplicationSettingsPage(notebook),
        ]
        labels = ("Pi-hole", "Automation", "Providers", "Profiles", "Application")
        for page, label in zip(self.pages, labels, strict=True):
            notebook.add(page, text=label)

    def _load_pages(self) -> None:
        for page in self.pages:
            page.load(self.options)

    def _save_all(self) -> None:
        for page in self.pages:
            if not page.store(self.options):
                return
        save_options(self.options)
        configure_client(self.options.pihole)
        setup_logging(force=True)
        if self.on_saved:
            self.on_saved()
        messagebox.showinfo("Settings", "All settings were saved.")

    def _reload(self) -> None:
        self.options = load_options()
        self._load_pages()
        messagebox.showinfo("Settings", "Settings reloaded from options.json.")
