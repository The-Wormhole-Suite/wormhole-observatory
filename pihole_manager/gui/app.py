from __future__ import annotations

import logging
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk

from pihole_manager.config import load_options, save_options
from pihole_manager.database import init_db
from pihole_manager.gui.tabs.lists import ListsTab
from pihole_manager.gui.tabs.llm_review import LLMReviewTab
from pihole_manager.gui.tabs.queries import QueriesTab
from pihole_manager.gui.tabs.settings import SettingsTab
from pihole_manager.gui.theme import apply_theme
from pihole_manager.logging_setup import setup_logging
from pihole_manager.pihole_service import close_client
from pihole_manager.workers import get_classifier, get_scanner, stop_workers

log = logging.getLogger(__name__)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        options = load_options()
        self.title("Pi-hole Manager")
        self.geometry(f"{options.ui.window_width}x{options.ui.window_height}")
        self.minsize(900, 650)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ui")

        apply_theme(self, options.ui.theme)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.queries_tab = QueriesTab(notebook, self.executor)
        self.lists_tab = ListsTab(notebook, self.executor)
        self.llm_tab = LLMReviewTab(notebook, self.executor)
        self.settings_tab = SettingsTab(notebook, self.executor, self._settings_saved)

        notebook.add(self.queries_tab, text="Live Queries")
        notebook.add(self.lists_tab, text="Lists")
        notebook.add(self.llm_tab, text="LLM Review")
        notebook.add(self.settings_tab, text="Settings")

        get_scanner()
        get_classifier()

    def _settings_saved(self) -> None:
        self.queries_tab.reload_preferences()
        self.lists_tab.refresh()
        self.llm_tab.reload_preferences()

    def _on_close(self) -> None:
        options = load_options()
        options.ui.window_width = max(self.winfo_width(), 800)
        options.ui.window_height = max(self.winfo_height(), 600)
        save_options(options)
        stop_workers()
        close_client()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def run_app() -> None:
    setup_logging()
    init_db()
    app = App()
    app.mainloop()
