from __future__ import annotations

import contextlib
import logging
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import ttk

from pihole_manager import __version__
from pihole_manager.config import load_options, save_options
from pihole_manager.database import init_db
from pihole_manager.external_trigger import configure_external_trigger, stop_external_trigger
from pihole_manager.gui.tabs.domains import DomainsTab
from pihole_manager.gui.tabs.history import HistoryTab
from pihole_manager.gui.tabs.lists import ListsTab
from pihole_manager.gui.tabs.llm_review import LLMReviewTab
from pihole_manager.gui.tabs.queries import QueriesTab
from pihole_manager.gui.tabs.settings import SettingsTab
from pihole_manager.gui.theme import apply_theme
from pihole_manager.logging_setup import setup_logging
from pihole_manager.pihole_service import close_client, test_connection
from pihole_manager.provider_registry import refresh_provider_registry_if_due
from pihole_manager.workers import (
    get_classifier,
    get_scanner,
    stop_workers,
)

log = logging.getLogger(__name__)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        options = load_options()
        self.title(f"Pi-hole Manager v{__version__}")
        self.geometry(f"{options.ui.window_width}x{options.ui.window_height}")
        self.minsize(900, 650)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ui")
        self._closing = False
        self._health_check_running = False
        self._health_after_id: str | None = None

        apply_theme(self, options.ui.theme)
        notebook_host = ttk.Frame(self)
        notebook_host.pack(fill="both", expand=True)
        notebook = ttk.Notebook(notebook_host)
        notebook.pack(fill="both", expand=True)
        self.notebook = notebook
        self.simulation_mode = tk.BooleanVar(value=options.llm.simulation_mode)
        self.simulation_text = tk.StringVar()
        self.simulation_toggle = ttk.Checkbutton(
            notebook_host,
            variable=self.simulation_mode,
            textvariable=self.simulation_text,
            command=self._toggle_simulation_mode,
        )
        self.simulation_toggle.place(relx=1.0, x=-12, y=3, anchor="ne")
        self._update_simulation_text()

        self.connection_status_text = tk.StringVar(value="Pi-hole: checking …")
        self.connection_status_label = ttk.Label(
            notebook_host,
            textvariable=self.connection_status_text,
        )
        self.connection_status_label.place(x=12, y=5, anchor="nw")

        self.queries_tab = QueriesTab(notebook, self.executor)
        self.history_tab = HistoryTab(notebook, self.executor)
        self.lists_tab = ListsTab(notebook, self.executor)
        self.domains_tab = DomainsTab(notebook, self.executor)
        self.llm_tab = LLMReviewTab(notebook, self.executor)
        self.settings_tab = SettingsTab(notebook, self.executor, self._settings_saved)

        notebook.add(self.queries_tab, text="Live Queries")
        notebook.add(self.history_tab, text="History Browser")
        notebook.add(self.lists_tab, text="Lists")
        notebook.add(self.domains_tab, text="Domain Database")
        notebook.add(self.llm_tab, text="Review Queue")
        notebook.add(self.settings_tab, text="Settings")

        get_scanner()
        get_classifier()
        self._configure_external_trigger(options)
        self.after(400, self._schedule_health_check)
        if options.provider_registry.auto_update:
            registry_future = self.executor.submit(refresh_provider_registry_if_due)
            registry_future.add_done_callback(self._registry_refresh_finished)
        if options.updates.check_automatically:
            from pihole_manager.updater import should_check

            if should_check(options.updates):
                self.after(1_500, lambda: self.settings_tab.check_for_updates(silent=True))

    def _settings_saved(self) -> None:
        options = load_options()
        apply_theme(self, options.ui.theme)
        self.simulation_mode.set(options.llm.simulation_mode)
        self._update_simulation_text()
        self.queries_tab.reload_preferences()
        self.history_tab.reload_preferences()
        self.lists_tab.reload_preferences()
        self.lists_tab.refresh()
        self.domains_tab.reload_preferences()
        self.domains_tab.refresh()
        self.llm_tab.reload_preferences()
        self._configure_external_trigger(options)
        self._schedule_health_check()

    @staticmethod
    def _configure_external_trigger(options) -> None:
        try:
            configure_external_trigger(options.external_trigger)
        except Exception as exc:
            log.warning("External review trigger could not start: %s", exc)

    def _schedule_health_check(self) -> None:
        if self._health_after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._health_after_id)
            self._health_after_id = None
        if self._closing or self._health_check_running:
            return
        self._health_check_running = True
        future = self.executor.submit(test_connection)
        future.add_done_callback(self._health_check_done)

    def _health_check_done(self, future: Future) -> None:
        if self._closing:
            return
        try:
            self.after(0, self._show_health_result, future)
        except tk.TclError:
            return

    def _show_health_result(self, future: Future) -> None:
        if self._closing:
            return
        self._health_check_running = False
        try:
            result = future.result()
        except Exception:
            self.connection_status_text.set("Pi-hole: status unavailable")
        else:
            if result.success:
                version = f" · {result.version}" if result.version else ""
                self.connection_status_text.set(
                    f"Pi-hole: online{version} · {result.elapsed_ms} ms"
                )
            elif result.state == "auth_error":
                self.connection_status_text.set("Pi-hole: authentication failed")
            elif result.state == "degraded":
                self.connection_status_text.set("Pi-hole: API degraded")
            elif result.state == "api_error":
                self.connection_status_text.set("Pi-hole: API error")
            elif result.state == "invalid_config":
                self.connection_status_text.set("Pi-hole: invalid configuration")
            elif result.state == "tls_error":
                self.connection_status_text.set("Pi-hole: TLS verification failed")
            elif result.state == "offline":
                self.connection_status_text.set("Pi-hole: offline")
            else:
                self.connection_status_text.set("Pi-hole: status unavailable")
        self._health_after_id = self.after(30_000, self._schedule_health_check)

    def _toggle_simulation_mode(self) -> None:
        enabled = bool(self.simulation_mode.get())
        options = load_options()
        options.llm.simulation_mode = enabled
        save_options(options)
        self.settings_tab.set_simulation_mode(enabled)
        self._update_simulation_text()

    @staticmethod
    def _registry_refresh_finished(future: Future) -> None:
        try:
            future.result()
        except Exception as exc:
            log.warning("Provider registry refresh failed: %s", exc)

    def _update_simulation_text(self) -> None:
        state = "active" if self.simulation_mode.get() else "inactive"
        self.simulation_text.set(f"Simulation Mode {state}")

    def _on_close(self) -> None:
        self._closing = True
        if self._health_after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._health_after_id)
        options = load_options()
        options.ui.window_width = max(self.winfo_width(), 800)
        options.ui.window_height = max(self.winfo_height(), 600)
        save_options(options)
        self.domains_tab.cancel_active_work(notify=False)
        self.llm_tab.cancel_active_work(notify=False)
        self.settings_tab.cancel_active_work(notify=False)
        stop_external_trigger()
        stop_workers()
        close_client()
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def run_app(*, post_update_marker: str = "") -> None:
    setup_logging()
    init_db()
    app = App()
    if post_update_marker:
        from pihole_manager.updater import mark_update_started

        mark_update_started(post_update_marker)
    app.mainloop()
