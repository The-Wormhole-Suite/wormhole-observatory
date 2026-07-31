from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk

from pihole_manager.config import load_options, save_options
from pihole_manager.gui.scrollable import ScrollableFrame
from pihole_manager.gui.tabs.settings_application import ApplicationSettingsPage
from pihole_manager.gui.tabs.settings_automation import AutomationSettingsPage
from pihole_manager.gui.tabs.settings_pihole import PiHoleSettingsPage
from pihole_manager.gui.tabs.settings_profiles import ProfilesSettingsPage
from pihole_manager.gui.tabs.settings_providers import ProvidersSettingsPage
from pihole_manager.gui.tabs.settings_research import ResearchSettingsPage
from pihole_manager.gui.theme import apply_theme
from pihole_manager.logging_setup import setup_logging
from pihole_manager.pihole_service import configure_client, test_connection


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
        self._loading = False
        self._saving = False
        self._save_jobs: dict[int, str] = {}
        self._build_ui()
        self._load_pages()
        self.after_idle(self._install_autosave_bindings)

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.notebook = notebook

        page_specs = (
            (
                "Pi-hole",
                lambda parent: PiHoleSettingsPage(parent, self._save_and_test),
            ),
            ("Automation", AutomationSettingsPage),
            ("LLM Providers", ProvidersSettingsPage),
            ("Prompt Profiles", ProfilesSettingsPage),
            ("Evidence Sources", ResearchSettingsPage),
            ("Application", ApplicationSettingsPage),
        )
        self.pages: list[ttk.Frame] = []
        self.page_wrappers: list[ScrollableFrame] = []
        for label, factory in page_specs:
            wrapper = ScrollableFrame(notebook)
            page = factory(wrapper.content)
            page.pack(fill="both", expand=True)
            notebook.add(wrapper, text=label)
            self.page_wrappers.append(wrapper)
            self.pages.append(page)

        self.pihole_page = self.pages[0]
        self.automation_page = self.pages[1]
        self.application_page = self.pages[5]
        for page in self.pages[1:]:
            setter = getattr(page, "set_change_callback", None)
            if callable(setter):
                setter(lambda current=page: self._schedule_auto_save(current))

    def _load_pages(self) -> None:
        self._loading = True
        try:
            for page in self.pages:
                page.load(self.options)
            self._apply_tooltip_preference()
        finally:
            self._loading = False

    def _apply_tooltip_preference(self) -> None:
        enabled = self.options.ui.show_tooltips
        self._set_tooltips_enabled(enabled)
        self.after_idle(self._set_tooltips_enabled, enabled)

    def _set_tooltips_enabled(self, enabled: bool) -> None:
        for page in self.pages:
            setter = getattr(page, "set_tooltips_enabled", None)
            if callable(setter):
                setter(enabled)

    def _install_autosave_bindings(self) -> None:
        for page in self.pages[1:]:
            for widget in self._walk_widgets(page):
                if isinstance(widget, ttk.Combobox):
                    widget.bind(
                        "<<ComboboxSelected>>",
                        lambda _event, current=page: self._schedule_auto_save(current),
                        add="+",
                    )
                    widget.bind(
                        "<FocusOut>",
                        lambda _event, current=page: self._schedule_auto_save(current),
                        add="+",
                    )
                elif isinstance(widget, (ttk.Entry, ttk.Spinbox, tk.Entry)):
                    widget.bind(
                        "<FocusOut>",
                        lambda _event, current=page: self._schedule_auto_save(current),
                        add="+",
                    )
                    widget.bind(
                        "<Return>",
                        lambda _event, current=page: self._schedule_auto_save(current),
                        add="+",
                    )
                elif isinstance(widget, ttk.Checkbutton):
                    widget.bind(
                        "<ButtonRelease-1>",
                        lambda _event, current=page: self.after_idle(
                            lambda: self._schedule_auto_save(current)
                        ),
                        add="+",
                    )
                    widget.bind(
                        "<KeyRelease-space>",
                        lambda _event, current=page: self.after_idle(
                            lambda: self._schedule_auto_save(current)
                        ),
                        add="+",
                    )
                elif isinstance(widget, tk.Text):
                    widget.bind(
                        "<FocusOut>",
                        lambda _event, current=page: self._schedule_auto_save(current),
                        add="+",
                    )
                elif isinstance(widget, tk.Listbox):
                    widget.bind(
                        "<<ListboxSelect>>",
                        lambda _event, current=page: self.after_idle(
                            lambda: self._schedule_auto_save(current)
                        ),
                        add="+",
                    )

    @staticmethod
    def _walk_widgets(parent: tk.Misc) -> list[tk.Widget]:
        widgets: list[tk.Widget] = []
        pending = list(parent.winfo_children())
        while pending:
            widget = pending.pop()
            widgets.append(widget)
            pending.extend(widget.winfo_children())
        return widgets

    def _schedule_auto_save(self, page: ttk.Frame) -> None:
        if self._loading or self._saving or page is self.pihole_page:
            return
        key = id(page)
        existing = self._save_jobs.pop(key, None)
        if existing is not None:
            self.after_cancel(existing)
        self._save_jobs[key] = self.after(300, self._auto_save_page, page)

    def _auto_save_page(self, page: ttk.Frame) -> None:
        self._save_jobs.pop(id(page), None)
        if self._loading or self._saving:
            return
        self._saving = True
        try:
            if not page.store(self.options):
                return
            save_options(self.options)
            if isinstance(page, ApplicationSettingsPage):
                setup_logging(force=True)
                apply_theme(self.winfo_toplevel(), self.options.ui.theme)
                for wrapper in self.page_wrappers:
                    wrapper.refresh_theme()
                self._apply_tooltip_preference()
            if self.on_saved:
                self.on_saved()
        except Exception as exc:
            messagebox.showerror("Settings", f"Could not save settings: {exc}")
        finally:
            self._saving = False

    def set_simulation_mode(self, enabled: bool) -> None:
        self.options.llm.simulation_mode = bool(enabled)
        simulation_var = getattr(self.automation_page, "simulation_mode", None)
        if simulation_var is not None:
            simulation_var.set(bool(enabled))

    def check_for_updates(self, *, silent: bool = False) -> None:
        checker = getattr(self.application_page, "check_for_updates", None)
        if callable(checker):
            checker(silent=silent)

    def _save_and_test(self) -> None:
        if not self.pihole_page.store(self.options):
            return
        try:
            save_options(self.options)
            configure_client(self.options.pihole)
        except Exception as exc:
            messagebox.showerror("Pi-hole", f"Could not save Pi-hole settings: {exc}")
            return

        self.pihole_page.set_test_running(True)
        self.pihole_page.set_connection_status("Saving settings and testing connection …")
        future = self.executor.submit(test_connection, self.options.pihole)
        future.add_done_callback(lambda item: self.after(0, self._show_test_result, item))

    def _show_test_result(self, future: Future) -> None:
        self.pihole_page.set_test_running(False)
        try:
            result = future.result()
        except Exception as exc:
            self.pihole_page.set_connection_status(f"⚠ Settings saved · Connection failed: {exc}")
            return

        if result.success:
            self.pihole_page.set_connection_status(
                f"✓ Saved and connected · {result.elapsed_ms} ms · {result.summary}"
            )
        else:
            self.pihole_page.set_connection_status(
                f"⚠ Settings saved · Connection failed · {result.summary}"
            )
        if self.on_saved:
            self.on_saved()
