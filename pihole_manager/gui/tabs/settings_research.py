from __future__ import annotations

import copy
import threading
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.config import Options, ResearchProviderOptions
from pihole_manager.evidence_licensing import source_license_policy
from pihole_manager.gui.tooltips import TooltipSupport
from pihole_manager.research import EvidenceSourceTestResult, test_research_provider
from pihole_manager.research_common import source_definition, source_definitions


class ResearchSettingsPage(TooltipSupport, ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        ttk.Frame.__init__(self, master, padding=10)
        self._init_tooltips()
        self._change_callback: Callable[[], None] | None = None
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)
        self.options: Options | None = None
        self.index = 0
        self._testing = False
        self.skip_api_key_sources = tk.BooleanVar()
        self.skip_missing_api_keys = tk.BooleanVar()

        general = ttk.LabelFrame(self, text="Evidence cache", padding=10)
        general.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        general.columnconfigure(1, weight=1)
        self.max_age_days = tk.StringVar()
        ttk.Label(general, text="Fallback cache lifetime (days)").grid(
            row=0,
            column=0,
            sticky="w",
            pady=3,
        )
        cache_row = ttk.Frame(general)
        cache_row.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=3)
        ttk.Entry(cache_row, textvariable=self.max_age_days, width=10).pack(side="left")
        ttk.Label(
            general,
            text=(
                "Catalog sources download complete datasets and match domains locally. "
                "Lookup sources may send the investigated domain or a resolved public IP "
                "address to the selected service. Every LLM classification receives the "
                "resulting compact evidence dossier."
            ),
            wraplength=900,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(5, 0))

        left = ttk.Frame(self)
        left.grid(row=1, column=0, sticky="ns", padx=(0, 10))
        self.listbox = tk.Listbox(
            left, width=34, exportselection=False, selectmode="browse", activestyle="none"
        )
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._selected)

        buttons = ttk.Frame(left)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Add", command=self._add).pack(side="left")
        ttk.Button(buttons, text="Duplicate", command=self._duplicate).pack(
            side="left",
            padx=4,
        )
        ttk.Button(buttons, text="Remove", command=self._remove).pack(side="left")

        test_buttons = ttk.Frame(left)
        test_buttons.pack(fill="x", pady=(8, 0))
        self.test_source_button = ttk.Button(
            test_buttons,
            text="Test source",
            command=self._test_selected,
        )
        self.test_source_button.pack(side="left", fill="x", expand=True)
        self.test_all_button = ttk.Button(
            test_buttons,
            text="Test all sources",
            command=self._test_all,
        )
        self.test_all_button.pack(side="left", fill="x", expand=True, padx=(6, 0))
        test_options = ttk.LabelFrame(left, text="Test options", padding=6)
        test_options.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(
            test_options,
            text="Skip all API-key sources",
            variable=self.skip_api_key_sources,
            command=self._test_option_changed,
        ).pack(anchor="w")
        ttk.Checkbutton(
            test_options,
            text="Skip sources without a configured API key",
            variable=self.skip_missing_api_keys,
            command=self._test_option_changed,
        ).pack(anchor="w", pady=(3, 0))
        self.test_status = ttk.Label(left, text="", wraplength=280, justify="left")
        self.test_status.pack(fill="x", pady=(6, 0))

        editor = ttk.LabelFrame(self, text="Evidence source", padding=10)
        editor.grid(row=1, column=1, sticky="nsew")
        editor.columnconfigure(1, weight=1)
        self.provider_enabled = tk.BooleanVar()
        self.name = tk.StringVar()
        self.kind = tk.StringVar()
        self.base_url = tk.StringVar()
        self.api_key = tk.StringVar()
        self.timeout = tk.StringVar()
        self.min_interval = tk.StringVar()
        self.refresh_interval = tk.StringVar()
        self.max_results = tk.StringVar()
        self.test_domain = tk.StringVar()

        ttk.Checkbutton(
            editor,
            text="Source enabled",
            variable=self.provider_enabled,
            command=self._enabled_changed,
        ).grid(row=0, column=0, sticky="w", pady=4)

        fields = (
            ("Name", self.name, False),
            ("Kind", self.kind, False),
            ("Base URL", self.base_url, False),
            ("API key", self.api_key, True),
            ("Timeout (seconds)", self.timeout, False),
            ("Minimum request interval (seconds)", self.min_interval, False),
            ("Refresh interval (hours)", self.refresh_interval, False),
            ("Maximum results", self.max_results, False),
            ("Test domain", self.test_domain, False),
        )
        for row, (label, variable, secret) in enumerate(fields, start=1):
            label_widget = ttk.Label(editor, text=label)
            label_widget.grid(row=row, column=0, sticky="w", pady=4)
            value_row = ttk.Frame(editor)
            value_row.grid(row=row, column=1, sticky="ew", padx=(10, 0), pady=4)
            value_row.columnconfigure(0, weight=1)
            if label == "Kind":
                widget = ttk.Combobox(
                    value_row,
                    textvariable=variable,
                    values=tuple(item.kind for item in source_definitions()),
                    state="readonly",
                )
                widget.bind("<<ComboboxSelected>>", self._kind_changed)
            else:
                widget = ttk.Entry(
                    value_row,
                    textvariable=variable,
                    show="•" if secret else "",
                )
            widget.grid(row=0, column=0, sticky="ew")
            if label == "API key":
                self.api_key_label = label_widget
                self.api_key_row = value_row
            if label == "Refresh interval (hours)":
                self._info_button(
                    value_row,
                    label,
                    "How long a positive or negative result remains fresh before the source "
                    "is contacted or reloaded again.",
                ).grid(row=0, column=1, sticky="w", padx=(6, 0))

        metadata = ttk.LabelFrame(editor, text="Source behavior", padding=8)
        metadata.grid(
            row=len(fields) + 1,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(12, 0),
        )
        metadata.columnconfigure(0, weight=1)
        self.source_metadata = ttk.Label(metadata, wraplength=800, justify="left")
        self.source_metadata.grid(row=0, column=0, sticky="ew")

    def set_change_callback(self, callback: Callable[[], None]) -> None:
        self._change_callback = callback

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

    def _test_option_changed(self) -> None:
        self._changed()

    def _enabled_changed(self) -> None:
        if self.options is None or not self._store_current():
            return
        selected_provider = self.options.research_providers[self.index]
        self._reload(_identity_index(self.options.research_providers, selected_provider))
        self._changed()

    def load(self, options: Options) -> None:
        self.options = options
        self.max_age_days.set(str(options.research.max_age_days))
        self.skip_api_key_sources.set(options.ui.evidence_test_skip_api_key_sources)
        self.skip_missing_api_keys.set(options.ui.evidence_test_skip_missing_api_keys)
        self._reload(0)

    def store(self, options: Options) -> bool:
        if self.options is not options:
            self.options = options
        if not self._store_current():
            return False
        options.ui.evidence_test_skip_api_key_sources = bool(self.skip_api_key_sources.get())
        options.ui.evidence_test_skip_missing_api_keys = bool(self.skip_missing_api_keys.get())
        try:
            options.research.max_age_days = int(self.max_age_days.get())
        except ValueError:
            messagebox.showerror("Evidence Sources", "Cache lifetime must be an integer.")
            return False
        return True

    def _reload(self, selected: int) -> None:
        assert self.options is not None
        providers = self.options.research_providers
        selected = min(max(0, selected), len(providers) - 1)
        selected_provider = providers[selected]
        providers.sort(
            key=lambda item: (
                not item.enabled,
                (item.name or "Unnamed source").casefold(),
            )
        )
        self.index = _identity_index(providers, selected_provider)

        self.listbox.delete(0, "end")
        for provider in providers:
            marker = "✓ " if provider.enabled else ""
            self.listbox.insert("end", marker + (provider.name or "Unnamed source"))
        self._select_index(self.index)
        self._load_current()

    def _select_index(self, index: int) -> None:
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(index)
        self.listbox.activate(index)
        self.listbox.see(index)

    def _load_current(self) -> None:
        assert self.options is not None
        provider = self.options.research_providers[self.index]
        self.provider_enabled.set(provider.enabled)
        self.name.set(provider.name)
        self.kind.set(provider.kind)
        self.base_url.set(provider.base_url)
        self.api_key.set(provider.api_key)
        self.timeout.set(str(provider.timeout_sec))
        self.min_interval.set(str(provider.min_interval_sec))
        self.refresh_interval.set(str(provider.refresh_interval_hours))
        self.max_results.set(str(provider.max_results))
        self.test_domain.set(provider.test_domain)
        self._update_source_metadata()

    def _store_current(self) -> bool:
        assert self.options is not None
        try:
            timeout = float(self.timeout.get())
            interval = float(self.min_interval.get())
            refresh_interval = int(self.refresh_interval.get())
            max_results = int(self.max_results.get())
        except ValueError:
            messagebox.showerror(
                "Evidence source",
                "Timeout, intervals, and maximum results must be numeric.",
            )
            return False
        selected_kind = self.kind.get().strip()
        definition = source_definition(selected_kind)
        if (
            self.provider_enabled.get()
            and definition is not None
            and definition.requires_api_key
            and not self.api_key.get().strip()
        ):
            messagebox.showerror(
                "Evidence source",
                f"{definition.display_name} requires an API key before it can be enabled.",
            )
            return False
        provider = self.options.research_providers[self.index]
        provider.enabled = self.provider_enabled.get()
        provider.name = self.name.get().strip() or "Unnamed source"
        provider.kind = selected_kind
        provider.base_url = self.base_url.get().strip()
        provider.api_key = (
            self.api_key.get().strip()
            if definition is not None and definition.requires_api_key
            else ""
        )
        provider.timeout_sec = timeout
        provider.min_interval_sec = interval
        provider.refresh_interval_hours = refresh_interval
        provider.max_results = max_results
        provider.test_domain = self.test_domain.get().strip().lower()
        self.listbox.delete(self.index)
        marker = "✓ " if provider.enabled else ""
        self.listbox.insert(self.index, marker + provider.name)
        self._select_index(self.index)
        return True

    def _selected(self, _event: tk.Event | None = None) -> None:
        selection = self.listbox.curselection()
        if not selection or int(selection[0]) == self.index:
            return
        selected = int(selection[0])
        if not self._store_current():
            self._select_index(self.index)
            return
        self.index = selected
        self._select_index(self.index)
        self._load_current()

    def _kind_changed(self, _event: tk.Event | None = None) -> None:
        definition = source_definition(self.kind.get())
        if definition is not None and definition.kind == "rdap" and not self.base_url.get():
            self.base_url.set("https://data.iana.org/rdap/dns.json")
        self._update_source_metadata()

    def _update_source_metadata(self) -> None:
        definition = source_definition(self.kind.get())
        if definition is None:
            self.source_metadata.configure(text="Unknown source type.")
            return
        privacy = {
            "catalog": "Downloads a complete dataset; individual domains are matched locally.",
            "local": "Runs locally and does not contact a dedicated evidence provider.",
            "lookup": (
                "Sends each investigated domain to the provider."
                if definition.sends_domain
                else "Sends only locally resolved public IP addresses to the provider."
            ),
        }.get(definition.mode, "")
        if definition.requires_api_key:
            self.api_key_label.grid()
            self.api_key_row.grid()
        else:
            self.api_key_label.grid_remove()
            self.api_key_row.grid_remove()
            self.api_key.set("")
        notes = [definition.description, privacy]
        if definition.requires_api_key:
            notes.append("API key required.")
        if definition.license_note:
            notes.append(f"License/usage note: {definition.license_note}")
        license_policy = source_license_policy(definition.kind)
        if license_policy is not None:
            notes.append(
                "Reviewed usage: "
                f"{license_policy.license_id}; "
                f"commercial={license_policy.commercial_use}; "
                f"reviewed {license_policy.reviewed_at}."
            )
            if not license_policy.release_default_eligible:
                notes.append(
                    "Release policy: opt-in only; this source must not be enabled "
                    "in distributed defaults."
                )
        if definition.experimental:
            notes.append("Experimental adapter: access or page layout may change without notice.")
        self.source_metadata.configure(text="\n".join(notes))

    def _add(self) -> None:
        assert self.options is not None
        name = simpledialog.askstring("Evidence source", "Source name:", parent=self)
        if not name or not self._store_current():
            return
        self.options.research_providers.append(
            ResearchProviderOptions(name=name.strip(), enabled=False)
        )
        self._reload(len(self.options.research_providers) - 1)
        self._changed()

    def _duplicate(self) -> None:
        assert self.options is not None
        if not self._store_current():
            return
        duplicate = copy.deepcopy(self.options.research_providers[self.index])
        duplicate.name = f"{duplicate.name} (copy)"
        duplicate.enabled = False
        self.options.research_providers.insert(self.index + 1, duplicate)
        self._reload(self.index + 1)
        self._changed()

    def _remove(self) -> None:
        assert self.options is not None
        if len(self.options.research_providers) <= 1:
            messagebox.showwarning("Evidence source", "At least one source must remain.")
            return
        del self.options.research_providers[self.index]
        self._reload(min(self.index, len(self.options.research_providers) - 1))
        self._changed()

    def _test_selected(self) -> None:
        assert self.options is not None
        if self._testing or not self._store_current():
            return
        provider = copy.deepcopy(self.options.research_providers[self.index])
        self._changed()
        self._start_test([provider], "Testing selected source …")

    def _test_all(self) -> None:
        assert self.options is not None
        if self._testing or not self._store_current():
            return
        providers = [copy.deepcopy(item) for item in self.options.research_providers]
        self._changed()
        self._start_test(providers, f"Testing {len(providers)} configured sources …")

    def _start_test(
        self,
        providers: list[ResearchProviderOptions],
        status: str,
    ) -> None:
        self._testing = True
        self.test_source_button.state(["disabled"])
        self.test_all_button.state(["disabled"])
        self.test_status.configure(text=status)
        skip_api_key_sources = bool(self.skip_api_key_sources.get())
        skip_missing_api_keys = bool(self.skip_missing_api_keys.get())
        threading.Thread(
            target=self._test_worker,
            args=(providers, skip_api_key_sources, skip_missing_api_keys),
            name="EvidenceSourceTest",
            daemon=True,
        ).start()

    def _test_worker(
        self,
        providers: list[ResearchProviderOptions],
        skip_api_key_sources: bool,
        skip_missing_api_keys: bool,
    ) -> None:
        results: list[EvidenceSourceTestResult] = []
        for position, provider in enumerate(providers, start=1):
            self.after(
                0,
                self.test_status.configure,
                {"text": f"Testing {position}/{len(providers)}: {provider.name} …"},
            )
            results.append(
                test_research_provider(
                    provider,
                    skip_api_key_sources=skip_api_key_sources,
                    skip_missing_api_keys=skip_missing_api_keys,
                )
            )
        self.after(0, self._tests_finished, results)

    def _tests_finished(self, results: list[EvidenceSourceTestResult]) -> None:
        self._testing = False
        self.test_source_button.state(["!disabled"])
        self.test_all_button.state(["!disabled"])
        passed = sum(1 for item in results if item.status == "pass")
        failed = sum(1 for item in results if item.status == "fail")
        skipped = sum(1 for item in results if item.status == "skip")
        self.test_status.configure(
            text=f"Completed: {passed} passed · {failed} failed · {skipped} skipped"
        )
        visible_results = [item for item in results if item.status != "skip"]
        if visible_results:
            self._show_test_results(visible_results)

    def _show_test_results(self, results: list[EvidenceSourceTestResult]) -> None:
        window = tk.Toplevel(self)
        window.title("Evidence source test results")
        window.geometry("1040x460")
        window.minsize(720, 320)
        window.transient(self.winfo_toplevel())

        summary = ttk.Frame(window, padding=(10, 10, 10, 6))
        summary.pack(fill="x")
        passed = sum(1 for item in results if item.status == "pass")
        failed = sum(1 for item in results if item.status == "fail")
        ttk.Label(
            summary,
            text=f"{passed} passed · {failed} failed",
        ).pack(side="left")
        ttk.Button(summary, text="Close", command=window.destroy).pack(side="right")

        host = ttk.Frame(window, padding=(10, 0, 10, 10))
        host.pack(fill="both", expand=True)
        host.rowconfigure(0, weight=1)
        host.columnconfigure(0, weight=1)
        columns = ("status", "source", "domain", "time", "result")
        tree = ttk.Treeview(host, columns=columns, show="headings")
        vertical = ttk.Scrollbar(host, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(host, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        headings = {
            "status": "Status",
            "source": "Source",
            "domain": "Test domain",
            "time": "Time",
            "result": "Result",
        }
        widths = {
            "status": 70,
            "source": 210,
            "domain": 180,
            "time": 80,
            "result": 470,
        }
        for column in columns:
            tree.heading(column, text=headings[column])
            tree.column(
                column,
                width=widths[column],
                minwidth=60,
                anchor="center" if column in {"status", "time"} else "w",
                stretch=column == "result",
            )
        for item in results:
            tree.insert(
                "",
                "end",
                values=(
                    item.status.upper(),
                    item.provider,
                    item.domain,
                    f"{item.elapsed_ms} ms",
                    item.summary,
                ),
            )


def _identity_index(
    values: list[ResearchProviderOptions],
    target: ResearchProviderOptions,
) -> int:
    for index, value in enumerate(values):
        if value is target:
            return index
    return 0
