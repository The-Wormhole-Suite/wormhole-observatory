from __future__ import annotations

import copy
import tkinter as tk
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk

from pihole_manager.analysis_dispatcher import benchmark_domain
from pihole_manager.cancellation import CancellationToken, OperationCancelledError
from pihole_manager.config import (
    Options,
    ProviderPoolMembershipOptions,
)
from pihole_manager.database import (
    benchmark_run_get,
    domain_observation_summary,
    get_domain_lock,
)
from pihole_manager.gui.tooltips import TooltipSupport
from pihole_manager.research import research_context, research_many


class AnalysisPoolsSettingsPage(TooltipSupport, ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        ttk.Frame.__init__(self, master, padding=10)
        self._init_tooltips()
        self.executor = executor
        self._change_callback: Callable[[], None] | None = None
        self.options: Options | None = None
        self.index = 0
        self._provider_choices: dict[str, str] = {}
        self._benchmark_provider_ids: list[str] = []
        self._benchmark_cancel_token: CancellationToken | None = None

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.pool_list = tk.Listbox(
            left,
            width=24,
            exportselection=False,
            activestyle="none",
        )
        self.pool_list.pack(fill="both", expand=True)
        self.pool_list.bind("<<ListboxSelect>>", self._pool_selected)

        editor = ttk.Frame(self)
        editor.grid(row=0, column=1, sticky="nsew")
        editor.columnconfigure(0, weight=1)

        self.pool_name = tk.StringVar()
        self.pool_enabled = tk.BooleanVar()
        self.pool_mode = tk.StringVar()
        self.profile_name = tk.StringVar()
        self.max_parallel = tk.StringVar()
        self.verification_sample = tk.StringVar()
        self.verify_auto = tk.BooleanVar()
        self.verify_security = tk.StringVar()
        self.verify_breakage = tk.StringVar()

        pool_box = ttk.LabelFrame(editor, text="Analysis pool", padding=8)
        pool_box.grid(row=0, column=0, sticky="ew")
        pool_box.columnconfigure(1, weight=1)
        self._entry(pool_box, 0, "Name", self.pool_name)
        ttk.Checkbutton(
            pool_box,
            text="Enabled",
            variable=self.pool_enabled,
            command=self._changed,
        ).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=3)
        ttk.Label(pool_box, text="Mode").grid(row=2, column=0, sticky="w", pady=3)
        ttk.Combobox(
            pool_box,
            textvariable=self.pool_mode,
            values=("distribute", "fallback", "compare", "verify"),
            state="readonly",
        ).grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=3)
        ttk.Label(pool_box, text="Prompt profile").grid(row=3, column=0, sticky="w", pady=3)
        self.profile_box = ttk.Combobox(
            pool_box,
            textvariable=self.profile_name,
            state="readonly",
        )
        self.profile_box.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=3)
        self._entry(pool_box, 4, "Maximum parallel requests", self.max_parallel)

        verification = ttk.LabelFrame(pool_box, text="Verification selection", padding=6)
        verification.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        verification.columnconfigure(1, weight=1)
        self._entry(verification, 0, "Deterministic sample (%)", self.verification_sample)
        ttk.Checkbutton(
            verification,
            text="Verify results eligible for automatic actions",
            variable=self.verify_auto,
            command=self._changed,
        ).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=3)
        self._entry(verification, 2, "Security risk at least", self.verify_security)
        self._entry(verification, 3, "Breakage risk at least", self.verify_breakage)

        members = ttk.LabelFrame(editor, text="Provider memberships", padding=8)
        members.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        members.columnconfigure(0, weight=1)
        members.rowconfigure(0, weight=1)
        self.member_tree = ttk.Treeview(
            members,
            columns=("provider", "role", "priority", "weight"),
            show="headings",
            height=6,
            selectmode="browse",
        )
        for column, label, width in (
            ("provider", "Provider", 280),
            ("role", "Role", 90),
            ("priority", "Priority", 70),
            ("weight", "Weight", 70),
        ):
            self.member_tree.heading(column, text=label)
            self.member_tree.column(column, width=width, anchor="w")
        self.member_tree.grid(row=0, column=0, columnspan=5, sticky="nsew")
        self.member_tree.bind("<<TreeviewSelect>>", self._member_selected)

        self.member_provider = tk.StringVar()
        self.member_role = tk.StringVar(value="primary")
        self.member_priority = tk.StringVar(value="100")
        self.member_weight = tk.StringVar(value="1")
        self.member_provider_box = ttk.Combobox(
            members,
            textvariable=self.member_provider,
            state="readonly",
            width=30,
        )
        self.member_provider_box.grid(row=1, column=0, sticky="ew", pady=(7, 0))
        ttk.Combobox(
            members,
            textvariable=self.member_role,
            values=("primary", "fallback", "verifier"),
            state="readonly",
            width=11,
        ).grid(row=1, column=1, padx=5, pady=(7, 0))
        ttk.Entry(members, textvariable=self.member_priority, width=8).grid(
            row=1,
            column=2,
            pady=(7, 0),
        )
        ttk.Entry(members, textvariable=self.member_weight, width=8).grid(
            row=1,
            column=3,
            padx=5,
            pady=(7, 0),
        )
        actions = ttk.Frame(members)
        actions.grid(row=1, column=4, pady=(7, 0))
        ttk.Button(actions, text="Add / update", command=self._upsert_member).pack(side="left")
        ttk.Button(actions, text="Remove", command=self._remove_member).pack(
            side="left",
            padx=(5, 0),
        )

        quota = ttk.LabelFrame(editor, text="Shared quota behavior", padding=8)
        quota.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        quota.columnconfigure(1, weight=1)
        self.realtime_reserve = tk.StringVar()
        self.quota_wait = tk.StringVar()
        self.unknown_rpm = tk.StringVar()
        self.unknown_batch = tk.StringVar()
        self.registry_auto_update = tk.BooleanVar()
        self.registry_refresh_hours = tk.StringVar()
        self._entry(quota, 0, "Realtime quota reserve (%)", self.realtime_reserve)
        self._entry(quota, 1, "Maximum quota wait (s)", self.quota_wait)
        self._entry(quota, 2, "Unknown remote requests / minute", self.unknown_rpm)
        self._entry(quota, 3, "Unknown remote domains / request", self.unknown_batch)
        ttk.Checkbutton(
            quota,
            text="Use verified remote provider-registry updates",
            variable=self.registry_auto_update,
            command=self._changed,
        ).grid(row=4, column=1, sticky="w", padx=(8, 0), pady=3)
        self._entry(quota, 5, "Registry refresh interval (hours)", self.registry_refresh_hours)

        benchmark = ttk.LabelFrame(editor, text="One-domain provider benchmark", padding=8)
        benchmark.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        benchmark.columnconfigure(1, weight=1)
        benchmark.rowconfigure(2, weight=1)
        self.benchmark_domain = tk.StringVar()
        ttk.Label(benchmark, text="Domain").grid(row=0, column=0, sticky="w")
        ttk.Entry(benchmark, textvariable=self.benchmark_domain).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(8, 6),
        )
        self.benchmark_button = ttk.Button(
            benchmark,
            text="Run benchmark",
            command=self._start_benchmark,
        )
        self.benchmark_button.grid(row=0, column=2)
        self.benchmark_cancel_button = ttk.Button(
            benchmark,
            text="Cancel",
            command=self._cancel_benchmark,
            state="disabled",
        )
        self.benchmark_cancel_button.grid(row=0, column=3, padx=(6, 0))
        self.benchmark_providers = tk.Listbox(
            benchmark,
            selectmode="extended",
            exportselection=False,
            height=4,
        )
        self.benchmark_providers.grid(
            row=1,
            column=0,
            columnspan=4,
            sticky="ew",
            pady=(7, 0),
        )
        self.benchmark_results = ttk.Treeview(
            benchmark,
            columns=("provider", "model", "status", "latency", "policy", "category"),
            show="headings",
            height=5,
        )
        for column, label, width in (
            ("provider", "Provider", 180),
            ("model", "Model", 180),
            ("status", "Status", 110),
            ("latency", "Latency ms", 80),
            ("policy", "Policy", 100),
            ("category", "Category / error", 220),
        ):
            self.benchmark_results.heading(column, text=label)
            self.benchmark_results.column(column, width=width, anchor="w")
        self.benchmark_results.grid(
            row=2,
            column=0,
            columnspan=4,
            sticky="ew",
            pady=(7, 0),
        )
        self.benchmark_status = ttk.Label(benchmark, text="")
        self.benchmark_status.grid(row=3, column=0, columnspan=4, sticky="w", pady=(5, 0))

    @staticmethod
    def _entry(
        parent: ttk.LabelFrame,
        row: int,
        label: str,
        variable: tk.StringVar,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable).grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(8, 0),
            pady=3,
        )

    def set_change_callback(self, callback: Callable[[], None]) -> None:
        self._change_callback = callback

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

    def load(self, options: Options) -> None:
        self.options = options
        self.profile_box.configure(
            values=tuple(profile.name for profile in options.prompt_profiles)
        )
        self._provider_choices = {}
        for provider in options.llm_providers:
            label = (
                f"{provider.name} · {provider.model or 'no model'} · {provider.provider_id[-8:]}"
            )
            self._provider_choices[label] = provider.provider_id
        labels = tuple(self._provider_choices)
        self.member_provider_box.configure(values=labels)
        if labels:
            self.member_provider.set(labels[0])
        self.pool_list.delete(0, "end")
        for pool in options.analysis_pools:
            self.pool_list.insert("end", pool.name)
        self.realtime_reserve.set(str(options.llm.realtime_quota_reserve_percent))
        self.quota_wait.set(str(options.llm.quota_wait_timeout_sec))
        self.unknown_rpm.set(str(options.llm.unknown_remote_requests_per_minute))
        self.unknown_batch.set(str(options.llm.unknown_remote_max_domains_per_request))
        self.registry_auto_update.set(options.provider_registry.auto_update)
        self.registry_refresh_hours.set(str(options.provider_registry.refresh_interval_hours))
        self._select_pool(0)

    def store(self, options: Options) -> bool:
        self.options = options
        if not self._store_current_pool():
            return False
        try:
            options.llm.realtime_quota_reserve_percent = float(self.realtime_reserve.get())
            options.llm.quota_wait_timeout_sec = float(self.quota_wait.get())
            options.llm.unknown_remote_requests_per_minute = int(self.unknown_rpm.get())
            options.llm.unknown_remote_max_domains_per_request = int(self.unknown_batch.get())
            options.provider_registry.refresh_interval_hours = int(
                self.registry_refresh_hours.get()
            )
        except ValueError:
            messagebox.showerror("Analysis pools", "Quota and registry values must be numbers.")
            return False
        options.provider_registry.auto_update = self.registry_auto_update.get()
        return True

    def _load_current_pool(self) -> None:
        assert self.options is not None
        pool = self.options.analysis_pools[self.index]
        self.pool_name.set(pool.name)
        self.pool_enabled.set(pool.enabled)
        self.pool_mode.set(pool.mode)
        profiles = [profile.name for profile in self.options.prompt_profiles]
        self.profile_name.set(profiles[pool.profile_index])
        self.max_parallel.set(str(pool.max_parallel_requests))
        self.verification_sample.set(str(pool.verification_sample_percent))
        self.verify_auto.set(pool.verify_automatic_actions)
        self.verify_security.set(str(pool.verify_security_risk_at_least))
        self.verify_breakage.set(str(pool.verify_breakage_risk_at_least))
        providers = {provider.provider_id: provider for provider in self.options.llm_providers}
        self.member_tree.delete(*self.member_tree.get_children())
        for membership in pool.memberships:
            provider = providers.get(membership.provider_id)
            if provider is None:
                continue
            self.member_tree.insert(
                "",
                "end",
                iid=membership.provider_id,
                values=(
                    provider.name,
                    membership.role,
                    membership.priority,
                    membership.weight,
                ),
            )
        self._reload_benchmark_providers()

    def _store_current_pool(self) -> bool:
        if self.options is None:
            return True
        pool = self.options.analysis_pools[self.index]
        try:
            pool.max_parallel_requests = int(self.max_parallel.get())
            pool.verification_sample_percent = int(self.verification_sample.get())
            pool.verify_security_risk_at_least = int(self.verify_security.get())
            pool.verify_breakage_risk_at_least = int(self.verify_breakage.get())
        except ValueError:
            messagebox.showerror("Analysis pool", "Pool limits must be whole numbers.")
            return False
        pool.name = self.pool_name.get().strip() or pool.name
        pool.enabled = self.pool_enabled.get()
        pool.mode = self.pool_mode.get().strip() or pool.mode
        pool.verify_automatic_actions = self.verify_auto.get()
        profile_names = [profile.name for profile in self.options.prompt_profiles]
        try:
            pool.profile_index = profile_names.index(self.profile_name.get())
        except ValueError:
            pool.profile_index = 0
        memberships = []
        existing = {item.provider_id: item for item in pool.memberships}
        for item_id in self.member_tree.get_children():
            values = self.member_tree.item(item_id, "values")
            membership = existing.get(
                item_id,
                ProviderPoolMembershipOptions(provider_id=item_id),
            )
            membership.enabled = True
            membership.role = str(values[1])
            membership.priority = int(values[2])
            membership.weight = int(values[3])
            memberships.append(membership)
        pool.memberships = memberships
        return True

    def _pool_selected(self, _event: tk.Event | None = None) -> None:
        if self.options is None:
            return
        selection = self.pool_list.curselection()
        if not selection or int(selection[0]) == self.index:
            return
        selected = int(selection[0])
        if not self._store_current_pool():
            self._select_pool(self.index)
            return
        self._select_pool(selected)
        self._changed()

    def _select_pool(self, index: int) -> None:
        assert self.options is not None
        self.index = min(max(0, index), len(self.options.analysis_pools) - 1)
        self.pool_list.selection_clear(0, "end")
        self.pool_list.selection_set(self.index)
        self.pool_list.activate(self.index)
        self._load_current_pool()

    def _member_selected(self, _event: tk.Event | None = None) -> None:
        selection = self.member_tree.selection()
        if not selection:
            return
        provider_id = selection[0]
        label = next(
            (
                item
                for item, selected_id in self._provider_choices.items()
                if selected_id == provider_id
            ),
            "",
        )
        values = self.member_tree.item(provider_id, "values")
        self.member_provider.set(label)
        self.member_role.set(str(values[1]))
        self.member_priority.set(str(values[2]))
        self.member_weight.set(str(values[3]))

    def _upsert_member(self) -> None:
        provider_id = self._provider_choices.get(self.member_provider.get(), "")
        if not provider_id:
            return
        try:
            priority = max(0, int(self.member_priority.get()))
            weight = max(1, int(self.member_weight.get()))
        except ValueError:
            messagebox.showerror("Analysis pool", "Priority and weight must be whole numbers.")
            return
        provider_name = self.member_provider.get().split(" · ", 1)[0]
        values = (provider_name, self.member_role.get(), priority, weight)
        if self.member_tree.exists(provider_id):
            self.member_tree.item(provider_id, values=values)
        else:
            self.member_tree.insert("", "end", iid=provider_id, values=values)
        self._reload_benchmark_providers()
        self._changed()

    def _remove_member(self) -> None:
        selection = self.member_tree.selection()
        if not selection:
            return
        if len(self.member_tree.get_children()) <= 1:
            messagebox.showwarning(
                "Analysis pool",
                "At least one provider must remain in an enabled analysis pool.",
            )
            return
        self.member_tree.delete(selection[0])
        self._reload_benchmark_providers()
        self._changed()

    def _reload_benchmark_providers(self) -> None:
        assert self.options is not None
        providers = {provider.provider_id: provider for provider in self.options.llm_providers}
        selected_ids = [item_id for item_id in self.member_tree.get_children()]
        self._benchmark_provider_ids = [
            provider_id for provider_id in selected_ids if provider_id in providers
        ]
        self.benchmark_providers.delete(0, "end")
        for provider_id in self._benchmark_provider_ids:
            provider = providers[provider_id]
            self.benchmark_providers.insert(
                "end",
                f"{provider.name} · {provider.model or 'no model'}",
            )
        if self._benchmark_provider_ids:
            self.benchmark_providers.selection_set(0, "end")

    def _start_benchmark(self) -> None:
        if self._benchmark_cancel_token is not None:
            self.benchmark_status.configure(text="A benchmark is already running.")
            return
        if self.options is None or not self._store_current_pool():
            return
        domain = self.benchmark_domain.get().strip().lower().rstrip(".")
        if not domain or any(character.isspace() for character in domain):
            messagebox.showerror("Provider benchmark", "Enter a valid domain.")
            return
        selections = self.benchmark_providers.curselection()
        provider_ids = [self._benchmark_provider_ids[int(index)] for index in selections]
        if not provider_ids:
            messagebox.showerror("Provider benchmark", "Select at least one provider.")
            return
        token = CancellationToken()
        self._benchmark_cancel_token = token
        self.benchmark_button.state(["disabled"])
        self.benchmark_cancel_button.state(["!disabled"])
        self.benchmark_status.configure(text="Building one dossier and running providers …")
        self.benchmark_results.delete(*self.benchmark_results.get_children())
        options = copy.deepcopy(self.options)
        pool_id = options.analysis_pools[self.index].pool_id
        future = self.executor.submit(
            self._benchmark_worker,
            domain,
            provider_ids,
            pool_id,
            options,
            token,
        )
        future.add_done_callback(
            lambda item: self.after(0, self._benchmark_finished, item, token)
        )

    def _benchmark_worker(
        self,
        domain: str,
        provider_ids: list[str],
        pool_id: str,
        options: Options,
        cancel_token: CancellationToken,
    ) -> dict:
        findings = research_many([domain], cancel_token=cancel_token)
        dossier = {
            "domain": domain,
            "query_context": domain_observation_summary(domain),
            "research": research_context(domain, findings.get(domain, [])),
            "lock": get_domain_lock(domain),
        }
        run_id = benchmark_domain(
            domain,
            dossier,
            provider_ids,
            pool_id=pool_id,
            options=options,
            cancel_token=cancel_token,
        )
        result = benchmark_run_get(run_id)
        if result is None:
            raise RuntimeError("Benchmark result could not be loaded.")
        return result

    def _cancel_benchmark(self) -> None:
        self.cancel_active_work()

    def cancel_active_work(self, *, notify: bool = True) -> bool:
        token = self._benchmark_cancel_token
        if token is None:
            return False
        token.cancel()
        if notify:
            self.benchmark_status.configure(text="Cancelling benchmark …")
        return True

    def _benchmark_finished(self, future: Future, token: CancellationToken) -> None:
        if self._benchmark_cancel_token is token:
            self._benchmark_cancel_token = None
        self.benchmark_button.state(["!disabled"])
        self.benchmark_cancel_button.state(["disabled"])
        try:
            result = future.result()
        except OperationCancelledError:
            self.benchmark_status.configure(text="Benchmark cancelled")
            return
        except Exception as exc:
            self.benchmark_status.configure(text=f"Benchmark failed: {exc}")
            return
        for index, item in enumerate(result["results"]):
            classification = item.get("classification") or {}
            category = str(classification.get("category") or item.get("error") or "")
            self.benchmark_results.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    item["provider_name"],
                    item["model"],
                    item["status"],
                    item["latency_ms"],
                    classification.get("policy", ""),
                    category,
                ),
            )
        self.benchmark_status.configure(
            text=f"Benchmark {result['status']} · dossier {result['dossier_hash'][:12]}…"
        )
