from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, ttk

from pihole_manager.config import Options
from pihole_manager.gui.policy_labels import policy_label, policy_value
from pihole_manager.gui.tooltips import TooltipSupport


class AutomationSettingsPage(TooltipSupport, ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        ttk.Frame.__init__(self, master, padding=12)
        self._init_tooltips()
        self._change_callback: Callable[[], None] | None = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self.llm_enabled = tk.BooleanVar()
        self.scanner_enabled = tk.BooleanVar()
        self.mode = tk.StringVar()
        self.simulation_mode = tk.BooleanVar()
        self.llm_interval = tk.StringVar()
        self.worker_batch = tk.StringVar()
        self.domains_per_request = tk.StringVar()
        self.min_request_interval = tk.StringVar()
        self.max_retries = tk.StringVar()
        self.default_recheck_days = tk.StringVar()
        self.review_threshold = tk.StringVar()
        self.auto_threshold = tk.StringVar()
        self.require_research = tk.BooleanVar()
        self.scan_interval = tk.StringVar()
        self.scan_batch = tk.StringVar()
        self.queue_trigger = tk.StringVar()
        self.max_queue_wait = tk.StringVar()
        self.history_backfill_enabled = tk.BooleanVar()
        self.history_idle_after = tk.StringVar()
        self.history_lookback_days = tk.StringVar()
        self.history_batch_size = tk.StringVar()
        self.excluded_suffixes = tk.StringVar()

        general = ttk.LabelFrame(self, text="Workers and decision safety", padding=10)
        general.grid(row=0, column=0, sticky="ew")
        general.columnconfigure(0, weight=1)

        analysis_row = ttk.Frame(general)
        analysis_row.grid(row=0, column=0, sticky="ew", pady=3)
        ttk.Checkbutton(
            analysis_row,
            text="Analyze queued domains in the background",
            variable=self.llm_enabled,
            command=self._changed,
        ).pack(side="left")
        self._info_button(
            analysis_row,
            "Background analysis",
            "Continuously processes domains already waiting in the durable analysis queue. "
            "Jobs can come from manual actions, the query collector, or scheduled rechecks. "
            "For each domain the worker refreshes enabled structured evidence when needed, "
            "builds a dossier, sends it to the selected LLM, validates the response, stores "
            "the history, and finally applies the configured safety and automation rules.",
        ).pack(side="left", padx=(6, 0))

        collector_row = ttk.Frame(general)
        collector_row.grid(row=1, column=0, sticky="ew", pady=3)
        ttk.Checkbutton(
            collector_row,
            text="Collect domains from the live Pi-hole query log",
            variable=self.scanner_enabled,
            command=self._changed,
        ).pack(side="left")
        self._info_button(
            collector_row,
            "Query collector",
            "Periodically reads only newer Pi-hole query-log rows, stores aggregated usage "
            "observations, and queues domains that are new or due for re-evaluation. It does "
            "not call the LLM itself. Protected domains are excluded from automatic collection "
            "and scheduled rechecks. Unlock a domain before requesting a new analysis.",
        ).pack(side="left", padx=(6, 0))

        history_row = ttk.Frame(general)
        history_row.grid(row=2, column=0, sticky="ew", pady=3)
        ttk.Checkbutton(
            history_row,
            text="Backfill unclassified domains from Pi-hole history while live collection is idle",
            variable=self.history_backfill_enabled,
            command=self._changed,
        ).pack(side="left")
        self._info_button(
            history_row,
            "Idle history backfill",
            "After the live query collector has seen no new rows for the configured idle time, "
            "it inspects older Pi-hole query-log pages in small batches. Only domains without a "
            "current classification or with a due recheck are queued. The feature is optional and "
            "rate-limited so it does not continuously scan the long-term database.",
        ).pack(side="left", padx=(6, 0))

        evidence_row = ttk.Frame(general)
        evidence_row.grid(row=3, column=0, sticky="ew", pady=3)
        ttk.Checkbutton(
            evidence_row,
            text="Require decision-relevant evidence for automatic Pi-hole changes",
            variable=self.require_research,
            command=self._changed,
        ).pack(side="left")
        self._info_button(
            evidence_row,
            "Evidence requirement",
            "The LLM result is still stored when no strong structured evidence exists, but "
            "automatic whitelist or blacklist changes remain blocked. Infrastructure "
            "context such as "
            "RDAP, DNS, ASN ownership, or Netcraft does not count as decision-relevant evidence.",
        ).pack(side="left", padx=(6, 0))

        mode_line = ttk.Frame(general)
        mode_line.grid(row=4, column=0, sticky="w", pady=3)
        ttk.Label(mode_line, text="Automation mode").pack(side="left")
        ttk.Combobox(
            mode_line,
            textvariable=self.mode,
            values=("manual", "hybrid", "auto"),
            state="readonly",
            width=20,
        ).pack(side="left", padx=(10, 0))
        self._info_button(
            mode_line,
            "Automation mode",
            "Manual never changes Pi-hole automatically. Hybrid requires the LLM recommendation "
            "and every applicable tag policy to agree. Auto uses the common tag policy even when "
            "the model's recommendation differs. Confidence, evidence, breakage, service role, "
            "and protected-entry safeguards still apply in both automatic modes.",
        ).pack(side="left", padx=(6, 0))

        simulation_row = ttk.Frame(general)
        simulation_row.grid(row=5, column=0, sticky="ew", pady=(6, 3))
        ttk.Checkbutton(
            simulation_row,
            text="Simulation mode — record automatic actions without changing Pi-hole",
            variable=self.simulation_mode,
            command=self._changed,
        ).pack(side="left")
        self._info_button(
            simulation_row,
            "Simulation mode",
            "Runs evidence collection, LLM classification, validation, tag policies, confidence "
            "checks, and the automatic decision engine normally. When a whitelist or "
            "blacklist action "
            "would be applied, it is stored as a planned action instead. You can review and apply "
            "planned actions later from Review Queue or Domain Database. Manual "
            "Whitelist/Blacklist "
            "buttons still "
            "change Pi-hole immediately.",
        ).pack(side="left", padx=(6, 0))

        grid = ttk.LabelFrame(self, text="Queue, requests, and rechecks", padding=10)
        grid.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        queue_group = ttk.LabelFrame(grid, text="Analysis queue and LLM requests", padding=8)
        queue_group.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        collector_group = ttk.LabelFrame(grid, text="Collection and rechecks", padding=8)
        collector_group.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        queue_fields = (
            (
                "Queue poll interval (s)",
                self.llm_interval,
                "How often the analysis worker checks again when the queue is empty or has "
                "not reached its automatic trigger. It is not the delay after an LLM reply.",
            ),
            (
                "Automatic queue trigger (domains)",
                self.queue_trigger,
                "Automatic jobs start immediately when at least this many domains are waiting. "
                "Manually queued domains bypass this threshold.",
            ),
            (
                "Maximum automatic queue wait (s)",
                self.max_queue_wait,
                "Starts a smaller automatic batch once the oldest waiting automatic item has "
                "reached this age, even if the queue trigger was not reached.",
            ),
            (
                "Domains claimed per worker cycle",
                self.worker_batch,
                "Maximum number of queued domains marked as processing in one cycle. They are "
                "then split into one or more LLM requests according to Domains per request.",
            ),
            (
                "Domains per LLM request",
                self.domains_per_request,
                "Maximum number of domain dossiers sent in a single LLM request.",
            ),
            (
                "Delay after completed LLM request (s)",
                self.min_request_interval,
                "Minimum pause measured from the completion of one LLM response before the "
                "next request starts.",
            ),
            (
                "Retries after a failed LLM request",
                self.max_retries,
                "Additional attempts after the first failed request. A value of 2 means up to "
                "three total attempts before the queue item is marked failed.",
            ),
        )
        collector_fields = (
            (
                "Query collector interval (s)",
                self.scan_interval,
                "How often the background collector asks Pi-hole for newer query-log rows.",
            ),
            (
                "Maximum query rows per collector cycle",
                self.scan_batch,
                "Maximum number of Pi-hole query rows requested in one collector cycle. This "
                "is not the number of unique domains sent to the LLM.",
            ),
            (
                "Excluded domain suffixes",
                self.excluded_suffixes,
                "Comma-separated suffixes that are never queued for analysis. The default "
                "'.arpa' excludes reverse-DNS and other infrastructure queries while keeping "
                "them visible in query history.",
            ),
            (
                "Fallback recheck age (days)",
                self.default_recheck_days,
                "Used only when no tag-specific recheck age is configured. A shorter recheck "
                "suggested by the model is still honored.",
            ),
            (
                "Review confidence threshold",
                self.review_threshold,
                "Below this confidence, the classification is explicitly sent to manual "
                "review. Between this value and the automatic threshold, it is stored only.",
            ),
            (
                "Automatic-action confidence threshold",
                self.auto_threshold,
                "Minimum confidence required before an automatic whitelist or blacklist action "
                "may be considered. Other safety checks still apply.",
            ),
            (
                "History backfill idle time (s)",
                self.history_idle_after,
                "How long live collection must remain idle before one historical query page is "
                "inspected for unclassified or stale domains.",
            ),
            (
                "History backfill lookback (days)",
                self.history_lookback_days,
                "Maximum age of Pi-hole query-log rows considered by idle backfill.",
            ),
            (
                "History rows per backfill cycle",
                self.history_batch_size,
                "Maximum number of historical query rows inspected in one idle collector cycle.",
            ),
        )
        self._build_option_column(queue_group, queue_fields)
        self._build_option_column(collector_group, collector_fields)

        group = ttk.LabelFrame(self, text="Tags, policies, and recheck ages", padding=8)
        group.grid(row=2, column=0, sticky="nsew", pady=(12, 0))
        group.columnconfigure(0, weight=1)
        group.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            group,
            columns=("tag", "policy", "recheck_days"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("tag", text="Tag")
        self.tree.heading("policy", text="Default policy")
        self.tree.heading("recheck_days", text="Recheck after days")
        self.tree.column("tag", width=300, anchor="w")
        self.tree.column("policy", width=170, anchor="w")
        self.tree.column("recheck_days", width=150, anchor="center")
        self.tree.grid(row=0, column=0, columnspan=4, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._selected)

        self.tag = tk.StringVar()
        self.policy = tk.StringVar(value="manual_review")
        self.tag_recheck = tk.StringVar(value="30")
        ttk.Entry(group, textvariable=self.tag).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Combobox(
            group,
            textvariable=self.policy,
            values=("whitelist", "blacklist", "manual_review"),
            state="readonly",
            width=20,
        ).grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Entry(group, textvariable=self.tag_recheck, width=12).grid(
            row=1, column=2, sticky="ew", padx=(0, 6), pady=(8, 0)
        )
        actions = ttk.Frame(group)
        actions.grid(row=1, column=3, sticky="e", pady=(8, 0))
        ttk.Button(actions, text="Add / update", command=self._upsert).pack(side="left")
        ttk.Button(actions, text="Remove", command=self._remove).pack(side="left", padx=(6, 0))

    def _build_option_column(self, parent: ttk.LabelFrame, fields: tuple) -> None:
        parent.columnconfigure(1, weight=1)
        for row, (label, variable, help_text) in enumerate(fields):
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
            value_row = ttk.Frame(parent)
            value_row.grid(row=row, column=1, sticky="w", padx=(10, 0), pady=3)
            width = 24 if variable is self.excluded_suffixes else 12
            ttk.Entry(value_row, textvariable=variable, width=width).pack(side="left")
            self._info_button(value_row, label, help_text).pack(side="left", padx=(4, 0))

    def set_change_callback(self, callback: Callable[[], None]) -> None:
        self._change_callback = callback

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

    def load(self, options: Options) -> None:
        self.llm_enabled.set(options.llm.enabled)
        self.scanner_enabled.set(options.scans.enabled)
        self.mode.set(options.llm.automation_mode)
        self.simulation_mode.set(options.llm.simulation_mode)
        self.llm_interval.set(str(options.llm.interval_sec))
        self.worker_batch.set(str(options.llm.worker_batch_size))
        self.domains_per_request.set(str(options.llm.domains_per_request))
        self.min_request_interval.set(str(options.llm.min_request_interval_sec))
        self.max_retries.set(str(options.llm.max_retries))
        self.default_recheck_days.set(str(options.llm.default_recheck_days))
        self.review_threshold.set(str(options.llm.review_confidence_threshold))
        self.auto_threshold.set(str(options.llm.auto_action_min_confidence))
        self.require_research.set(options.llm.require_research_for_auto_action)
        self.scan_interval.set(str(options.scans.interval_sec))
        self.scan_batch.set(str(options.scans.batch_size))
        self.queue_trigger.set(str(options.scans.queue_trigger_size))
        self.max_queue_wait.set(str(options.scans.max_queue_wait_sec))
        self.history_backfill_enabled.set(options.scans.history_backfill_enabled)
        self.history_idle_after.set(str(options.scans.history_idle_after_sec))
        self.history_lookback_days.set(str(options.scans.history_lookback_days))
        self.history_batch_size.set(str(options.scans.history_batch_size))
        self.excluded_suffixes.set(", ".join(options.scans.excluded_domain_suffixes))
        self.tree.delete(*self.tree.get_children())
        for tag in options.llm.tags:
            self.tree.insert(
                "",
                "end",
                iid=tag,
                values=(
                    tag,
                    policy_label(options.llm.tag_policies.get(tag, "manual_review")),
                    options.llm.tag_recheck_days.get(tag, options.llm.default_recheck_days),
                ),
            )

    def store(self, options: Options) -> bool:
        try:
            options.llm.interval_sec = int(self.llm_interval.get())
            options.llm.worker_batch_size = int(self.worker_batch.get())
            options.llm.domains_per_request = int(self.domains_per_request.get())
            options.llm.min_request_interval_sec = float(self.min_request_interval.get())
            options.llm.max_retries = int(self.max_retries.get())
            options.llm.default_recheck_days = int(self.default_recheck_days.get())
            options.llm.review_confidence_threshold = float(self.review_threshold.get())
            options.llm.auto_action_min_confidence = float(self.auto_threshold.get())
            options.scans.interval_sec = int(self.scan_interval.get())
            options.scans.batch_size = int(self.scan_batch.get())
            options.scans.queue_trigger_size = int(self.queue_trigger.get())
            options.scans.max_queue_wait_sec = int(self.max_queue_wait.get())
            options.scans.history_idle_after_sec = int(self.history_idle_after.get())
            options.scans.history_lookback_days = int(self.history_lookback_days.get())
            options.scans.history_batch_size = int(self.history_batch_size.get())
        except ValueError:
            messagebox.showerror(
                "Automation",
                "Intervals, batch sizes, retries, ages, and thresholds must be numbers.",
            )
            return False
        if options.llm.review_confidence_threshold > options.llm.auto_action_min_confidence:
            messagebox.showerror(
                "Automation",
                "The review confidence threshold cannot be higher than the automatic-action "
                "confidence threshold.",
            )
            return False
        options.llm.enabled = self.llm_enabled.get()
        options.scans.enabled = self.scanner_enabled.get()
        options.scans.history_backfill_enabled = self.history_backfill_enabled.get()
        options.scans.excluded_domain_suffixes = [
            item.strip() for item in self.excluded_suffixes.get().split(",") if item.strip()
        ]
        options.llm.automation_mode = self.mode.get()
        options.llm.simulation_mode = self.simulation_mode.get()
        options.llm.require_research_for_auto_action = self.require_research.get()
        rows = [self.tree.item(item, "values") for item in self.tree.get_children()]
        try:
            options.llm.tag_recheck_days = {str(row[0]): max(1, int(row[2])) for row in rows}
        except (ValueError, TypeError):
            messagebox.showerror(
                "Automation",
                "Every tag recheck age must be a positive whole number of days.",
            )
            return False
        options.llm.tags = [str(row[0]) for row in rows]
        options.llm.tag_policies = {str(row[0]): policy_value(str(row[1])) for row in rows}
        return True

    def _selected(self, _event: tk.Event | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        self.tag.set(str(values[0]))
        self.policy.set(policy_label(str(values[1])))
        self.tag_recheck.set(str(values[2]))

    def _upsert(self) -> None:
        tag = self.tag.get().strip().lower().replace(" ", "_")
        if not tag:
            return
        try:
            recheck_days = max(1, int(self.tag_recheck.get()))
        except ValueError:
            messagebox.showerror("Tag", "Recheck age must be a positive whole number.")
            return
        values = (tag, policy_label(self.policy.get()), recheck_days)
        if self.tree.exists(tag):
            self.tree.item(tag, values=values)
        else:
            self.tree.insert("", "end", iid=tag, values=values)
        self.tag.set("")
        self._changed()

    def _remove(self) -> None:
        selection = self.tree.selection()
        if selection:
            self.tree.delete(selection[0])
            self._changed()
