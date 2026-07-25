from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from pihole_manager.config import Options


class AutomationSettingsPage(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=12)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)

        self.llm_enabled = tk.BooleanVar()
        self.scanner_enabled = tk.BooleanVar()
        self.mode = tk.StringVar()
        self.llm_interval = tk.StringVar()
        self.llm_batch = tk.StringVar()
        self.scan_interval = tk.StringVar()
        self.scan_batch = tk.StringVar()

        ttk.Checkbutton(
            self,
            text="Enabled: run LLM analysis in the background",
            variable=self.llm_enabled,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Checkbutton(
            self,
            text="Continuously queue domains from live queries",
            variable=self.scanner_enabled,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Label(self, text="Automation mode").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Combobox(
            self,
            textvariable=self.mode,
            values=("manual", "hybrid", "auto"),
            state="readonly",
            width=20,
        ).grid(row=2, column=1, sticky="w", padx=(10, 0), pady=4)

        intervals = ttk.Frame(self)
        intervals.grid(row=3, column=0, columnspan=2, sticky="ew", pady=4)
        for label, variable in (
            ("LLM interval", self.llm_interval),
            ("LLM batch", self.llm_batch),
            ("Scan interval", self.scan_interval),
            ("Scan batch", self.scan_batch),
        ):
            ttk.Label(intervals, text=label).pack(side="left", padx=(0, 4))
            ttk.Entry(intervals, textvariable=variable, width=8).pack(
                side="left", padx=(0, 14)
            )

        group = ttk.LabelFrame(self, text="Categories and default policies", padding=8)
        group.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(12, 0))
        group.columnconfigure(0, weight=1)
        group.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            group,
            columns=("category", "policy"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("category", text="Category")
        self.tree.heading("policy", text="Default policy")
        self.tree.column("category", width=260, anchor="w")
        self.tree.column("policy", width=180, anchor="w")
        self.tree.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._selected)

        self.category = tk.StringVar()
        self.policy = tk.StringVar(value="manual_review")
        ttk.Entry(group, textvariable=self.category).grid(
            row=1, column=0, sticky="ew", pady=(8, 0)
        )
        ttk.Combobox(
            group,
            textvariable=self.policy,
            values=("allow", "deny", "manual_review"),
            state="readonly",
            width=20,
        ).grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        actions = ttk.Frame(group)
        actions.grid(row=1, column=2, sticky="e", pady=(8, 0))
        ttk.Button(actions, text="Add / update", command=self._upsert).pack(side="left")
        ttk.Button(actions, text="Remove", command=self._remove).pack(
            side="left", padx=(6, 0)
        )

    def load(self, options: Options) -> None:
        self.llm_enabled.set(options.llm.enabled)
        self.scanner_enabled.set(options.scans.enabled)
        self.mode.set(options.llm.automation_mode)
        self.llm_interval.set(str(options.llm.interval_sec))
        self.llm_batch.set(str(options.llm.batch_size))
        self.scan_interval.set(str(options.scans.interval_sec))
        self.scan_batch.set(str(options.scans.batch_size))
        self.tree.delete(*self.tree.get_children())
        for category in options.llm.categories:
            self.tree.insert(
                "",
                "end",
                iid=category,
                values=(category, options.llm.category_policies.get(category, "manual_review")),
            )

    def store(self, options: Options) -> bool:
        try:
            options.llm.interval_sec = int(self.llm_interval.get())
            options.llm.batch_size = int(self.llm_batch.get())
            options.scans.interval_sec = int(self.scan_interval.get())
            options.scans.batch_size = int(self.scan_batch.get())
        except ValueError:
            messagebox.showerror("Automation", "Intervals and batch sizes must be integers.")
            return False
        options.llm.enabled = self.llm_enabled.get()
        options.scans.enabled = self.scanner_enabled.get()
        options.llm.automation_mode = self.mode.get()
        rows = [self.tree.item(item, "values") for item in self.tree.get_children()]
        options.llm.categories = [str(row[0]) for row in rows]
        options.llm.category_policies = {str(row[0]): str(row[1]) for row in rows}
        return True

    def _selected(self, _event: tk.Event | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        self.category.set(str(values[0]))
        self.policy.set(str(values[1]))

    def _upsert(self) -> None:
        category = self.category.get().strip().lower()
        if not category:
            return
        if self.tree.exists(category):
            self.tree.item(category, values=(category, self.policy.get()))
        else:
            self.tree.insert("", "end", iid=category, values=(category, self.policy.get()))
        self.category.set("")

    def _remove(self) -> None:
        selection = self.tree.selection()
        if selection:
            self.tree.delete(selection[0])
