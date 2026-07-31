from __future__ import annotations

import time
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import messagebox, ttk
from typing import Any

from pihole_manager.database import (
    domain_browser_search,
    get_domain_lock,
    mark_action_applied,
    queue_domains_for_review,
)
from pihole_manager.gui.column_visibility import ColumnVisibilityController
from pihole_manager.gui.domain_details import show_domain_details
from pihole_manager.gui.policy_labels import action_label, policy_label, policy_value
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain
from pihole_manager.research import research_many

_COLUMNS = (
    "domain",
    "tags",
    "service",
    "role",
    "policy",
    "planned",
    "confidence",
    "privacy",
    "security",
    "breakage",
    "queries",
    "last_seen",
    "classified",
    "recheck",
    "review",
    "lock",
    "provider",
    "short",
)

_HEADINGS = {
    "domain": "Domain",
    "tags": "Tags",
    "service": "Service",
    "role": "Role",
    "policy": "Policy",
    "planned": "Action",
    "confidence": "Conf.",
    "privacy": "Privacy",
    "security": "Security",
    "breakage": "Breakage",
    "queries": "Queries",
    "last_seen": "Last seen",
    "classified": "Classified",
    "recheck": "Recheck",
    "review": "Review",
    "lock": "Lock",
    "provider": "Provider",
    "short": "Description",
}


class DomainsTab(ttk.Frame):
    PAGE_SIZE = 500

    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self.search_text = tk.StringVar()
        self.policy_filter = tk.StringVar(value="all")
        self.tag_filter = tk.StringVar()
        self.role_filter = tk.StringVar(value="all")
        self.review_filter = tk.StringVar(value="all")
        self.status = tk.StringVar(value="Idle")
        self._rows: dict[str, dict[str, Any]] = {}
        self._offset = 0
        self._total = 0
        self._request_running = False
        self._build_ui()
        self.after(250, self.refresh)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Search").pack(side="left")
        search = ttk.Entry(toolbar, textvariable=self.search_text, width=28)
        search.pack(side="left", padx=(5, 10))
        search.bind("<Return>", lambda _event: self._new_search())

        ttk.Label(toolbar, text="Policy").pack(side="left")
        policy = ttk.Combobox(
            toolbar,
            textvariable=self.policy_filter,
            values=("all", "whitelist", "blacklist", "manual_review", "unknown"),
            state="readonly",
            width=14,
        )
        policy.pack(side="left", padx=(5, 10))
        policy.bind("<<ComboboxSelected>>", lambda _event: self._new_search())

        ttk.Label(toolbar, text="Tag").pack(side="left")
        tag = ttk.Entry(toolbar, textvariable=self.tag_filter, width=18)
        tag.pack(side="left", padx=(5, 10))
        tag.bind("<Return>", lambda _event: self._new_search())

        ttk.Label(toolbar, text="Role").pack(side="left")
        role = ttk.Combobox(
            toolbar,
            textvariable=self.role_filter,
            values=("all", "core", "optional", "shared", "unknown"),
            state="readonly",
            width=10,
        )
        role.pack(side="left", padx=(5, 10))
        role.bind("<<ComboboxSelected>>", lambda _event: self._new_search())

        ttk.Label(toolbar, text="Review").pack(side="left")
        review = ttk.Combobox(
            toolbar,
            textvariable=self.review_filter,
            values=("all", "required", "not_required", "overdue"),
            state="readonly",
            width=12,
        )
        review.pack(side="left", padx=(5, 10))
        review.bind("<<ComboboxSelected>>", lambda _event: self._new_search())

        ttk.Button(toolbar, text="Search", command=self._new_search).pack(side="left")
        ttk.Button(toolbar, text="Reset", command=self._reset_filters).pack(
            side="left", padx=(6, 0)
        )

        actions = ttk.Frame(self, padding=(8, 0, 8, 6))
        actions.pack(fill="x")
        ttk.Button(actions, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(actions, text="Re-analyze selected", command=self._queue_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Re-collect evidence", command=self._research_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            actions,
            text="Apply planned",
            command=self._apply_planned_selected,
        ).pack(side="left", padx=(12, 0))
        ttk.Button(actions, text="Previous", command=self._previous_page).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Next", command=self._next_page).pack(side="left", padx=(6, 0))
        ttk.Button(
            actions,
            text="Whitelist exact",
            command=lambda: self._apply_selected(Policy.ALLOW),
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            actions,
            text="Blacklist exact",
            command=lambda: self._apply_selected(Policy.DENY),
        ).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Details", command=self._show_details).pack(
            side="left", padx=(12, 0)
        )

        self.columns_button = ttk.Menubutton(actions, text="Columns")
        self.columns_button.pack(side="left", padx=(12, 0))
        ttk.Label(actions, textvariable=self.status).pack(side="right", padx=(0, 14))

        tree_frame = ttk.Frame(self, padding=(8, 0, 8, 8))
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            tree_frame,
            columns=_COLUMNS,
            show="headings",
            selectmode="extended",
        )
        vertical = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        for column, heading in _HEADINGS.items():
            self.tree.heading(column, text=heading)
            self.tree.column(
                column,
                anchor="center"
                if column
                in {
                    "role",
                    "policy",
                    "planned",
                    "confidence",
                    "privacy",
                    "security",
                    "breakage",
                    "queries",
                    "review",
                    "lock",
                }
                else "w",
            )
        self.tree.bind("<Double-1>", lambda _event: self._show_details())

        self.column_controller = ColumnVisibilityController(
            self.columns_button,
            self.tree,
            table_key="domains",
            columns=_COLUMNS,
            headings=_HEADINGS,
        )

    def reload_preferences(self) -> None:
        self.column_controller.reload()

    def _new_search(self) -> None:
        self._offset = 0
        self.refresh()

    def _reset_filters(self) -> None:
        self.search_text.set("")
        self.policy_filter.set("all")
        self.tag_filter.set("")
        self.role_filter.set("all")
        self.review_filter.set("all")
        self._new_search()

    def refresh(self) -> None:
        if self._request_running:
            return
        self._request_running = True
        self.status.set("Loading …")
        future = self.executor.submit(
            domain_browser_search,
            search=self.search_text.get(),
            policy=policy_value(self.policy_filter.get()),
            tag=self.tag_filter.get(),
            service_role=self.role_filter.get(),
            review_state=self.review_filter.get(),
            limit=self.PAGE_SIZE,
            offset=self._offset,
        )
        future.add_done_callback(lambda item: self.after(0, self._refresh_done, item))

    def _refresh_done(self, future: Future) -> None:
        self._request_running = False
        try:
            rows, total = future.result()
        except Exception as exc:
            self.status.set(f"Error: {exc}")
            return
        self._rows = {str(row["domain"]): row for row in rows}
        self._total = total
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            domain = str(row.get("domain") or "")
            self.tree.insert(
                "",
                "end",
                iid=domain,
                values=(
                    domain,
                    ",".join(row.get("tags") or []),
                    row.get("service", ""),
                    row.get("service_role", "unknown"),
                    policy_label(row.get("policy", "unknown")),
                    _format_action(row),
                    f"{float(row.get('confidence') or 0):.2f}",
                    row.get("privacy_risk", 0),
                    row.get("security_risk", 0),
                    row.get("breakage_risk", 50),
                    row.get("query_count", 0),
                    _format_timestamp(row.get("last_seen")),
                    _format_timestamp(row.get("last_classified_at")),
                    _format_timestamp(row.get("next_recheck_at")),
                    "yes" if row.get("needs_review") else "no",
                    row.get("lock_type", ""),
                    row.get("provider", ""),
                    row.get("short", ""),
                ),
            )
        start = 0 if not rows else self._offset + 1
        end = self._offset + len(rows)
        self.status.set(f"{start}–{end} of {total} classified domains")

    def _selected_domains(self) -> list[str]:
        return [
            self.tree.set(item, "domain")
            for item in self.tree.selection()
            if self.tree.set(item, "domain")
        ]

    def _previous_page(self) -> None:
        if self._offset <= 0:
            return
        self._offset = max(0, self._offset - self.PAGE_SIZE)
        self.refresh()

    def _next_page(self) -> None:
        if self._offset + self.PAGE_SIZE >= self._total:
            return
        self._offset += self.PAGE_SIZE
        self.refresh()

    def _queue_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Domain Database", "Select at least one domain.")
            return
        result = queue_domains_for_review(domains, source="manual_domain_browser")
        parts = []
        if result.queued:
            parts.append(f"{result.queued} newly queued")
        if result.requeued:
            parts.append(f"{result.requeued} requeued")
        if result.already_pending:
            parts.append(f"{result.already_pending} already pending")
        if result.skipped_locked:
            parts.append(f"{result.skipped_locked} protected")
        if result.skipped_filtered:
            parts.append(f"{result.skipped_filtered} filtered")
        messagebox.showinfo(
            "Domain Database",
            (", ".join(parts) or "No domains queued") + ".",
        )

    def _research_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Domain Database", "Select at least one domain.")
            return
        self.status.set("Collecting evidence for selected domains …")
        future = self.executor.submit(self._research_domains, domains)
        future.add_done_callback(lambda item: self.after(0, self._research_done, item))

    @staticmethod
    def _research_domains(domains: list[str]) -> tuple[int, list[str]]:
        errors: list[str] = []
        unlocked: list[str] = []
        for domain in domains:
            if get_domain_lock(domain) is not None:
                errors.append(f"{domain}: protected domain")
            else:
                unlocked.append(domain)
        findings = research_many(unlocked, force=True)
        return sum(len(items) for items in findings.values()), errors

    def _research_done(self, future: Future) -> None:
        try:
            count, errors = future.result()
        except Exception as exc:
            self.status.set(f"Evidence collection failed: {exc}")
            return
        self.status.set(f"Collected {count} evidence finding(s)")
        if errors:
            messagebox.showwarning("Evidence", "Some sources failed:\n" + "\n".join(errors[:10]))
        self.refresh()

    def _apply_planned_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Domain Database", "Select at least one domain.")
            return
        future = self.executor.submit(self._apply_planned_domains, domains)
        future.add_done_callback(lambda item: self.after(0, self._apply_planned_done, item))

    def _apply_planned_domains(self, domains: list[str]) -> tuple[int, list[str]]:
        applied = 0
        errors: list[str] = []
        for domain in domains:
            action = str(self._rows.get(domain, {}).get("planned_action") or "")
            if action not in {Policy.ALLOW.value, Policy.DENY.value}:
                errors.append(f"{domain}: no simulated whitelist/blacklist action")
                continue
            try:
                policy = Policy(action)
                comment = str(self._rows.get(domain, {}).get("short") or "")
                add_exact_domain(domain, policy, comment)
                mark_action_applied(domain, action)
                applied += 1
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return applied, errors

    def _apply_planned_done(self, future: Future) -> None:
        try:
            applied, errors = future.result()
        except Exception as exc:
            messagebox.showerror("Domain Database", str(exc))
            return
        if errors:
            messagebox.showwarning(
                "Domain Database",
                f"Applied {applied} planned action(s). Some failed:\n" + "\n".join(errors[:10]),
            )
        else:
            messagebox.showinfo(
                "Domain Database",
                f"Applied {applied} planned action(s).",
            )
        self.refresh()

    def _apply_selected(self, policy: Policy) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("Domain Database", "Select at least one domain.")
            return
        future = self.executor.submit(self._apply_domains, domains, policy)
        future.add_done_callback(lambda item: self.after(0, self._apply_done, item, policy))

    def _apply_domains(self, domains: list[str], policy: Policy) -> list[str]:
        errors: list[str] = []
        for domain in domains:
            try:
                comment = str(self._rows.get(domain, {}).get("short") or "")
                add_exact_domain(domain, policy, comment)
                mark_action_applied(domain, policy.value)
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return errors

    def _apply_done(self, future: Future, policy: Policy) -> None:
        try:
            errors = future.result()
        except Exception as exc:
            messagebox.showerror("Domain Database", str(exc))
            return
        if errors:
            messagebox.showwarning(
                "Domain Database",
                "Some actions failed:\n" + "\n".join(errors[:10]),
            )
        else:
            messagebox.showinfo(
                "Domain Database",
                f"Applied {action_label(policy)} to the selection.",
            )

    def _show_details(self) -> None:
        domains = self._selected_domains()
        if domains:
            show_domain_details(self, domains[0])


def _format_action(row: dict[str, Any]) -> str:
    action = str(row.get("planned_action") or "")
    state = str(row.get("action_status") or "none")
    if action not in {Policy.ALLOW.value, Policy.DENY.value}:
        return ""
    return f"{policy_label(action)} · {state}"


def _format_timestamp(value: Any) -> str:
    try:
        timestamp = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if timestamp <= 0:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))
