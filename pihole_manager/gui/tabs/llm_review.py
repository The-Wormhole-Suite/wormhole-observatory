from __future__ import annotations

import csv
import time
import tkinter as tk
from concurrent.futures import Future, ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk
from typing import Any

from pihole_manager.cancellation import CancellationToken, OperationCancelledError
from pihole_manager.database import (
    get_domain_lock,
    mark_action_applied,
    queue_domains_for_review,
    review_queue_get,
    review_resolve,
    review_save,
    staging_remove,
)
from pihole_manager.gui.column_visibility import ColumnVisibilityController
from pihole_manager.gui.domain_details import show_domain_details
from pihole_manager.gui.evidence_dialog import has_evidence, show_evidence
from pihole_manager.gui.feedback import show_toast
from pihole_manager.gui.policy_labels import action_label, policy_label, status_label
from pihole_manager.gui.tree_sorting import TreeSortController
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain
from pihole_manager.research import research_many
from pihole_manager.workers import cancel_classifier_jobs

_COLUMNS = (
    "selected",
    "order",
    "queued",
    "lock",
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
    "short",
    "status",
)

_HEADINGS = {
    "selected": "✓",
    "order": "#",
    "queued": "Queued",
    "lock": "Lock",
    "domain": "Domain",
    "tags": "Tags",
    "service": "Service",
    "role": "Role",
    "policy": "Policy",
    "planned": "Action",
    "confidence": "Conf.",
    "privacy": "Privacy",
    "security": "Security",
    "breakage": "Breakage risk",
    "short": "Description",
    "status": "Status",
}


class LLMReviewTab(ttk.Frame):
    def __init__(self, master: tk.Misc, executor: ThreadPoolExecutor) -> None:
        super().__init__(master)
        self.executor = executor
        self._rows: dict[str, dict[str, Any]] = {}
        self._checked: set[str] = set()
        self._evidence_cancel_token: CancellationToken | None = None
        self.status = tk.StringVar()
        self._build_ui()
        self.reload_preferences()
        self.after(300, self._refresh_loop)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(toolbar, text="Analyze selected", command=self._queue_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(
            toolbar,
            text="Collect evidence",
            command=self._collect_selected_evidence,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar,
            text="Cancel active",
            command=self._cancel_active_work,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Apply planned", command=self._apply_planned_selected).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(
            toolbar,
            text="Whitelist exact",
            command=lambda: self._apply_selected(Policy.ALLOW),
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar,
            text="Blacklist exact",
            command=lambda: self._apply_selected(Policy.DENY),
        ).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Details", command=self._show_selected_details).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(toolbar, text="Dismiss review", command=self._remove_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(toolbar, text="Export CSV", command=self._export_csv).pack(
            side="left", padx=(12, 0)
        )
        ttk.Button(toolbar, text="Import CSV", command=self._import_csv).pack(
            side="left", padx=(6, 0)
        )
        self.columns_button = ttk.Menubutton(toolbar, text="Columns")
        self.columns_button.pack(side="left", padx=(12, 0))
        ttk.Label(toolbar, textvariable=self.status).pack(side="right")

        tree_frame = ttk.Frame(self, padding=(8, 0, 8, 8))
        tree_frame.pack(fill="both", expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
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
        for column, heading in _HEADINGS.items():
            self.tree.heading(column, text=heading)
        widths = {
            "selected": 38,
            "order": 48,
            "queued": 115,
            "lock": 48,
            "domain": 250,
            "tags": 230,
            "service": 180,
            "role": 80,
            "policy": 105,
            "planned": 95,
            "confidence": 65,
            "privacy": 65,
            "security": 65,
            "breakage": 90,
            "short": 300,
            "status": 120,
        }
        centered = {
            "selected",
            "order",
            "queued",
            "lock",
            "role",
            "policy",
            "planned",
            "confidence",
            "privacy",
            "security",
            "breakage",
            "status",
        }
        for column, width in widths.items():
            self.tree.column(
                column,
                width=width,
                stretch=column not in {"selected", "order", "lock"},
                anchor="center" if column in centered else "w",
            )
        self.tree.bind("<Button-1>", self._toggle_checkbox, add=True)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Double-1>", lambda _event: self._show_selected_details())

        self.column_controller = ColumnVisibilityController(
            self.columns_button,
            self.tree,
            table_key="review",
            columns=_COLUMNS,
            headings=_HEADINGS,
        )
        self.sort_controller = TreeSortController(
            self.tree,
            headings=_HEADINGS,
            parsers={
                "order": _parse_number,
                "queued": str.casefold,
                "domain": str.casefold,
                "tags": str.casefold,
                "service": str.casefold,
                "role": str.casefold,
                "policy": str.casefold,
                "planned": str.casefold,
                "confidence": _parse_number,
                "privacy": _parse_number,
                "security": _parse_number,
                "breakage": _parse_number,
                "short": str.casefold,
                "status": str.casefold,
            },
            default_column="order",
        )
        self.column_controller.menu.add_separator()
        self.column_controller.menu.add_command(
            label="Reset sort",
            command=self.sort_controller.reset,
        )

        self.context_menu = tk.Menu(self, tearoff=False)
        self.context_menu.add_command(label="Show evidence", command=self._show_context_evidence)
        self.context_menu.add_command(
            label="Collect and show evidence",
            command=self._collect_and_show_context_evidence,
        )
        self.context_menu.add_command(
            label="Run full review",
            command=self._run_context_full_review,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Analyze", command=self._queue_context_domain)
        self.context_menu.add_command(label="Domain details", command=self._show_context_details)
        self._context_domain = ""

    def reload_preferences(self) -> None:
        self._update_status()
        self.column_controller.reload()

    def _update_status(self) -> None:
        from pihole_manager.config import load_options

        options = load_options()
        state = "enabled" if options.llm.enabled else "disabled"
        simulation = "on" if options.llm.simulation_mode else "off"
        research_count = sum(1 for provider in options.research_providers if provider.enabled)
        self.status.set(
            f"{len(self._rows)} pending · LLM {state} · simulation {simulation} · "
            f"evidence sources {research_count}"
        )

    def _refresh_loop(self) -> None:
        self.refresh()
        self.after(2_000, self._refresh_loop)

    def refresh(self) -> None:
        rows = review_queue_get(limit=2_000)
        current_selection = {
            self.tree.set(item, "domain")
            for item in self.tree.selection()
            if self.tree.set(item, "domain")
        }
        self._rows = {str(row["domain"]): row for row in rows}
        self._checked.intersection_update(self._rows)
        self.tree.delete(*self.tree.get_children())
        for position, row in enumerate(rows, start=1):
            domain = str(row.get("domain") or "")
            checked = domain in self._checked
            self.tree.insert(
                "",
                "end",
                iid=domain,
                values=(
                    "☑" if checked else "☐",
                    position,
                    _format_short_timestamp(row.get("queue_created_at") or row.get("updated_at")),
                    "🔒" if row.get("locked") else "",
                    domain,
                    ",".join(row.get("tags") or row.get("categories") or []),
                    row.get("service", ""),
                    row.get("service_role", "unknown"),
                    policy_label(row.get("policy", "unknown")),
                    _format_action(row),
                    _format_confidence(row),
                    _format_risk(row, "privacy_risk"),
                    _format_risk(row, "security_risk"),
                    _format_risk(row, "breakage_risk"),
                    row.get("short", ""),
                    status_label(row.get("status", "")),
                ),
            )
        self.sort_controller.apply()
        for domain in current_selection:
            if self.tree.exists(domain):
                self.tree.selection_add(domain)
        self._update_status()

    def _toggle_checkbox(self, event: tk.Event) -> None:
        if self.column_controller.displayed_column_at(event.x) != "selected":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        domain = self.tree.set(item, "domain")
        if domain in self._checked:
            self._checked.remove(domain)
            self.tree.set(item, "selected", "☐")
        else:
            self._checked.add(domain)
            self.tree.set(item, "selected", "☑")

    def _show_context_menu(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        self.tree.focus(item)
        self._context_domain = self.tree.set(item, "domain")
        state = "normal" if has_evidence(self._context_domain) else "disabled"
        self.context_menu.entryconfigure(0, state=state)
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _selected_domains(self) -> list[str]:
        if self._checked:
            return sorted(self._checked.intersection(self._rows))
        return sorted(
            {
                self.tree.set(item, "domain")
                for item in self.tree.selection()
                if self.tree.set(item, "domain")
            }
        )

    def _queue_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        self._queue_domains(domains, source="manual_review_queue")

    def _queue_context_domain(self) -> None:
        if self._context_domain:
            self._queue_domains([self._context_domain], source="manual_review_queue")

    def _queue_domains(self, domains: list[str], *, source: str) -> None:
        result = queue_domains_for_review(domains, source=source)
        parts = []
        if result.queued:
            parts.append(f"{result.queued} queued")
        if result.requeued:
            parts.append(f"{result.requeued} requeued")
        if result.already_pending:
            parts.append(f"{result.already_pending} already pending")
        if result.skipped_locked:
            parts.append(f"{result.skipped_locked} protected")
        if result.skipped_filtered:
            parts.append(f"{result.skipped_filtered} filtered")
        show_toast(self, ", ".join(parts) or "No domains queued.")
        self.refresh()

    def _collect_selected_evidence(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        self._start_evidence_collection(domains)

    def _show_context_evidence(self) -> None:
        if self._context_domain:
            show_evidence(self, self._context_domain)

    def _collect_and_show_context_evidence(self) -> None:
        if self._context_domain:
            self._start_evidence_collection(
                [self._context_domain],
                show_domain=self._context_domain,
            )

    def _run_context_full_review(self) -> None:
        if self._context_domain:
            self._start_evidence_collection(
                [self._context_domain],
                queue_domain=self._context_domain,
            )

    def _start_evidence_collection(
        self,
        domains: list[str],
        *,
        show_domain: str = "",
        queue_domain: str = "",
    ) -> None:
        if self._evidence_cancel_token is not None:
            show_toast(self, "Evidence collection is already running.")
            return
        token = CancellationToken()
        self._evidence_cancel_token = token
        self.status.set(f"Collecting evidence for {len(domains)} domain(s) …")
        future = self.executor.submit(self._collect_evidence, domains, token)
        future.add_done_callback(
            lambda item: self.after(
                0,
                self._evidence_collection_done,
                item,
                token,
                show_domain,
                queue_domain,
            )
        )

    @staticmethod
    def _collect_evidence(
        domains: list[str],
        cancel_token: CancellationToken,
    ) -> tuple[int, list[str]]:
        errors: list[str] = []
        unlocked: list[str] = []
        for domain in domains:
            cancel_token.raise_if_cancelled()
            if get_domain_lock(domain) is not None:
                errors.append(f"{domain}: protected domain")
            else:
                unlocked.append(domain)
        findings = research_many(unlocked, force=True, cancel_token=cancel_token)
        return sum(len(items) for items in findings.values()), errors

    def _cancel_active_work(self) -> None:
        self.cancel_active_work()

    def cancel_active_work(self, *, notify: bool = True) -> int:
        cancelled = cancel_classifier_jobs()
        if self._evidence_cancel_token is not None:
            self._evidence_cancel_token.cancel()
            cancelled += 1
        if cancelled:
            self.status.set("Cancelling active analysis/evidence jobs …")
            if notify:
                show_toast(self, f"Cancellation requested for {cancelled} active job(s).")
        elif notify:
            show_toast(self, "No active analysis or evidence job to cancel.")
        return cancelled

    def _evidence_collection_done(
        self,
        future: Future,
        token: CancellationToken,
        show_domain: str,
        queue_domain: str,
    ) -> None:
        if self._evidence_cancel_token is token:
            self._evidence_cancel_token = None
        try:
            count, errors = future.result()
        except OperationCancelledError:
            self.status.set("Evidence collection cancelled")
            show_toast(self, "Evidence collection cancelled.")
            return
        except Exception as exc:
            self.status.set("Evidence collection failed")
            show_toast(self, f"Evidence collection failed: {exc}", duration_ms=3500)
            return

        message = f"Collected {count} evidence finding(s)"
        if errors:
            message += f" · {len(errors)} domain(s) had source errors"
        self.status.set(message)
        show_toast(self, message)

        if queue_domain:
            self._queue_domains(
                [queue_domain],
                source="manual_full_review",
            )
        if show_domain:
            show_evidence(self, show_domain)
        self.refresh()

    def _show_context_details(self) -> None:
        if self._context_domain:
            show_domain_details(self, self._context_domain)

    def _apply_planned_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("LLM Review", "Select or check at least one domain.")
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
            messagebox.showerror("LLM Review", str(exc))
            return
        if errors:
            messagebox.showwarning(
                "LLM Review",
                f"Applied {applied} planned action(s). Some failed:\n" + "\n".join(errors[:10]),
            )
        else:
            messagebox.showinfo("LLM Review", f"Applied {applied} planned action(s).")
        self._checked.difference_update(self._selected_domains())
        self.refresh()

    def _apply_selected(self, policy: Policy) -> None:
        domains = self._selected_domains()
        if not domains:
            messagebox.showinfo("LLM Review", "Select or check at least one domain.")
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
            messagebox.showerror("LLM Review", str(exc))
            return
        if errors:
            messagebox.showwarning("LLM Review", "Some actions failed:\n" + "\n".join(errors[:10]))
        else:
            messagebox.showinfo("LLM Review", f"Applied {action_label(policy)} to the selection.")

    def _remove_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        staging_remove(domains)
        review_resolve(domains)
        self._checked.difference_update(domains)
        self.refresh()

    def _show_selected_details(self) -> None:
        domains = self._selected_domains()
        if domains:
            show_domain_details(self, domains[0])

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export LLM review",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        fields = [
            "domain",
            "tags",
            "service",
            "service_role",
            "policy",
            "planned_action",
            "action_status",
            "confidence",
            "privacy_risk",
            "security_risk",
            "breakage_risk",
            "needs_review",
            "review_reason",
            "short",
            "details",
            "provider",
            "status",
        ]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in self._rows.values():
                writer.writerow(
                    {
                        key: ",".join(row.get("tags") or []) if key == "tags" else row.get(key, "")
                        for key in fields
                    }
                )

    def _import_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Import LLM review",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                domain = str(row.get("domain") or "").strip()
                if not domain:
                    continue
                review_save(
                    domain,
                    row.get("tags") or "",
                    row.get("details") or "",
                    row.get("status") or "imported",
                    policy=row.get("policy") or "unknown",
                    short=row.get("short") or "",
                    provider=row.get("provider") or "",
                    service=row.get("service") or "",
                    service_role=row.get("service_role") or "unknown",
                    privacy_risk=_int(row.get("privacy_risk"), 0),
                    security_risk=_int(row.get("security_risk"), 0),
                    breakage_risk=_int(row.get("breakage_risk"), 50),
                    confidence=_float(row.get("confidence"), 0.0),
                    needs_review=str(row.get("needs_review") or "true").lower()
                    not in {"false", "0", "no"},
                    review_reason=row.get("review_reason") or "",
                    planned_action=row.get("planned_action") or "",
                    action_status=row.get("action_status") or "none",
                )
        self.refresh()


def _has_classification(row: dict[str, Any]) -> bool:
    policy = str(row.get("policy") or "unknown")
    return bool(row.get("provider")) or policy not in {"", "unknown"}


def _format_confidence(row: dict[str, Any]) -> str:
    if not _has_classification(row):
        return "—"
    return f"{float(row.get('confidence') or 0.0):.2f}"


def _format_risk(row: dict[str, Any], key: str) -> str:
    if not _has_classification(row):
        return "—"
    value = row.get(key)
    return "—" if value is None else str(int(value))


def _format_action(row: dict[str, Any]) -> str:
    action = str(row.get("planned_action") or "")
    state = str(row.get("action_status") or "none")
    if action not in {Policy.ALLOW.value, Policy.DENY.value}:
        return ""
    return f"{policy_label(action)} · {state}"


def _format_short_timestamp(value: Any) -> str:
    try:
        timestamp = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if timestamp <= 0:
        return ""
    return time.strftime("%m-%d %H:%M:%S", time.localtime(timestamp))


def _parse_number(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _int(value: Any, default: int) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
