from __future__ import annotations

import time
from tkinter import messagebox, simpledialog, ttk

from pihole_manager.gui.feedback import show_toast
from pihole_manager.gui.tabs.llm_review import LLMReviewTab
from pihole_manager.models import Policy
from pihole_manager.review_decisions import apply_review_decision


class ReviewDecisionTab(LLMReviewTab):
    def _build_ui(self) -> None:
        super()._build_ui()
        decisions = ttk.Frame(self, padding=(8, 0, 8, 8))
        decisions.pack(fill="x")
        ttk.Label(decisions, text="Review decisions:").pack(side="left")
        ttk.Button(decisions, text="Postpone…", command=self._postpone_selected).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(decisions, text="Never ask again", command=self._never_ask_selected).pack(
            side="left", padx=(6, 0)
        )

    def _apply_planned_domains(self, domains: list[str]) -> tuple[int, list[str]]:
        applied = 0
        errors: list[str] = []
        for domain in domains:
            action = str(self._rows.get(domain, {}).get("planned_action") or "")
            if action not in {Policy.ALLOW.value, Policy.DENY.value}:
                errors.append(f"{domain}: no simulated whitelist/blacklist action")
                continue
            try:
                comment = str(self._rows.get(domain, {}).get("short") or "")
                apply_review_decision(domain, action, comment=comment)
                applied += 1
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return applied, errors

    def _apply_domains(self, domains: list[str], policy: Policy) -> list[str]:
        errors: list[str] = []
        for domain in domains:
            try:
                comment = str(self._rows.get(domain, {}).get("short") or "")
                apply_review_decision(domain, policy.value, comment=comment)
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        return errors

    def _remove_selected(self) -> None:
        self._apply_local_decision("ignore")

    def _postpone_selected(self) -> None:
        hours = simpledialog.askinteger(
            "Postpone review",
            "Hide the selected review(s) for how many hours?",
            initialvalue=24,
            minvalue=1,
            maxvalue=24 * 365,
            parent=self,
        )
        if hours is None:
            return
        self._apply_local_decision(
            "postpone",
            postpone_until=int(time.time()) + int(hours) * 3600,
        )

    def _never_ask_selected(self) -> None:
        domains = self._selected_domains()
        if not domains:
            show_toast(self, "Select or check at least one domain.")
            return
        if not messagebox.askyesno(
            "Never ask again",
            f"Suppress future review prompts for {len(domains)} selected domain(s)?",
            parent=self,
        ):
            return
        self._apply_local_decision("never_ask", domains=domains)

    def _apply_local_decision(
        self,
        decision: str,
        *,
        postpone_until: int | None = None,
        domains: list[str] | None = None,
    ) -> None:
        selected = domains or self._selected_domains()
        if not selected:
            show_toast(self, "Select or check at least one domain.")
            return
        errors: list[str] = []
        for domain in selected:
            try:
                apply_review_decision(
                    domain,
                    decision,
                    postpone_until=postpone_until,
                )
            except Exception as exc:
                errors.append(f"{domain}: {exc}")
        self._checked.difference_update(selected)
        self.refresh()
        if errors:
            messagebox.showwarning(
                "LLM Review",
                "Some decisions failed:\n" + "\n".join(errors[:10]),
                parent=self,
            )
