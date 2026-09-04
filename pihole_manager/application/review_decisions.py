from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pihole_manager.models import Policy

VALID_REVIEW_DECISIONS = frozenset({"allow", "deny", "postpone", "ignore", "never_ask"})


class InvalidReviewDecision(ValueError):
    """The requested review decision is not valid application input."""


class ReviewDecisionConflict(RuntimeError):
    """The decision was valid but could not be applied to current state."""


@dataclass(frozen=True, slots=True)
class ReviewDecisionCommand:
    """Frontend-neutral command for one domain review decision."""

    domain: str
    decision: str
    postpone_until: int | None = None
    comment: str = ""


@dataclass(frozen=True, slots=True)
class ReviewDecisionResult:
    """Canonical result returned to every review-decision frontend."""

    domain: str
    decision: str
    applied: bool
    preference: dict[str, Any]
    postpone_until: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "domain": self.domain,
            "decision": self.decision,
            "applied": self.applied,
            "preference": self.preference,
        }
        if self.postpone_until is not None:
            payload["postpone_until"] = self.postpone_until
        return payload


@dataclass(frozen=True, slots=True)
class ReviewDecisionPorts:
    """Infrastructure operations required by the application service."""

    fetch_exact_domains: Callable[[str], list[dict[str, Any]]]
    add_exact_domain: Callable[..., Any]
    delete_exact_domain: Callable[[str, str], Any]
    mark_action_applied: Callable[[str, str], Any]
    staging_remove: Callable[[list[str]], Any]
    resolve_review: Callable[..., Any]
    set_review_preference: Callable[..., dict[str, Any]]
    resolve_open_review_tasks: Callable[[str, str], None]
    clock: Callable[[], float]


class ReviewDecisionApplicationService:
    """Canonical review-decision behavior shared by Tk and HTTP frontends."""

    def __init__(self, ports: ReviewDecisionPorts) -> None:
        self._ports = ports

    def execute(self, command: ReviewDecisionCommand) -> ReviewDecisionResult:
        normalized = command.domain.strip().lower().rstrip(".")
        selected = str(command.decision or "").strip().lower()
        if not normalized:
            raise InvalidReviewDecision("domain must not be empty")
        if selected not in VALID_REVIEW_DECISIONS:
            raise InvalidReviewDecision(
                "decision must be allow, deny, postpone, ignore, or never_ask"
            )

        try:
            return self._execute_validated(
                normalized,
                selected,
                postpone_until=command.postpone_until,
                comment=command.comment,
            )
        except InvalidReviewDecision:
            raise
        except ReviewDecisionConflict:
            raise
        except RuntimeError as exc:
            raise ReviewDecisionConflict(str(exc)) from exc

    def _exact_rule_exists(self, domain: str, policy: str) -> bool:
        return any(
            str(row.get("domain") or "") == domain
            for row in self._ports.fetch_exact_domains(policy)
        )

    def _execute_validated(
        self,
        domain: str,
        decision: str,
        *,
        postpone_until: int | None,
        comment: str,
    ) -> ReviewDecisionResult:
        if decision in {"allow", "deny"}:
            policy = Policy.ALLOW if decision == "allow" else Policy.DENY
            opposite = "deny" if decision == "allow" else "allow"
            desired_exists = self._exact_rule_exists(domain, decision)
            opposite_exists = self._exact_rule_exists(domain, opposite)
            if not desired_exists:
                self._ports.add_exact_domain(
                    domain,
                    policy,
                    comment=comment.strip() or f"Review decision: {decision}",
                )
            if opposite_exists:
                self._ports.delete_exact_domain(domain, opposite)
            self._ports.mark_action_applied(domain, decision)
            self._ports.staging_remove([domain])
            preference = self._ports.set_review_preference(
                domain,
                last_decision=decision,
            )
            return ReviewDecisionResult(
                domain=domain,
                decision=decision,
                applied=True,
                preference=preference,
            )

        if decision == "ignore":
            self._ports.staging_remove([domain])
            self._ports.resolve_review([domain], decision="ignored")
            preference = self._ports.set_review_preference(
                domain,
                last_decision="ignore",
            )
            return ReviewDecisionResult(
                domain=domain,
                decision=decision,
                applied=True,
                preference=preference,
            )

        if decision == "postpone":
            if postpone_until is None:
                raise InvalidReviewDecision("postpone_until is required for postpone")
            try:
                postponed = int(postpone_until)
            except (TypeError, ValueError) as exc:
                raise InvalidReviewDecision("postpone_until must be an integer") from exc
            if postponed <= int(self._ports.clock()):
                raise InvalidReviewDecision("postpone_until must be in the future")
            self._ports.staging_remove([domain])
            self._ports.resolve_open_review_tasks(domain, "postponed")
            preference = self._ports.set_review_preference(
                domain,
                postponed_until=postponed,
                last_decision="postpone",
            )
            return ReviewDecisionResult(
                domain=domain,
                decision=decision,
                applied=True,
                preference=preference,
                postpone_until=postponed,
            )

        self._ports.staging_remove([domain])
        self._ports.resolve_open_review_tasks(domain, "never_ask")
        preference = self._ports.set_review_preference(
            domain,
            never_ask=True,
            last_decision="never_ask",
        )
        return ReviewDecisionResult(
            domain=domain,
            decision=decision,
            applied=True,
            preference=preference,
        )
