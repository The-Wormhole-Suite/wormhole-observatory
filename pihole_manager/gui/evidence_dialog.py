from __future__ import annotations

import time
import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import Any

from pihole_manager.database import research_findings_get

_COLUMNS = (
    "source",
    "signal",
    "verdict",
    "confidence",
    "decision",
    "collected",
    "expires",
    "summary",
)

_HEADINGS = {
    "source": "Source",
    "signal": "Signal",
    "verdict": "Verdict",
    "confidence": "Confidence",
    "decision": "Policy evidence",
    "collected": "Collected",
    "expires": "Fresh until",
    "summary": "Summary",
}


def has_evidence(domain: str) -> bool:
    return bool(research_findings_get(domain, limit=1))


def show_evidence(parent: tk.Misc, domain: str) -> None:
    findings = research_findings_get(domain, limit=500)
    positive = [item for item in findings if _is_visible_finding(item)]
    no_match_sources = sorted(
        {
            str(item.get("provider") or "Unknown source")
            for item in findings
            if not _is_visible_finding(item)
        },
        key=str.casefold,
    )
    positive.sort(
        key=lambda item: (
            not bool(item.get("decision_relevant")),
            -float(item.get("confidence") or 0.0),
            -int(item.get("retrieved_at") or 0),
            str(item.get("provider") or "").casefold(),
        )
    )

    dialog = tk.Toplevel(parent)
    dialog.title(f"Evidence — {domain}")
    dialog.geometry("1120x650")
    dialog.minsize(820, 460)
    dialog.transient(parent.winfo_toplevel())

    header = ttk.Frame(dialog, padding=(10, 10, 10, 6))
    header.pack(fill="x")
    decision_count = sum(1 for item in positive if item.get("decision_relevant"))
    ttk.Label(
        header,
        text=(
            f"{domain} · {len(positive)} relevant finding(s) · {decision_count} policy signal(s)"
        ),
    ).pack(side="left")
    ttk.Button(header, text="Close", command=dialog.destroy).pack(side="right")

    if no_match_sources:
        ttk.Label(
            dialog,
            text="Checked without a match: " + ", ".join(no_match_sources),
            wraplength=1060,
            justify="left",
        ).pack(fill="x", padx=10, pady=(0, 6))

    host = ttk.Frame(dialog, padding=(10, 0, 10, 8))
    host.pack(fill="both", expand=True)
    host.rowconfigure(0, weight=1)
    host.columnconfigure(0, weight=1)

    tree = ttk.Treeview(host, columns=_COLUMNS, show="headings", selectmode="browse")
    vertical = ttk.Scrollbar(host, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(host, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")

    widths = {
        "source": 170,
        "signal": 105,
        "verdict": 135,
        "confidence": 85,
        "decision": 95,
        "collected": 125,
        "expires": 125,
        "summary": 390,
    }
    for column in _COLUMNS:
        tree.heading(column, text=_HEADINGS[column])
        tree.column(
            column,
            width=widths[column],
            minwidth=65,
            anchor="center"
            if column in {"confidence", "decision", "collected", "expires"}
            else "w",
            stretch=column == "summary",
        )

    rows: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(positive):
        iid = str(index)
        rows[iid] = item
        tree.insert(
            "",
            "end",
            iid=iid,
            values=(
                item.get("provider", ""),
                item.get("signal_type", "context"),
                item.get("verdict", "unknown"),
                f"{float(item.get('confidence') or 0.0):.2f}",
                "yes" if item.get("decision_relevant") else "no",
                _format_timestamp(item.get("retrieved_at")),
                _format_timestamp(item.get("expires_at")),
                _single_line(item.get("summary", "")),
            ),
        )

    details_box = ttk.LabelFrame(dialog, text="Selected finding", padding=8)
    details_box.pack(fill="x", padx=10, pady=(0, 10))
    details_box.columnconfigure(0, weight=1)
    details_text = tk.Text(details_box, height=6, wrap="word")
    details_text.grid(row=0, column=0, sticky="ew")
    details_text.configure(state="disabled")
    open_button = ttk.Button(details_box, text="Open source", state="disabled")
    open_button.grid(row=0, column=1, sticky="n", padx=(8, 0))

    def selected(_event: tk.Event | None = None) -> None:
        selection = tree.selection()
        if not selection:
            return
        item = rows[str(selection[0])]
        text = _finding_text(item)
        details_text.configure(state="normal")
        details_text.delete("1.0", "end")
        details_text.insert("1.0", text)
        details_text.configure(state="disabled")
        url = str(item.get("source_url") or "").strip()
        if url:
            open_button.configure(
                state="normal",
                command=lambda current=url: webbrowser.open(current),
            )
        else:
            open_button.configure(state="disabled", command=lambda: None)

    tree.bind("<<TreeviewSelect>>", selected)
    tree.bind("<Double-1>", lambda _event: open_button.invoke())

    if positive:
        first = tree.get_children()[0]
        tree.selection_set(first)
        tree.focus(first)
        selected()
    else:
        details_text.configure(state="normal")
        details_text.insert(
            "1.0",
            "No relevant evidence is stored for this domain. Use “Collect and show evidence” "
            "to query all enabled evidence sources.",
        )
        details_text.configure(state="disabled")


def _is_visible_finding(item: dict[str, Any]) -> bool:
    raw_data = item.get("raw_data") or {}
    return (
        bool(raw_data.get("include_in_prompt", True))
        and str(item.get("verdict") or "") != "no_match"
    )


def _finding_text(item: dict[str, Any]) -> str:
    parts = []
    title = str(item.get("title") or "").strip()
    summary = str(item.get("summary") or "").strip()
    if title:
        parts.append(title)
    if summary and summary != title:
        parts.append(summary)
    source_url = str(item.get("source_url") or "").strip()
    if source_url:
        parts.append(f"Source: {source_url}")
    return "\n\n".join(parts) or "No additional details are available."


def _single_line(value: Any) -> str:
    return " ".join(str(value or "").split())


def _format_timestamp(value: Any) -> str:
    try:
        timestamp = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if timestamp <= 0:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))
