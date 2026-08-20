from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk

from pihole_manager.compatibility_profiles import compatibility_match_for_domain
from pihole_manager.database import domain_details
from pihole_manager.gui.policy_labels import policy_label, status_label


def show_domain_details(parent: tk.Misc, domain: str) -> None:
    data = dict(domain_details(domain) or {})
    compatibility = compatibility_match_for_domain(domain)
    if compatibility is not None:
        data["compatibility_profile"] = compatibility.as_dict()
    dialog = tk.Toplevel(parent)
    dialog.title(f"Domain intelligence — {domain}")
    dialog.geometry("980x720")
    dialog.minsize(760, 520)

    frame = ttk.Frame(dialog, padding=8)
    frame.pack(fill="both", expand=True)
    text = tk.Text(frame, wrap="word")
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    text.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    text.insert(
        "1.0",
        json.dumps(_display_values(data), ensure_ascii=False, indent=2, default=str),
    )
    text.configure(state="disabled")


def _display_values(value, key: str = ""):
    if isinstance(value, dict):
        return {item_key: _display_values(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_display_values(item, key) for item in value]
    if key in {"policy", "planned_action", "list_type"} and isinstance(value, str):
        return policy_label(value)
    if key in {"status", "action_status"} and isinstance(value, str):
        return status_label(value)
    return value
