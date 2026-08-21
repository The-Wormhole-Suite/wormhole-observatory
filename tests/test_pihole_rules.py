from __future__ import annotations

from types import SimpleNamespace

import pytest

from pihole_manager import pihole_rules


def test_fetch_regex_domains_normalizes_groups(monkeypatch) -> None:
    client = SimpleNamespace(
        domain_management=SimpleNamespace(
            get_domains=lambda domain_type, kind: {
                "domains": [
                    {
                        "domain": r"(^|\\.)example\\.com$",
                        "comment": "tracker",
                        "enabled": True,
                        "groups": [3, "1", 3, "bad"],
                    }
                ]
            }
        )
    )
    monkeypatch.setattr(pihole_rules, "get_client", lambda: client)

    rows = pihole_rules.fetch_regex_domains("deny")

    assert rows == [
        {
            "domain": r"(^|\\.)example\\.com$",
            "type": "deny",
            "comment": "tracker",
            "enabled": True,
            "groups": [1, 3],
        }
    ]


def test_add_regex_domain_uses_regex_endpoint(monkeypatch) -> None:
    calls = []
    client = SimpleNamespace(
        domain_management=SimpleNamespace(
            add_domain=lambda *args, **kwargs: calls.append((args, kwargs)) or {"ok": True}
        )
    )
    monkeypatch.setattr(pihole_rules, "get_client", lambda: client)

    pihole_rules.add_regex_domain("  ^ads\\.example$  ", "deny", groups=[2, 2, 0])

    assert calls == [
        (
            (r"^ads\.example$", "deny", "regex"),
            {"comment": None, "groups": [0, 2], "enabled": True},
        )
    ]


def test_subscribed_list_mutations_preserve_type_and_groups(monkeypatch) -> None:
    calls = []
    client = SimpleNamespace(
        list_management=SimpleNamespace(
            update_list=lambda *args, **kwargs: calls.append((args, kwargs)) or {"ok": True}
        )
    )
    monkeypatch.setattr(pihole_rules, "get_client", lambda: client)

    result = pihole_rules.update_subscribed_list(
        "https://example.invalid/list.txt",
        "block",
        comment="maintained",
        groups=[4, 1, 4],
        enabled=False,
    )

    assert result == {"ok": True}
    assert calls == [
        (
            ("https://example.invalid/list.txt", "block"),
            {"comment": "maintained", "groups": [1, 4], "enabled": False},
        )
    ]


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (pihole_rules.fetch_regex_domains, "block"),
        (pihole_rules.fetch_subscribed_lists, "deny"),
    ],
)
def test_invalid_rule_types_are_rejected(function, value) -> None:
    with pytest.raises(ValueError):
        function(value)
