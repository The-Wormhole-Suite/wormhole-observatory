from __future__ import annotations

from pihole_manager.list_rule_parser import domain_from_list_rule


def test_list_rule_parser_supports_hosts_and_adblock_syntax() -> None:
    assert domain_from_list_rule("0.0.0.0 ads.example.com") == "ads.example.com"
    assert domain_from_list_rule("||tracker.example.org^") == "tracker.example.org"
    assert domain_from_list_rule("plain.example.net") == "plain.example.net"
    assert domain_from_list_rule("@@||allowed.example^") == ""
    assert domain_from_list_rule("# comment") == ""
