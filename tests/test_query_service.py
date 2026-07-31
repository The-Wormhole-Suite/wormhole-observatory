from __future__ import annotations


def test_fetch_query_page_preserves_fractional_timestamp(monkeypatch) -> None:
    from pihole_manager import pihole_service

    class Metrics:
        @staticmethod
        def get_queries(**_kwargs):
            return {
                "queries": [
                    {
                        "time": 1_700_000_000.987,
                        "client": {"name": "phone"},
                        "domain": "example.com",
                        "type": "A",
                        "status": "FORWARDED",
                    }
                ],
                "cursor": {"next": "abc"},
                "total": 1,
            }

    class Client:
        metrics = Metrics()

    monkeypatch.setattr(pihole_service, "get_client", lambda: Client())

    page = pihole_service.fetch_query_page(100, 1_700_000_000.0)

    assert page.rows[0]["time"] == 1_700_000_000.987
    assert page.rows[0]["client"] == "phone"
    assert page.cursor == "abc"
    assert page.total == 1
