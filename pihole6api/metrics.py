from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection


class PiHole6Metrics:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def get_history(self) -> Any:
        return self.connection.get("history")

    def get_history_clients(self, clients: int = 20) -> Any:
        return self.connection.get("history/clients", params={"N": max(0, clients)})

    def get_history_database(self, start: int, end: int) -> Any:
        return self.connection.get("history/database", params={"from": start, "until": end})

    def get_history_database_clients(self, start: int, end: int) -> Any:
        return self.connection.get("history/database/clients", params={"from": start, "until": end})

    def get_queries(
        self,
        length: int = 100,
        from_ts: float | None = None,
        until_ts: float | None = None,
        upstream: str | None = None,
        domain: str | None = None,
        client: str | None = None,
        cursor: str | None = None,
    ) -> Any:
        params = {
            "length": max(1, int(length)),
            "from": from_ts,
            "until": until_ts,
            "upstream": upstream,
            "domain": domain,
            "client": client,
            "cursor": cursor,
        }
        return self.connection.get(
            "queries", params={key: value for key, value in params.items() if value is not None}
        )

    def get_query_suggestions(self) -> Any:
        return self.connection.get("queries/suggestions")

    def get_stats_database_query_types(self, start: int, end: int) -> Any:
        return self.connection.get(
            "stats/database/query_types", params={"from": start, "until": end}
        )

    def get_stats_database_summary(self, start: int, end: int) -> Any:
        return self.connection.get("stats/database/summary", params={"from": start, "until": end})

    def get_stats_database_top_clients(
        self, start: int, end: int, blocked: bool | None = None, count: int | None = None
    ) -> Any:
        return self._database_top("clients", start, end, blocked, count)

    def get_stats_database_top_domains(
        self, start: int, end: int, blocked: bool | None = None, count: int | None = None
    ) -> Any:
        return self._database_top("domains", start, end, blocked, count)

    def _database_top(
        self,
        resource: str,
        start: int,
        end: int,
        blocked: bool | None,
        count: int | None,
    ) -> Any:
        params = {
            "from": start,
            "until": end,
            "blocked": str(blocked).lower() if blocked is not None else None,
            "count": count,
        }
        return self.connection.get(
            f"stats/database/top_{resource}",
            params={key: value for key, value in params.items() if value is not None},
        )

    def get_stats_database_upstreams(self, start: int, end: int) -> Any:
        return self.connection.get("stats/database/upstreams", params={"from": start, "until": end})

    def get_stats_query_types(self) -> Any:
        return self.connection.get("stats/query_types")

    def get_stats_recent_blocked(self, count: int | None = None) -> Any:
        return self.connection.get(
            "stats/recent_blocked", params={"count": count} if count is not None else None
        )

    def get_stats_summary(self) -> Any:
        return self.connection.get("stats/summary")

    def get_stats_top_clients(self, blocked: bool | None = None, count: int | None = None) -> Any:
        return self._top("clients", blocked, count)

    def get_stats_top_domains(self, blocked: bool | None = None, count: int | None = None) -> Any:
        return self._top("domains", blocked, count)

    def _top(self, resource: str, blocked: bool | None, count: int | None) -> Any:
        params = {
            "blocked": str(blocked).lower() if blocked is not None else None,
            "count": count,
        }
        return self.connection.get(
            f"stats/top_{resource}",
            params={key: value for key, value in params.items() if value is not None},
        )

    def get_stats_upstreams(self) -> Any:
        return self.connection.get("stats/upstreams")
