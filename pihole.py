"""Pi-hole API Client (v6-Style):
return True
except Exception as e:
log.exception("allow_exact error: %s", e)
return False


@retry(3, 0.2)
def deny_exact(self, domain: str, comment: str = "") -> bool:
log.info("DENY %s (%s)", domain, comment)
# TODO REAL API: POST /api/blacklist with payload {domain, type:"exact", comment}
if not self._can_request():
return True
try:
# payload = {"domain": domain, "type": "exact", "comment": comment}
# resp = self.session.post(self._url("/api/blacklist"), headers=self._headers(), json=payload, verify=self.opts.verify_tls, timeout=10)
# resp.raise_for_status()
return True
except Exception as e:
log.exception("deny_exact error: %s", e)
return False


@retry(3, 0.2)
def set_comment(self, domain: str, list_kind: str, comment: str) -> bool:
log.info("COMMENT %s [%s]: %s", domain, list_kind, comment)
# TODO REAL API: PATCH/PUT wenn vorhanden; sonst DB-only
return True


# -------------------- Queries -------------------
@retry(3, 0.2)
def poll_queries_since(self, since_ts: int) -> List[Dict[str, Any]]:
"""Delta-Polling.
Erwarteter Rückgabewert: [{ts, domain, client, status, type}, ...]
"""
if not self._can_request():
# Demo-Daten
now = int(time.time())
if now - since_ts < 1:
return []
return [
{"ts": now, "domain": "news.example.com", "client": "192.168.1.20", "status": "OK", "type": "A"},
{"ts": now, "domain": "tracker.badco.io", "client": "192.168.1.42", "status": "BLOCKED", "type": "AAAA"},
]
try:
# TODO REAL API: nutze deine lokale Doku (z.B. /api/queries?since=<ts>)
# resp = self.session.get(self._url(f"/api/queries?since={since_ts}"), headers=self._headers(), verify=self.opts.verify_tls, timeout=10)
# resp.raise_for_status()
# return resp.json().get("queries", [])
return []
except Exception as e:
log.exception("poll_queries_since error: %s", e)
return []


client = PiHoleClient()