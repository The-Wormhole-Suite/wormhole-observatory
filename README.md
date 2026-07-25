# Pi-hole Manager

Desktop-Anwendung für **Pi-hole v6 oder neuer**. Sie zeigt DNS-Anfragen, verwaltet exakte Allow-/Deny-Einträge und kann Domains optional über einen OpenAI-kompatiblen LLM-Endpunkt klassifizieren.

## Status

Das Repository enthält einen konsistenten technischen Ausgangsstand. Der zuvor getrennte GUI-Code und der lokale `pihole6api`-Client wurden in klar abgegrenzte Pakete überführt. Die Anwendung ist noch frühe Alpha-Software; automatische LLM-Aktionen sollten zunächst im Modus `manual` oder `hybrid` getestet werden.

## Architektur

- `pihole6api/`: niedrige, UI-unabhängige Pi-hole-v6-API-Schicht
- `pihole_manager/`: Konfiguration, SQLite-Persistenz, LLM-Logik und Worker
- `pihole_manager/gui/`: Tkinter-Oberfläche und Tabs
- `tests/`: Offline-Tests ohne laufenden Pi-hole- oder LLM-Server
- `docs/`: Architekturentscheidungen und Roadmap

Weitere Details stehen in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installation

Voraussetzungen:

- Python 3.11 oder neuer
- Tkinter
- Pi-hole v6 oder neuer

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e .
python app.py
```

Unter Linux lautet die Aktivierung meist:

```bash
source .venv/bin/activate
```

Optional für Desktop-Benachrichtigungen:

```bash
python -m pip install -e ".[desktop-notifications]"
```

## Konfiguration

Beim ersten Start wird lokal eine `options.json` erzeugt. Sie enthält unter anderem das Pi-hole-Anwendungspasswort und mögliche LLM-API-Schlüssel im Klartext. Deshalb wird sie durch `.gitignore` ausgeschlossen und darf nicht eingecheckt werden.

`options.example.json` zeigt die Struktur ohne Zugangsdaten.

Pi-hole stellt die exakt zur installierten Version passende API-Dokumentation unter `http://pi.hole/api/docs` bereit. Diese lokale Dokumentation sollte bei API-Abweichungen zuerst geprüft werden.

## Entwicklung

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Sicherheitsmodell der Automatik

- `manual`: keine automatische Allow-/Deny-Aktion
- `hybrid`: nur wenn LLM-Entscheidung und Kategorie-Policy übereinstimmen
- `auto`: die konfigurierte Kategorie-Policy wird automatisch angewendet

Der LLM-Kurztext (`short`) wird bei Allow-/Deny-Aktionen als Pi-hole-Kommentar gespeichert.
