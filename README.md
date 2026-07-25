# Pi-hole Manager

Desktop-Anwendung für **Pi-hole v6 oder neuer**. Sie kombiniert eine bequeme Verwaltung exakter Allow-/Deny-Einträge mit einem lokalen Domain-Wissensspeicher, einem optionalen Recherche-Layer und einer OpenAI-kompatiblen LLM-Analyse.

## Status

Frühe Alpha. Der aktuelle Stand legt das technische Fundament für nachvollziehbare Domain-Intelligence:

- Live-Erfassung und Aggregation von DNS-Anfragen
- historisierte LLM-Klassifizierungen statt Überschreiben des letzten Ergebnisses
- mehrere Tags pro Domain, Dienstzuordnung und getrennte Risikowerte
- automatische Wiedervorlage abgelaufener Klassifizierungen
- optionale Recherche über RDAP, GitHub, Brave Search und VirusTotal
- geschützte Allow-/Deny-Einträge mit automatischer Wiederherstellung
- verlustfreie Worker-Queue mit Claim/Ack/Fail-Semantik
- manuelle Review-Aufgaben bei Unsicherheit, hohem Ausfallrisiko oder Konflikten

Automatische Aktionen sollten zunächst ausschließlich im Modus `manual` oder `hybrid` getestet werden.

## Architektur

- `pihole6api/`: niedrige, UI-unabhängige Pi-hole-v6-API-Schicht
- `pihole_manager/`: Konfiguration, SQLite-Persistenz, Recherche, LLM-Logik und Worker
- `pihole_manager/gui/`: Tkinter-Oberfläche und Tabs
- `tests/`: Offline-Tests ohne laufenden Pi-hole-, Recherche- oder LLM-Server
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
python -m pip install -e "[desktop-notifications]"
```

## Konfiguration und Datenschutz

Beim ersten Start wird lokal eine `options.json` erzeugt. Sie enthält unter anderem das Pi-hole-Anwendungspasswort sowie mögliche LLM- und Recherche-API-Schlüssel im Klartext. Deshalb wird sie durch `.gitignore` ausgeschlossen und darf nicht eingecheckt werden.

Externe Recherche ist standardmäßig deaktiviert. Wird sie aktiviert, erhalten die ausgewählten Provider die zu untersuchenden Domainnamen. RDAP benötigt keinen Schlüssel; GitHub-Code-Suche, Brave Search und VirusTotal benötigen jeweils eigene Zugangsdaten.

`options.example.json` zeigt die vollständige Struktur ohne Zugangsdaten.

Pi-hole stellt die exakt zur installierten Version passende API-Dokumentation unter `http://pi.hole/api/docs` bereit. Diese lokale Dokumentation sollte bei API-Abweichungen zuerst geprüft werden.

## LLM-Ausgabe

Der Manager erwartet ein strikt validiertes Batch-Ergebnis. Jede Domain erhält getrennte Felder für:

- primäres Tag und zusätzliche Tags
- Dienst und Rolle im Dienst
- Datenschutz-, Sicherheits- und Ausfallrisiko
- Modellkonfidenz und manuellen Review-Grund
- Empfehlung, Beschreibung und ausführliche Begründung
- Zeitpunkt der nächsten Neubewertung

Provider können JSON Schema, JSON Object oder reines Prompt-Formatting verwenden. Im Modus `auto` versucht der Client diese Varianten kontrolliert nacheinander. Eine unvollständige, doppelte oder einer falschen Domain zugeordnete Antwort wird verworfen.

## Sicherheitsmodell der Automatik

- `manual`: keine automatische Allow-/Deny-Aktion
- `hybrid`: Modellentscheidung und sämtliche Tag-Policies müssen übereinstimmen
- `auto`: gemeinsame Tag-Policy darf angewendet werden

Unabhängig vom Modus wird keine automatische Aktion ausgeführt bei:

- aktivem manuellen Review
- zu geringer Konfidenz
- Kern- oder geteilter Infrastruktur
- hohem Ausfallrisiko
- widersprüchlichen Tag-Policies
- Konflikt mit einem geschützten Listen-Eintrag

Der LLM-Kurztext wird bei Allow-/Deny-Aktionen als Pi-hole-Kommentar gespeichert.

## Entwicklung

```bash
python -m pip install -e "[dev]"
pytest
ruff check .
```
