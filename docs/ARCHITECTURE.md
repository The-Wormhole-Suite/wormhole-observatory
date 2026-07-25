# Architektur

## Produktmodell

Pi-hole Manager behandelt vier Ebenen getrennt:

1. **Beobachtung** – wann, wie häufig und von welchen Clients eine Domain verwendet wurde
2. **Wissen** – Rechercheergebnisse, Tags, Dienstzuordnung und Klassifizierungsverlauf
3. **Entscheidung** – Nutzer- und Policy-Entscheidungen einschließlich Review-Aufgaben
4. **Durchsetzung** – tatsächliche Allow-/Deny-Einträge in Pi-hole

Eine LLM-Empfehlung ist damit kein unmittelbarer DNS-Befehl. Erst die deterministische Policy-Engine darf daraus eine Aktion ableiten.

## Schichten

### `pihole6api`

Diese Schicht kennt nur HTTP und Pi-hole-Ressourcen. Sie enthält keine GUI-, Datenbank- oder Anwendungskonfiguration.

- normiert Basis-URLs auf `/api/`
- verwaltet Pi-hole-Sessions
- unterstützt konfigurierbare TLS-Prüfung und Timeouts
- wirft definierte Exceptions bei HTTP-, Authentifizierungs- und Verbindungsfehlern
- wiederholt automatisch nur idempotente Lesezugriffe

### `pihole_manager`

Diese Schicht enthält Anwendungsregeln:

- typisierte und migrierbare Konfiguration
- SQLite-Queue mit Claim/Ack/Fail-Semantik
- persistierte Scanner-Checkpoints
- aggregierte Query-Beobachtungen
- historisierte Recherche- und Klassifizierungsläufe
- OpenAI-kompatible LLM-Anbindung mit validierter Batch-Ausgabe
- Auflösung mehrerer Tag-Policies in automatische Aktionen
- langlebige Scanner-, Classifier- und Lock-Reconciler-Worker

### `pihole_manager.gui`

Tkinter bleibt ausschließlich Darstellung und Benutzerinteraktion. Netzwerkzugriffe werden über einen Executor ausgeführt und Ergebnisse anschließend im UI-Thread verarbeitet.

## Datenmodell

### `domains`

Stabiler Zustand pro Domain: erstes und letztes Auftreten, Query-Anzahl, letzte Klassifizierung, nächste Neubewertung und aktueller Dienst-/Policy-Snapshot.

### `query_observations`

Stündlich aggregierte Beobachtungen nach Domain, Client, Query-Typ und Status. Dadurch bleibt Kontext erhalten, ohne jede einzelne DNS-Anfrage unbegrenzt zu duplizieren.

### `classification_runs`

Unveränderlicher Verlauf aller LLM-Auswertungen mit Provider, Modell, Prompt-Fingerprint, Tags, Risiken, Konfidenz, Rohantwort und Ablaufdatum.

### `research_findings`

Zeitlich begrenzte Evidenz aus unabhängigen Quellen. Aktuell implementiert:

- RDAP-Registrierungsinformationen über das IANA-Bootstrap-Verzeichnis
- GitHub-Code-Suche
- Brave-Websuche
- VirusTotal-Domainberichte

Jeder Provider besitzt eigenes Caching, Timeout und Request-Intervall. Externe Recherche ist standardmäßig deaktiviert.

### `domain_locks`

Administrative Schutzregel für einen exakten Allow- oder Deny-Eintrag. Der Lock-Reconciler stellt entfernte Einträge wieder her und erzeugt bei widersprüchlichen Listen einen Review-Task.

### `review_tasks`

Priorisierte Aufgaben für unsichere, riskante oder widersprüchliche Ergebnisse. Diese Tabelle bildet später die Grundlage für Desktop-, Web- und Smartphone-Clients.

## Tags, Dienst und Policy

Die fachlichen Ebenen bleiben getrennt:

- `tags`: mehrere Zwecke oder technische Rollen
- `service`: vermuteter oder bekannter Dienst
- `service_role`: `core`, `optional`, `shared` oder `unknown`
- `policy`: Modell-Empfehlung
- Risikowerte: Datenschutz, Sicherheit und Ausfallgefahr

Eine Klassifizierung kann beispielsweise gleichzeitig `telemetry`, `analytics` und `api_backend` tragen. Automatik ist nur zulässig, wenn alle zugehörigen Tag-Policies dieselbe Aktion ergeben.

## LLM-Vertrag

Die LLM liefert ein Objekt mit `schema_version` und einem `results`-Array. Das Programm prüft:

- exakt ein Ergebnis pro angeforderter Domain
- keine unbekannten oder doppelten Domains
- gültige Tags und Enum-Werte
- begrenzte Risiko- und Konfidenzwerte
- vollständige Pflichtfelder

Schema-Konformität schützt nur die technische Schnittstelle. Die Policy-Engine prüft zusätzlich semantische Risiken und arbeitet fail-closed.

## Persistenz und Secrets

`options.json`, SQLite-Datenbank und Logs sind Laufzeitdaten im Anwendungsverzeichnis. Sie gehören nicht in Git. Die Konfiguration wird atomar über eine temporäre Datei ersetzt.

Die aktuelle Passwortspeicherung ist weiterhin nur ein Baseline-Verhalten. Eine spätere Version soll Windows Credential Manager, Secret Service oder macOS Keychain über eine Secret-Store-Abstraktion unterstützen.
