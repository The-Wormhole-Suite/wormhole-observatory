# Architektur

## Ausgangsprobleme

Der frühere Stand vermischte Transport, Anwendung und GUI. Dadurch entstanden mehrere konkrete Fehler:

1. Der GUI-Wrapper rief den lokalen API-Client mit Parametern auf, die dessen Konstruktor nicht akzeptierte.
2. Konfigurationsfelder hatten je nach Datei unterschiedliche Namen (`host`/`base_url`, `batch`/`batch_size`, `file`/`filename`).
3. TLS-Prüfung war im API-Client faktisch immer deaktiviert.
4. HTTP-Fehler wurden teilweise als normale Rückgabewerte behandelt und von Aufrufern als Erfolg interpretiert.
5. Netzwerkzugriffe liefen teilweise im Tkinter-Hauptthread.
6. Checkbox-Spalten waren optisch vorhanden, besaßen aber keinen eigenen Zustand.
7. Die Staging-Queue löschte Domains vor erfolgreicher Klassifizierung und konnte Daten verlieren.
8. LLM-Kategorie, Policy und Kurztext wurden beim Parsen und Speichern miteinander verwechselt.

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
- OpenAI-kompatible LLM-Anbindung
- Auflösung von Kategorie-Policies in automatische Aktionen
- langlebige Scanner- und Classifier-Worker

### `pihole_manager.gui`

Tkinter bleibt ausschließlich Darstellung und Benutzerinteraktion. Netzwerkzugriffe werden über einen Executor ausgeführt und Ergebnisse anschließend im UI-Thread verarbeitet.

## Persistenz

`options.json`, SQLite-Datenbank und Logs sind Laufzeitdaten im Anwendungsverzeichnis. Sie gehören nicht in Git. Die Konfiguration wird atomar über eine temporäre Datei ersetzt.

Die aktuelle Passwortspeicherung ist bewusst nur ein Baseline-Verhalten. Eine spätere Version sollte Windows Credential Manager, Secret Service oder macOS Keychain über eine kleine Secret-Store-Abstraktion unterstützen.

## LLM-Automatik

Eine Klassifizierung besteht getrennt aus:

- `policy`: Einschätzung des Modells
- `category`: fachliche Kategorie
- `short`: kurzer, für Pi-hole geeigneter Kommentar
- `details`: ausführlichere Begründung

Die Kategorie-Policy ist die administrative Vorgabe. Im Hybrid-Modus wird nur automatisch gehandelt, wenn Modell-Policy und Vorgabe übereinstimmen. Im Auto-Modus ist die Vorgabe maßgeblich.
