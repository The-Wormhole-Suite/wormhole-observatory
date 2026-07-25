# Roadmap

## Priorität 1: Stabilität und Sicherheit

- Zugangsdaten über einen plattformabhängigen Secret Store ablegen
- API-Verhalten gegen mehrere Pi-hole-v6-Minor-Versionen testen
- kontrollierte Schema-Migrationen mit eigener Migrationsnummer ergänzen
- UI-Fehlerzustände und Abbruch laufender Requests verbessern

## Priorität 2: Bedienung

- Details-Dialog für vollständige Query- und Listeneinträge
- Filter nach Client, Status, Query-Typ und Zeitraum
- editierbare Gruppen-Zuordnung für Domains und Listen
- separate Ansicht für Regex-Regeln und abonnierte Listen

## Priorität 3: LLM

- Provider-Verbindungstest und Modellabfrage
- optional strukturierte Ausgaben per JSON Schema, sofern der Provider dies unterstützt
- Verlauf mehrerer Klassifizierungen pro Domain statt nur des letzten Stands
- Dry-Run-Bericht vor Aktivierung des Auto-Modus

## Priorität 4: Distribution

- Windows-Build mit PyInstaller
- signierte Releases und reproduzierbarer Build
- automatische Release-Artefakte über GitHub Actions
