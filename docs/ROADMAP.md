# Roadmap

## Priorität 1: Stabilität und Migration

- echte versionierte SQLite-Migrationsschritte statt ausschließlich idempotenter Schema-Erweiterung
- Zugangsdaten über Windows Credential Manager, Secret Service und macOS Keychain
- API-Verhalten gegen mehrere Pi-hole-v6-Minor-Versionen testen
- kontrollierter Dry-Run-Bericht vor Aktivierung automatischer Aktionen
- Abbruch, Timeout und Fortschrittsanzeige für lange Recherche- und LLM-Jobs

## Priorität 2: Domain Intelligence

- Protected Services und Compatibility Profiles
- manuell editierbare Tags mit Vorrang vor LLM-Tags
- bekannte Listen-Repositories gezielt priorisieren
- Link- und Evidenzansicht statt reinem JSON-Detaildialog
- optionale DNS-, CNAME- und Zertifikatstransparenz-Provider
- Quellenqualität und widersprüchliche Evidenz bewerten
- Golden-Testdatensatz für Prompt-, Provider- und Modellvergleiche

## Priorität 3: Pi-hole-Verwaltung

- editierbare Gruppen-Zuordnung für Domains und Listen
- separate Ansicht für Regex-Regeln und abonnierte Listen
- Konflikterkennung zwischen Allow, Deny, Regex, Gruppen und Locks
- Unterstützung mehrerer Pi-hole-Instanzen
- Audit-Log und Ein-Klick-Rollback

## Priorität 4: Review-Clients

- lokale HTTP-API mit Authentifizierung und Rollen
- responsive Weboberfläche/PWA als erster Smartphone-Client
- ntfy-/UnifiedPush-Benachrichtigungen mit Deep-Links
- Review-Aktionen: erlauben, sperren, später, ignorieren, nie wieder fragen
- Zugriff über LAN oder Tailscale ohne öffentliche Cloud-Abhängigkeit

## Priorität 5: Distribution

- Windows-Build mit PyInstaller
- signierte Releases und reproduzierbarer Build
- automatische Release-Artefakte über GitHub Actions
