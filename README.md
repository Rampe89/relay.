# relay.

**Geräteverwaltung und Ausleihe für Schulen – Version 0.11 (Testprojekt)**

relay. ist eine lokal betreibbare Webanwendung für die Verwaltung von Schulgeräten, Schülerinnen und Schülern sowie Ausleihen. Der bisherige interne Projekt- und Docker-Service-Name `leihpilot` bleibt aus Kompatibilitätsgründen erhalten.

> **Status:** Prototyp für Testdaten. Nicht für den produktiven Einsatz mit personenbezogenen Schuldaten freigegeben. Kein vollständiges Security-Audit, keine datenschutzrechtliche Freigabe.

## Funktionen

- Geräte- und Schülerverwaltung mit Klassenübersicht
- Ausleihe und Rückgabe per manueller Auswahl oder Code-128-Barcodes
- **Klassenausleihe:** Klasse wählen, alphabetisch durchgehen, Gerät scannen/eingeben, nach erfolgreicher Buchung automatisch weiter; akustische Rückmeldung
- Geräte-Lebenszyklus: Aktiv, Reparatur, Defekt, Verloren, Ausgesondert; gesperrte Geräte nicht ausleihbar
- CSV-Import und -Export, Suche und Filter
- Ausleihhistorie, Leihvertrag und Übergabe-/Rückgabeprotokoll als PDF; Dokumentstatus
- Admin-Login mit Argon2-Passwort-Hash, Sitzungen, CSRF-Schutz, Login-Drosselung, Audit-Log
- Manuelle verschlüsselte SQLite-Backups und Datenschutz-/Anonymisierungsfunktionen

## Voraussetzungen

- Docker Engine und Docker Compose (auch `docker-compose` v1 für bestehende Pi-Installationen)
- ARM64 oder x86_64; Raspberry Pi mit ausreichend Speicherplatz
- Zugriff auf die lokale Shell für Ersteinrichtung und Backups

## Schnellstart (ausschließlich mit Testdaten)

```bash
git clone <REPOSITORY-URL>
cd relay
mkdir -p data backups
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:3100/health
```

Für ältere Docker-Compose-Installationen `docker-compose` statt `docker compose` verwenden.

**Wichtig:** `127.0.0.1:3100` ist nur auf dem Docker-Host erreichbar. Für einen entfernten Rechner einen SSH-Tunnel nutzen:

```bash
ssh -N -L 3100:127.0.0.1:3100 USER@HOST
```

Danach `http://localhost:3100` öffnen und das Admin-Konto bei der Ersteinrichtung anlegen. `USER@HOST` durch den eigenen SSH-Zugang ersetzen. Keine öffentlichen Portfreigaben einrichten.

## Bestehende Installation aktualisieren

Die bestehende SQLite-Datenbank befindet sich unter `data/leihpilot.db`. **Vor jedem Update sichern**, ebenso die aktuelle `app.py`. Bestehende Installationen sollten Änderungen zunächst in einer separaten Testumgebung prüfen.

```bash
cp app.py app.py.bak
cp data/leihpilot.db data/leihpilot.db.bak
python3 -m py_compile app.py
docker compose up -d --build --no-deps leihpilot
docker compose ps
docker compose logs --tail=40 leihpilot
```

**Hinweis:** Die hier veröffentlichte `app.py` enthält die Korrektur des Python-3.11-f-string-Syntaxfehlers aus dem ursprünglichen v0.11-Paket. Der Code ist syntaktisch geprüft; vollständige Integrationstests und Hardware-Scannertests sind noch ausstehend.

## Barcode und Klassenausleihe

Barcodes der Form `S0000001` (Schüler) und `G0000001` (Gerät) werden unterstützt. Ein Barcode-Scanner kann als Tastatur-Eingabegerät verwendet werden. In der Klassenausleihe wird **nur nach erfolgreicher Buchung** zum nächsten Schüler gewechselt; bei Fehlern bleibt die aktuelle Auswahl bestehen. Ein Test mit dem konkreten Scanner-Modell steht noch aus.

## Backups

```bash
docker compose exec leihpilot python /app/backup_crypto.py backup
docker compose exec leihpilot python /app/backup_crypto.py verify /backups/DATEI.lpbak
```

Das Skript fragt eine separate Backup-Passphrase ab. Sie wird nicht gespeichert. Die verschlüsselten Dateien liegen in `backups/` und werden **nicht** in Git eingecheckt. Ein Restore-Test auf separater Testumgebung ist vor produktiver Nutzung erforderlich.

## Sicherheit und Datenschutz

- SQLite-Datenbank ist **nicht im Ruhezustand verschlüsselt**.
- Backups werden nicht automatisch extern gespeichert.
- Das System ist standardmäßig nur an `127.0.0.1` des Hosts gebunden.
- Es gibt keinen öffentlichen HTTPS-Reverse-Proxy und keine zentrale Benutzer-/Rollenverwaltung.
- Musterverträge, Aufbewahrungsfristen, TOMs und Rechtsgrundlagen müssen vor einem realen Schulbetrieb geprüft werden.
- **Keine echten Schülerdaten, Datenbankdateien, Backups, Passwörter oder privaten Schlüssel committen.**

## Entwicklung und Tests

```bash
python3 -m py_compile app.py backup_crypto.py reset_admin.py
docker compose config
docker compose up -d --build
curl -f http://127.0.0.1:3100/health
```

Ein GitHub-Actions-Workflow prüft Python-3.11-Syntax, Docker-Build und den Health-Endpunkt. Er ersetzt keine Funktionstests für Login, Ausleihe, PDFs und Scanner.

## Projektstruktur

```text
app.py                  FastAPI-Anwendung
backup_crypto.py        Verschlüsselte Backups
reset_admin.py          Lokales Admin-Reset-Werkzeug
Dockerfile              Container-Build
docker-compose.yml      Lokaler Dienst (Port 3100)
.github/workflows/      CI-Starttest
data/                   Persistente SQLite-Daten (nicht in Git)
backups/                Backup-Dateien (nicht in Git)
```

## Lizenz

Derzeit **keine Open-Source-Lizenz** hinterlegt. Der Quellcode ist damit nicht automatisch zur Weiterverwendung lizenziert. Vor einer öffentlichen Freigabe eine passende Lizenz auswählen und eine `LICENSE`-Datei ergänzen.
