# Mitarbeit

relay. ist derzeit ein Testprojekt. Vor Pull Requests bitte prüfen:

1. Keine personenbezogenen Daten, lokalen Datenbanken, Backups oder Zugangsdaten committen.
2. Python 3.11: `python3 -m py_compile app.py backup_crypto.py reset_admin.py`
3. Docker-Build und `/health`-Endpunkt testen.
4. Bestehende Scan-, Einzel- und Klassenausleihe nicht unbeabsichtigt verändern.
5. Sicherheitsrelevante Änderungen (Login, CSRF, Backup) besonders sorgfältig prüfen.

Bitte Fehler mit reproduzierbaren Schritten und anonymisierten Logs melden.
