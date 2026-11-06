"""Local console-only password reset; no web endpoint or default credentials."""
import getpass
import sqlite3
from pathlib import Path
from argon2 import PasswordHasher

DB = Path('/data/leihpilot.db')

def main():
    if not DB.is_file():
        raise SystemExit('Datenbank nicht gefunden.')
    with sqlite3.connect(DB) as db:
        account = db.execute('SELECT username FROM admin_account WHERE id=1').fetchone()
        if account is None:
            raise SystemExit('Kein Administrator vorhanden.')
        print('Administrator:', account[0])
        print('Nur auf dem Pi über eine autorisierte Shell ausführen.')
        if input('Passwort für diesen Administrator zurücksetzen? [ja/NEIN] ').strip() != 'ja':
            raise SystemExit('Abgebrochen.')
        pw = getpass.getpass('Neues Passwort (mindestens 14 Zeichen): ')
        confirm = getpass.getpass('Wiederholen: ')
        if pw != confirm or not 14 <= len(pw) <= 256:
            raise SystemExit('Passwörter stimmen nicht überein oder Länge ungültig.')
        db.execute('UPDATE admin_account SET password_hash=? WHERE id=1', (PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1).hash(pw),))
        db.execute('DELETE FROM sessions')
        db.execute("INSERT INTO audit_log(at,event,details) VALUES(datetime('now'),'password_reset_console','')")
    print('Passwort geändert. Alle Sitzungen abgemeldet.')

if __name__ == '__main__':
    main()
