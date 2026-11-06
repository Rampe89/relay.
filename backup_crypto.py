"""Authenticated encrypted SQLite backups; run in LeihPilot container."""
import os, sys, sqlite3, tempfile, secrets, hashlib, getpass, datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DATA=Path('/data/leihpilot.db')
BACKUPS=Path('/backups')
MAGIC=b'LPBACKUP1'

def password(confirm=False):
 p=getpass.getpass('Backup-Passphrase: ')
 if len(p)<16:raise ValueError('Mindestens 16 Zeichen erforderlich')
 if confirm and p!=getpass.getpass('Passphrase wiederholen: '):raise ValueError('Passphrasen stimmen nicht überein')
 return p.encode()

def key(p,salt):return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(p)

def snapshot():
 fd,name=tempfile.mkstemp(prefix='lp-snapshot-',suffix='.db',dir='/data')
 os.close(fd)
 try:
  src=sqlite3.connect(DATA);dst=sqlite3.connect(name)
  try:src.backup(dst)
  finally:dst.close();src.close()
  return Path(name)
 except:
  os.unlink(name);raise

def backup():
 BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
 p=password(confirm=True);snap=snapshot()
 try:
  salt=secrets.token_bytes(16);nonce=secrets.token_bytes(12)
  payload=MAGIC+salt+nonce+AESGCM(key(p,salt)).encrypt(nonce,snap.read_bytes(),MAGIC)
  filename='leihpilot-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.lpbak'
  fd=os.open(BACKUPS/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(payload)
  print('Verschlüsseltes Backup:',BACKUPS/filename)
 finally:snap.unlink(missing_ok=True)

def decrypt(path,p):
 payload=path.read_bytes()
 if not payload.startswith(MAGIC) or len(payload)<len(MAGIC)+28:raise ValueError('Ungültiges Backup')
 offset=len(MAGIC);salt=payload[offset:offset+16];nonce=payload[offset+16:offset+28]
 plain=AESGCM(key(p,salt)).decrypt(nonce,payload[offset+28:],MAGIC)
 # verify SQLite integrity without exposing data in logs
 fd,name=tempfile.mkstemp(prefix='lp-check-',suffix='.db',dir='/data');os.close(fd)
 try:
  Path(name).write_bytes(plain)
  with sqlite3.connect(name) as c:
   if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('SQLite-Integritätsprüfung fehlgeschlagen')
 finally:Path(name).unlink(missing_ok=True)
 return plain

def verify(path):
 decrypt(path,password());print('Backup entschlüsselt und SQLite-Integrität bestätigt:',path.name)

def restore(path):
 if os.getenv('LEIHPILOT_RESTORE_OFFLINE')!='YES':raise ValueError('Wiederherstellung nur offline mit LEIHPILOT_RESTORE_OFFLINE=YES')
 plain=decrypt(path,password())
 # Do not overwrite the live DB here; administrator must stop the container and replace manually.
 target=BACKUPS/'RESTORED-leihpilot.db'
 if target.exists():raise ValueError('Zieldatei existiert bereits: '+str(target))
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(plain)
 print('Wiederhergestellte Datei (noch nicht aktiv):',target)

if __name__=='__main__':
 if len(sys.argv)<2:raise SystemExit('Nutzung: backup | verify /backups/datei.lpbak | restore /backups/datei.lpbak')
 try:
  if sys.argv[1]=='backup' and len(sys.argv)==2:backup()
  elif sys.argv[1] in ('verify','restore') and len(sys.argv)==3:
   path=Path(sys.argv[2]).resolve()
   if path.parent!=BACKUPS.resolve() or path.suffix!='.lpbak':raise ValueError('Nur .lpbak im Backup-Ordner')
   (verify if sys.argv[1]=='verify' else restore)(path)
  else:raise ValueError('Ungültige Parameter')
 except Exception as e:
  print('Fehler:',type(e).__name__,str(e),file=sys.stderr);sys.exit(1)
