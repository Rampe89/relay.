import os, sqlite3, io, csv, secrets, html, time, hashlib, re
from urllib.parse import parse_qs
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, Form, UploadFile, File, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from reportlab.pdfgen import canvas
from reportlab.graphics.barcode import code128
from fastapi.responses import Response, JSONResponse
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from contextvars import ContextVar
CSRF_CONTEXT=ContextVar("csrf",default="")
# Reject oversized requests before parsing form data. Scanner requests are tiny;
# CSV import is limited separately to 300 KB of UTF-8 text.
MAX_REQUEST_BYTES=1024*1024

def csv_safe_cell(value):
 """Prevent spreadsheet formula interpretation (including leading whitespace)."""
 text='' if value is None else str(value)
 if text.lstrip('\t\r\n ').startswith(('=', '+', '-', '@')):
  return "'"+text
 return text


ROOT=Path('/data'); ROOT.mkdir(exist_ok=True)
DB=ROOT/'leihpilot.db'
app=FastAPI(title='relay. – Demo')

def conn():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY,name TEXT NOT NULL,class_name TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY,inventory TEXT NOT NULL UNIQUE,serial TEXT,token TEXT NOT NULL UNIQUE);
  CREATE TABLE IF NOT EXISTS loans(id INTEGER PRIMARY KEY,device_id INTEGER NOT NULL REFERENCES devices(id),student_id INTEGER NOT NULL REFERENCES students(id),issued TEXT NOT NULL,returned TEXT,accessories TEXT DEFAULT '');
  CREATE UNIQUE INDEX IF NOT EXISTS one_active_loan ON loans(device_id) WHERE returned IS NULL;''')
  c.execute("CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)")
  c.execute("CREATE TABLE IF NOT EXISTS scan_codes(kind TEXT NOT NULL, entity_id INTEGER NOT NULL, code TEXT NOT NULL UNIQUE, PRIMARY KEY(kind,entity_id))")
  for kind,table in [('student','students'),('device','devices')]:
   for row in c.execute(f'SELECT id FROM {table}').fetchall():
    c.execute('INSERT OR IGNORE INTO scan_codes(kind,entity_id,code) VALUES(?,?,?)',(kind,row[0],('S' if kind=='student' else 'G')+f'{row[0]:07d}'))
  for column in ('model','condition','notes'):
   if column not in [x[1] for x in c.execute('PRAGMA table_info(devices)').fetchall()]:
    c.execute(f'ALTER TABLE devices ADD COLUMN {column} TEXT DEFAULT ""')
  if 'operational_state' not in [x[1] for x in c.execute('PRAGMA table_info(devices)').fetchall()]:
   c.execute("ALTER TABLE devices ADD COLUMN operational_state TEXT NOT NULL DEFAULT 'Aktiv'")
  c.execute("INSERT OR IGNORE INTO settings VALUES('school','Musterschule (Demo)')")
  if not c.execute('SELECT 1 FROM students').fetchone():
   c.executemany('INSERT INTO students(name,class_name) VALUES(?,?)',[('Mia Beispiel','7a'),('Leon Muster','8b'),('Alex Demo','9a')])
  if not c.execute('SELECT 1 FROM devices').fetchone():
   c.executemany('INSERT INTO devices(inventory,serial,token) VALUES(?,?,?)',[(f'IP-{i:04}',f'DEMO-SN-{i}',secrets.token_urlsafe(18)) for i in range(1,6)])
  for r in c.execute('SELECT DISTINCT class_name FROM students WHERE trim(class_name) != ""').fetchall():
   c.execute('INSERT OR IGNORE INTO classes(name) VALUES(?)',(r[0],))
init()

# Authentication and audit are intentionally stored in the existing persistent SQLite volume.
PH=PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1)
SESSION_SECONDS=8*3600
with conn() as c:
 c.execute("CREATE TABLE IF NOT EXISTS admin_account(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password_hash TEXT NOT NULL)")
 c.execute("CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL)")
 c.execute("CREATE TABLE IF NOT EXISTS login_attempts(ip TEXT NOT NULL, timestamp INTEGER NOT NULL)")
 c.execute("CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, at TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL DEFAULT '')")

def audit(event,details=''):
 with conn() as c:c.execute('INSERT INTO audit_log(at,event,details) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),event,str(details)[:180]))

def account_exists():
 with conn() as c:return bool(c.execute('SELECT 1 FROM admin_account WHERE id=1').fetchone())

def session_for(request):
 token=request.cookies.get('lp_session','')
 if len(token)!=64:return None
 with conn() as c:
  return c.execute('SELECT csrf FROM sessions WHERE token_hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()

def auth_page(title,content):
 return HTMLResponse(f'''<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} · relay.</title><style>body{{font:15px system-ui,Arial;background:#f3f5f7;color:#23313e;display:grid;place-items:center;min-height:100vh;margin:0}}main{{background:white;border:1px solid #dfe5ea;border-radius:7px;padding:32px;width:min(390px,calc(100vw - 60px))}}h1{{margin:0 0 5px;font-size:25px}}p{{color:#697581;line-height:1.5}}label{{display:block;margin:18px 0 5px;font-weight:600}}input{{width:100%;box-sizing:border-box;padding:12px;border:1px solid #bdc9d3;border-radius:4px;font:inherit}}button{{background:#284f70;color:white;border:0;border-radius:4px;padding:12px 18px;margin-top:22px;cursor:pointer;font:inherit;width:100%}}.error{{color:#a22b2b}}small{{color:#78818a}}</style><main><h1>relay.</h1><p>{html.escape(title)}</p>{content}<p><small>Lokales Testsystem. Keine echten Schülerdaten.</small></p></main></html>''')

@app.middleware('http')
async def security_middleware(request:Request,call_next):
 path=request.url.path
 if request.method in ('POST','PUT','PATCH','DELETE'):
  length=request.headers.get('content-length')
  if length is not None:
   try:
    if int(length)>MAX_REQUEST_BYTES:return HTMLResponse('Anfrage zu groß.',status_code=413)
   except ValueError:
    return HTMLResponse('Ungültige Anfragegröße.',status_code=400)
  # Also enforce the limit for chunked requests without Content-Length.
  # Starlette caches the body for downstream form parsing.
  received=await request.body()
  if len(received)>MAX_REQUEST_BYTES:return HTMLResponse('Anfrage zu groß.',status_code=413)
 public=path in ('/login','/setup','/health')
 session=session_for(request)
 ctx=CSRF_CONTEXT.set(session['csrf'] if session else '')
 if not public and session is None:
  response=RedirectResponse('/login',status_code=303)
 elif request.method in ('POST','PUT','PATCH','DELETE') and not public:
  # Standard HTML form submissions, including scanner forms.
  raw=await request.body()
  content_type=request.headers.get('content-type','')
  if 'application/x-www-form-urlencoded' in content_type:
   provided=parse_qs(raw.decode('utf-8',errors='replace')).get('_csrf',[''])[0]
  else:
   provided='' # Reject multipart writes until a CSRF-safe multipart handler is implemented.
  if not secrets.compare_digest(provided,session['csrf']):
   response=HTMLResponse('Sicherheitsprüfung fehlgeschlagen. Seite neu laden.',status_code=403)
  else:
   response=await call_next(request)
 else:response=await call_next(request)
 if session is not None and isinstance(response, Response) and False:pass
 if session is not None and request.method=='POST' and response.status_code<400:
  audit('write',path)
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['Cache-Control']='no-store'
 response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
 # Do not set HSTS until a real HTTPS reverse proxy is in place.
 CSRF_CONTEXT.reset(ctx)
 return response

@app.get('/health')
def health():return {'status':'ok'}

@app.get('/setup')
def setup_get():
 if account_exists():return go('/login')
 return auth_page('Administrator einrichten','<form method="post"><label>Benutzername</label><input name="username" value="admin" required maxlength="40" autocomplete="username"><label>Passwort (mindestens 14 Zeichen)</label><input name="password" type="password" minlength="14" required autocomplete="new-password"><label>Passwort wiederholen</label><input name="repeat" type="password" minlength="14" required autocomplete="new-password"><button>Administrator erstellen</button></form>')

@app.post('/setup')
def setup_post(username:str=Form(...),password:str=Form(...),repeat:str=Form(...)):
 if password!=repeat or len(password)<14 or len(password)>256 or not (1<=len(username.strip())<=40):return auth_page('Administrator einrichten','<p class="error">Angaben ungültig. Passwort: 14–256 Zeichen, beide Eingaben identisch.</p><a href="/setup">Erneut versuchen</a>')
 try:
  with conn() as c:c.execute('INSERT INTO admin_account(id,username,password_hash) VALUES(1,?,?)',(username.strip(),PH.hash(password)))
 except sqlite3.IntegrityError:return go('/login')
 audit('admin_created')
 return go('/login')

@app.get('/login')
def login_get():
 if not account_exists():return go('/setup')
 return auth_page('Anmelden','<form method="post"><label>Benutzername</label><input name="username" required autocomplete="username"><label>Passwort</label><input name="password" type="password" required autocomplete="current-password"><button>Anmelden</button></form>')

@app.post('/login')
def login_post(request:Request,username:str=Form(...),password:str=Form(...)):
 if not account_exists():return go('/setup')
 ip=request.client.host if request.client else 'unknown'; now=int(time.time())
 with conn() as c:
  c.execute('DELETE FROM login_attempts WHERE timestamp<?',(now-900,))
  fails=c.execute('SELECT COUNT(*) FROM login_attempts WHERE ip=?',(ip,)).fetchone()[0]
  account=c.execute('SELECT * FROM admin_account WHERE id=1').fetchone()
 if fails>=8:return HTMLResponse('Zu viele Versuche. Bitte in 15 Minuten erneut versuchen.',status_code=429)
 try:valid=bool(account and secrets.compare_digest(username,account['username']) and PH.verify(account['password_hash'],password))
 except (VerifyMismatchError,VerificationError):valid=False
 if not valid:
  with conn() as c:c.execute('INSERT INTO login_attempts(ip,timestamp) VALUES(?,?)',(ip,now))
  audit('login_failed')
  return auth_page('Anmelden','<p class="error">Anmeldung fehlgeschlagen.</p><a href="/login">Erneut versuchen</a>')
 token=secrets.token_hex(32);csrf=secrets.token_urlsafe(32)
 with conn() as c:
  c.execute('DELETE FROM login_attempts WHERE ip=?',(ip,))
  c.execute('DELETE FROM sessions WHERE expires<?',(now,))
  c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),csrf,now+SESSION_SECONDS))
 audit('login_success')
 response=go('/')
 response.set_cookie('lp_session',token,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE','0')=='1',max_age=SESSION_SECONDS,path='/')
 return response

@app.post('/logout')
def logout(request:Request):
 token=request.cookies.get('lp_session','')
 with conn() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
 audit('logout')
 response=go('/login');response.delete_cookie('lp_session',path='/');return response

@app.get('/account')
def account_get(request:Request):
 csrf=session_for(request)['csrf']
 return page('Passwort ändern',f'''<div class="card"><form method="post" action="/account"><input type="hidden" name="_csrf" value="{csrf}"><label class="field">Aktuelles Passwort<input type="password" name="old" required></label><p><label class="field">Neues Passwort (mindestens 14 Zeichen)<input type="password" name="new" minlength="14" required></label></p><p><label class="field">Wiederholung<input type="password" name="repeat" minlength="14" required></label></p><button>Passwort ändern</button></form></div>''','/account')

@app.post('/account')
def account_post(request:Request,old:str=Form(...),new:str=Form(...),repeat:str=Form(...)):
 with conn() as c:row=c.execute('SELECT password_hash FROM admin_account WHERE id=1').fetchone()
 try:valid=PH.verify(row['password_hash'],old)
 except (VerifyMismatchError,VerificationError):valid=False
 if not valid or new!=repeat or not 14<=len(new)<=256:return HTMLResponse('Passwortänderung fehlgeschlagen.',status_code=400)
 with conn() as c:
  c.execute('UPDATE admin_account SET password_hash=? WHERE id=1',(PH.hash(new),))
  c.execute('DELETE FROM sessions')
 audit('password_changed')
 response=go('/login');response.delete_cookie('lp_session',path='/');return response

DEFAULT_CONTRACT = """Die Schule überlässt das oben bezeichnete Gerät zur schulischen Nutzung.

Die Einzelheiten zu Nutzungsumfang, Sorgfaltspflichten, Haftung und Rückgabe sind vor dem produktiven Einsatz durch die zuständigen Stellen verbindlich festzulegen.

Diese Vorlage ist ausschließlich ein Entwurf für die Erprobung der Software und begründet keine geprüften Vertragsbedingungen."""
with conn() as c:
 c.execute("CREATE TABLE IF NOT EXISTS contract_docs (loan_id INTEGER PRIMARY KEY REFERENCES loans(id), status TEXT NOT NULL DEFAULT 'Entwurf', updated TEXT NOT NULL)")
 c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('contract_template',?)",(DEFAULT_CONTRACT,))

STYLE='''<style>
:root{--navy:#111c31;--blue:#335cdd;--muted:#66758c;--line:#e3e9f2}*{box-sizing:border-box}body{font-family:Inter,system-ui,-apple-system,Segoe UI,Arial;margin:0;background:#f5f7fb;color:#18253b}header{position:fixed;inset:0 auto 0 0;width:238px;background:var(--navy);color:#fff;padding:29px 17px;z-index:3}header h1{font-size:22px;margin:0 0 3px;letter-spacing:-.7px}header .school{font-size:12px;color:#b0bed4;line-height:1.5;margin-bottom:34px}nav{display:flex;flex-direction:column;gap:6px}nav a{padding:13px 14px;border-radius:10px;color:#bdc9dc;text-decoration:none;font-size:14px;font-weight:600}nav a:hover,nav a.active{background:#293b59;color:white}main{margin-left:238px;max-width:1550px;padding:34px 44px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:23px}.top h2{font-size:28px;letter-spacing:-.9px;margin:0}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:23px;margin:17px 0;box-shadow:0 4px 22px #24385809}.card h3{margin:0 0 17px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:15px}.stat{font-size:34px;font-weight:750;letter-spacing:-1px;color:#172b4c}.statcard{margin:0}small,.sub{color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:15px 12px;text-align:left;border-bottom:1px solid #eef1f5}th{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#758399}tr:last-child td{border-bottom:0}input,select,textarea{font:inherit;padding:11px 12px;border:1px solid #cdd7e5;border-radius:9px;background:white;max-width:100%;min-width:0}input:focus,select:focus,textarea:focus{outline:2px solid #aec3ff;border-color:#335cdd}button,.btn{font:inherit;background:var(--blue);color:white;border:0;padding:11px 16px;border-radius:9px;cursor:pointer;text-decoration:none;display:inline-block;font-weight:600;font-size:13px}button:hover,.btn:hover{filter:brightness(.94)}button:disabled{opacity:.45}a{color:#2f54c9}.secondary{background:#edf1f8;color:#29415d}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:13px}.field{display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:600;color:#44536a}.field input,.field select,.field textarea{width:100%}.notice{background:#fff5de;border:1px solid #f2dc9e;color:#795816;padding:12px 16px;border-radius:10px;font-size:12px;margin-bottom:24px}.pill{display:inline-block;background:#eaf6ef;color:#247047;border-radius:50px;padding:5px 10px;font-size:12px;font-weight:700}.pill.gray{background:#eff2f6;color:#64748b}.search{margin-bottom:14px;width:100%;max-width:350px}.empty{padding:22px;text-align:center;color:#64748b}@media(max-width:800px){header{position:static;width:auto;padding:16px}header .school{margin-bottom:12px}nav{flex-direction:row;overflow-x:auto}nav a{white-space:nowrap;padding:9px}main{margin:0;padding:20px}.top h2{font-size:24px}.card{overflow-x:auto;padding:16px}td,th{white-space:nowrap}}
</style>'''
STYLE += '''<style>
:root{--navy:#1c2634;--blue:#284f70;--muted:#6a7481;--line:#e0e5e9}body{background:#f6f7f8;color:#202a35;font-family:system-ui,-apple-system,Segoe UI,Arial}header{background:#1c2634}header h1{font-size:23px;font-weight:720;letter-spacing:-.7px}.brand-dot{color:#81b4ca}nav a{border-radius:5px;font-weight:500}nav a:hover,nav a.active{background:#334252}main{max-width:1400px}.top h2{font-size:26px;font-weight:680}.card{border-radius:8px;box-shadow:none}button,.btn{background:#284f70;border-radius:5px}input,select,textarea{border-radius:5px}button.secondary,.btn.secondary{background:#eef1f3;color:#273746}.scan-layout{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(270px,1fr);gap:20px;align-items:start}.scan-primary,.scan-side{background:#fff;border:1px solid var(--line);border-radius:8px;padding:28px}.scan-heading{display:flex;justify-content:space-between;gap:20px}.scan-heading h3{font-size:23px;letter-spacing:-.5px;margin:6px 0 8px}.scan-heading p,.scan-help{color:var(--muted);font-size:13px;line-height:1.6}.eyebrow{font-size:10px;letter-spacing:1.2px;color:#738092;font-weight:750}.scan-counter{font-size:11px;color:#647383;white-space:nowrap}.mode-switch{display:flex;border-bottom:1px solid var(--line);margin:25px 0}.mode-switch a{padding:12px 22px;color:#657180;text-decoration:none;font-weight:600;font-size:13px;border-bottom:2px solid transparent}.mode-switch a.selected{color:#284f70;border-color:#284f70}.scan-label{display:block;font-size:12px;font-weight:700;margin:0 0 8px}.scan-input-row{display:flex;gap:9px}.scan-input-row input{flex:1;width:100%;font-size:17px;padding:15px}.scan-input-row button{min-width:100px}.scan-current{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:25px;padding:20px;background:#f6f8f9;border:1px solid #e7eaed;border-radius:6px}.scan-person{display:flex;gap:10px;align-items:center;margin-top:9px}.scan-person span{color:#75808d;font-size:13px}.text-link{font-size:12px}.scan-confirm{margin-top:20px;padding:20px;border:1px solid #cbdce4;background:#f5f9fa;border-radius:6px}.scan-confirm h3{font-size:20px}.scan-confirm h3 span{font-size:14px;font-weight:400;color:#526477}.scan-confirm form{display:grid;gap:15px}.scan-alert{padding:12px 15px;background:#eaf2f6;border-left:3px solid #396783;color:#23475d;margin:15px 0;font-size:13px}.scan-side h3{font-size:18px;margin:8px 0 22px}.step{display:flex;gap:15px;margin:20px 0}.step>b{color:#6b8595;font-size:12px}.step strong{font-size:13px}.step p{margin:4px 0;color:#7a8590;font-size:12px;line-height:1.5}.aside-rule{height:1px;background:#e8ecef;margin:24px 0}.scan-side select{width:100%;font-size:13px}.label-links{display:flex;gap:15px;flex-wrap:wrap}.label-links a{font-size:12px;font-weight:650;color:#284f70}@media(max-width:1050px){.scan-layout{grid-template-columns:1fr}}@media(max-width:600px){.scan-primary,.scan-side{padding:18px}.scan-input-row{flex-direction:column}.scan-heading{flex-direction:column}}
</style>'''
STYLE += '<style>.card{padding:19px}.grid{gap:12px}.top{margin-bottom:18px}nav a{padding:11px 13px}.stat{font-size:29px}.actions{margin-bottom:12px}table a{font-weight:600}</style>'
def page(title,body,active=''):
 with conn() as c: school=c.execute("SELECT value FROM settings WHERE key='school'").fetchone()[0]
 links=[('/privacy','Datenschutz'),('/','Dashboard'),('/devices','Geräte'),('/classes','Klassen'),('/students','Schüler'),('/scan','Scan-Ausleihe'),('/class-issue','Klassenausleihe'),('/loans','Ausleihen'),('/contracts','Verträge'),('/settings','Schule'),('/account','Passwort')]
 nav=''.join(f'<a class="{"active" if active==path else ""}" href="{path}">{name}</a>' for path,name in links)
 body=re.sub(r'(<form\b[^>]*method=[\"\']?post[\"\']?[^>]*>)',lambda m:m.group(1)+'<input type="hidden" name="_csrf" value="'+esc(CSRF_CONTEXT.get())+'">',body,flags=re.I)
 return HTMLResponse(f'<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · relay.</title>{STYLE}</head><body><header><h1>relay<span class="brand-dot">.</span></h1><div class="school">{esc(school)}<br>Geräteverwaltung · Pilot</div><nav>{nav}<form method="post" action="/logout"><input type="hidden" name="_csrf" value="{esc(CSRF_CONTEXT.get())}"><button class="secondary">Abmelden</button></form></nav></header><main><div class="notice"><b>TESTSYSTEM</b> · Keine echten Schülerdaten eingeben. Zugang geschützt; weiterhin ausschließlich fiktive Daten verwenden.</div><div class="top"><h2>{esc(title)}</h2><span class="sub">relay. v0.11.1</span></div>{body}</main><script>function filterTable(id,q){{document.querySelectorAll("#"+id+" tbody tr").forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q.toLowerCase())?"":"none")}}</script></body></html>')
def esc(x):
 import html
 return html.escape(str(x or ''))
def go(path): return RedirectResponse(path,status_code=303)
@app.get('/')
def home():
 with conn() as c:
  n=c.execute('SELECT count(*) FROM devices').fetchone()[0]; active=c.execute('SELECT count(*) FROM loans WHERE returned IS NULL').fetchone()[0]; s=c.execute('SELECT count(*) FROM students').fetchone()[0]
 return page('Dashboard',f'<div class="grid"><div class="card"><div class="stat">{n}</div>Geräte</div><div class="card"><div class="stat">{active}</div>Ausgeliehen</div><div class="card"><div class="stat">{n-active}</div>Verfügbar</div><div class="card"><div class="stat">{s}</div>Schüler</div></div><div class="card">Start: <a href="/devices">Geräte verwalten</a> · <a href="/loans">Gerät ausgeben</a></div>')
def field(label,name,value='',required=False,kind='text'):
 return f'<label class="field">{esc(label)}<input type="{kind}" name="{name}" value="{esc(value)}" {"required" if required else ""}></label>'
DEVICE_STATES=('Aktiv','Reparatur','Defekt','Verloren','Ausgesondert')
def state_select(value='Aktiv'):
 return '<label class="field">Gerätestatus<select name="operational_state">'+''.join(f'<option value="{x}" {"selected" if x==value else ""}>{x}</option>' for x in DEVICE_STATES)+'</select></label>'
def validate_state(value):
 if value not in DEVICE_STATES:raise HTTPException(422,'Unbekannter Gerätestatus')
def can_issue(c,device_id):
 return bool(c.execute("SELECT 1 FROM devices WHERE id=? AND operational_state='Aktiv'",(device_id,)).fetchone())

@app.get('/devices')
def devices(status:str=''):
 with conn() as c:
  rows=c.execute('SELECT d.*,s.name AS borrower FROM devices d LEFT JOIN loans l ON l.device_id=d.id AND l.returned IS NULL LEFT JOIN students s ON s.id=l.student_id ORDER BY d.inventory').fetchall()
 tr=''.join(f'<tr><td><b>{esc(r["inventory"])}</b></td><td>{esc(r["model"]) or "—"}</td><td>{esc(r["serial"]) or "—"}</td><td>{esc(r["condition"]) or "—"}</td><td>{esc(r["operational_state"])}</td><td>{esc(r["borrower"]) if r["borrower"] else "Verfügbar" if r["operational_state"]=="Aktiv" else "Nicht ausleihbar"}</td><td><a href="/devices/{r["id"]}/edit">Bearbeiten</a> · <a href="/devices/{r["id"]}/history">Verlauf</a></td></tr>' for r in rows)
 form='<details class="card"><summary><b>Neues Gerät hinzufügen</b></summary><form method="post" action="/devices"><div class="formgrid">'+field('Inventarnummer','inventory',required=True)+field('Seriennummer','serial')+field('Modell','model')+field('Zustand / Beschreibung','condition')+state_select()+'</div><p>'+field('Notizen','notes')+'</p><button>Gerät hinzufügen</button></form></details>'
 filters='<label>Statusfilter <select id="device-state-filter" onchange="filterDevices()"><option value="">Alle</option>'+''.join(f'<option>{x}</option>' for x in DEVICE_STATES)+'</select></label>'
 script='''<script>function filterDevices(){const q=document.getElementById('device-search').value.toLowerCase(),v=document.getElementById('device-state-filter').value;document.querySelectorAll('#devtable tbody tr').forEach(r=>{r.hidden=!(r.textContent.toLowerCase().includes(q)&&(!v||r.cells[4].textContent===v));});}</script>'''
 body=f'<div class="card"><h3>Gerätebestand · {len(rows)}</h3><div class="actions"><a class="btn secondary" href="/devices/import">CSV importieren</a><a class="btn secondary" href="/devices/export.csv">CSV exportieren</a><a class="btn secondary" href="/labels/devices.pdf">Barcode-Etiketten</a></div><div class="formgrid"><label>Suche<input id="device-search" placeholder="Inventar, Modell, Seriennummer …" oninput="filterDevices()"></label>{filters}</div><div style="overflow-x:auto"><table id="devtable"><thead><tr><th>Inventar</th><th>Modell</th><th>Seriennummer</th><th>Zustand</th><th>Gerätestatus</th><th>Ausleihe</th><th>Aktionen</th></tr></thead><tbody>{tr}</tbody></table></div></div>{form}{script}'
 return page('Geräteverwaltung',body,'/devices')

@app.post('/devices')
def add_device(inventory:str=Form(...),serial:str=Form(''),model:str=Form(''),condition:str=Form(''),notes:str=Form(''),operational_state:str=Form('Aktiv')):
 validate_state(operational_state)
 if not inventory.strip():raise HTTPException(422,'Inventarnummer fehlt')
 try:
  with conn() as c:
   c.execute('INSERT INTO devices(inventory,serial,token,model,condition,notes,operational_state) VALUES(?,?,?,?,?,?,?)',(inventory.strip(),serial.strip(),secrets.token_urlsafe(18),model.strip(),condition.strip(),notes.strip(),operational_state))
   did=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   c.execute('INSERT INTO scan_codes(kind,entity_id,code) VALUES(?,?,?)',('device',did,f'G{did:07d}'))
 except sqlite3.IntegrityError:raise HTTPException(409,'Inventarnummer bereits vorhanden')
 return go('/devices')

@app.get('/devices/{device_id}/edit')
def edit_device(device_id:int):
 with conn() as c:r=c.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
 if not r:raise HTTPException(404)
 body=f'<div class="card"><h3>Gerät {esc(r["inventory"])} bearbeiten</h3><form method="post" action="/devices/{device_id}/edit"><div class="formgrid">'+field('Inventarnummer','inventory',r['inventory'],True)+field('Seriennummer','serial',r['serial'])+field('Modell','model',r['model'])+field('Zustand / Beschreibung','condition',r['condition'])+state_select(r['operational_state'])+'</div><p>'+field('Notizen','notes',r['notes'])+'</p><div class="actions"><button>Änderungen speichern</button><a class="btn secondary" href="/devices">Abbrechen</a></div></form></div>'
 return page('Gerät bearbeiten',body,'/devices')

@app.post('/devices/{device_id}/edit')
def update_device(device_id:int,inventory:str=Form(...),serial:str=Form(''),model:str=Form(''),condition:str=Form(''),notes:str=Form(''),operational_state:str=Form('Aktiv')):
 validate_state(operational_state)
 if not inventory.strip():raise HTTPException(422,'Inventarnummer fehlt')
 try:
  with conn() as c:
   if not c.execute('UPDATE devices SET inventory=?,serial=?,model=?,condition=?,notes=?,operational_state=? WHERE id=?',(inventory.strip(),serial.strip(),model.strip(),condition.strip(),notes.strip(),operational_state,device_id)).rowcount:raise HTTPException(404)
 except sqlite3.IntegrityError:raise HTTPException(409,'Inventarnummer bereits vergeben')
 return go('/devices')

@app.get('/devices/export.csv')
def export_devices():
 output=io.StringIO();writer=csv.writer(output,delimiter=';')
 writer.writerow(['Inventarnummer','Seriennummer','Modell','Zustand','Notizen','Gerätestatus'])
 with conn() as c:
  for r in c.execute('SELECT inventory,serial,model,condition,notes,operational_state FROM devices ORDER BY inventory'):
   writer.writerow([csv_safe_cell(v) for v in r])
 return Response(content='\ufeff'+output.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="relay-geraete.csv"'})

@app.get('/devices/import')
def device_import():
 body='''<div class="card"><h3>Geräte aus CSV übernehmen</h3><p>CSV-Datei aus Excel auswählen (UTF-8, Semikolon oder Komma). Vor dem Import wird eine Vorschau angezeigt. Bereits vorhandene Inventarnummern werden übersprungen.</p><p><b>Pflichtspalte:</b> Inventarnummer. Optional: Seriennummer, Modell, Zustand, Notizen, Gerätestatus.</p><form method="post" action="/devices/import/preview"><label>CSV-Datei<input type="file" id="csv-file" accept=".csv,text/csv"></label><label>CSV-Inhalt<textarea name="csv_text" id="csv-text" rows="9" placeholder="Inventarnummer;Seriennummer;Modell;Zustand;Notizen;Gerätestatus" required></textarea></label><button>Import prüfen</button></form></div><script>document.getElementById('csv-file').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;if(f.size>300000){alert('Maximal 300 KB');return;}document.getElementById('csv-text').value=await f.text();});</script>'''
 return page('CSV-Import',body,'/devices')

def parse_device_csv(raw):
 if len(raw.encode('utf-8'))>300000:raise HTTPException(413,'CSV zu groß (maximal 300 KB)')
 try:dialect=csv.Sniffer().sniff(raw[:4096],delimiters=';,\t')
 except csv.Error:raise HTTPException(422,'CSV-Trennzeichen nicht erkannt')
 reader=csv.DictReader(io.StringIO(raw.lstrip('\ufeff'),newline=''),dialect=dialect)
 if not reader.fieldnames:raise HTTPException(422,'Kopfzeile fehlt')
 aliases={'inventarnummer':'inventory','inventar':'inventory','inventory':'inventory','serial':'serial','seriennummer':'serial','modell':'model','model':'model','zustand':'condition','condition':'condition','notizen':'notes','notes':'notes','gerätestatus':'operational_state','geraetestatus':'operational_state','status':'operational_state'}
 mapping={key:aliases.get(key.strip().lower().replace(' ','').replace('_','')) for key in reader.fieldnames}
 if 'inventory' not in mapping.values():raise HTTPException(422,'Spalte Inventarnummer fehlt')
 rows=[]; seen=set()
 for n,row in enumerate(reader,start=2):
  if n>2001:raise HTTPException(422,'Maximal 2000 Datensätze pro Import')
  data={mapping[k]:(v or '').strip() for k,v in row.items() if k in mapping and mapping[k]}
  if not any(data.values()):continue
  inv=data.get('inventory','')
  if not inv or len(inv)>100:raise HTTPException(422,f'Zeile {n}: ungültige Inventarnummer')
  if inv in seen:raise HTTPException(422,f'Zeile {n}: doppelte Inventarnummer in CSV: {inv}')
  seen.add(inv)
  state=data.get('operational_state') or 'Aktiv'
  if state not in DEVICE_STATES:raise HTTPException(422,f'Zeile {n}: ungültiger Gerätestatus: {state}')
  if any(len(data.get(k,''))>1000 for k in ('serial','model','condition','notes')):raise HTTPException(422,f'Zeile {n}: Feld zu lang')
  rows.append((inv,data.get('serial',''),data.get('model',''),data.get('condition',''),data.get('notes',''),state))
 if not rows:raise HTTPException(422,'Keine Geräte in der Datei')
 return rows

@app.post('/devices/import/preview')
def device_import_preview(csv_text:str=Form(...)):
 rows=parse_device_csv(csv_text)
 with conn() as c:existing={r[0] for r in c.execute('SELECT inventory FROM devices')}
 new=[r for r in rows if r[0] not in existing];skip=len(rows)-len(new)
 preview=''.join('<tr>'+''.join(f'<td>{esc(x)}</td>' for x in r[:4])+'</tr>' for r in new[:12])
 body=f'<div class="card"><h3>Vorschau</h3><p><b>{len(new)} neue Geräte</b> · {skip} vorhandene Inventarnummern werden übersprungen.</p><table><tr><th>Inventar</th><th>Seriennummer</th><th>Modell</th><th>Zustand</th></tr>{preview}</table><p>Es werden nur neue Geräte angelegt. Bestehende Einträge werden nicht überschrieben.</p><form method="post" action="/devices/import/confirm"><textarea name="csv_text" hidden>{esc(csv_text)}</textarea><button {("disabled" if not new else "")}>Import bestätigen</button><a class="btn secondary" href="/devices/import">Abbrechen</a></form></div>'
 return page('CSV-Import prüfen',body,'/devices')

@app.post('/devices/import/confirm')
def device_import_confirm(csv_text:str=Form(...)):
 rows=parse_device_csv(csv_text);count=0
 with conn() as c:
  for inv,serial,model,condition,notes,state in rows:
   if c.execute('SELECT 1 FROM devices WHERE inventory=?',(inv,)).fetchone():continue
   c.execute('INSERT INTO devices(inventory,serial,token,model,condition,notes,operational_state) VALUES(?,?,?,?,?,?,?)',(inv,serial,secrets.token_urlsafe(18),model,condition,notes,state))
   did=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   c.execute('INSERT INTO scan_codes(kind,entity_id,code) VALUES(?,?,?)',('device',did,f'G{did:07d}'))
   count+=1
 audit('device_csv_import',str(count))
 return page('Import abgeschlossen',f'<div class="card"><h3>{count} Geräte importiert</h3><p>Bereits vorhandene Inventarnummern wurden nicht verändert.</p><a class="btn" href="/devices">Zur Geräteübersicht</a></div>','/devices')

@app.get('/devices/{device_id}/history')
def device_history(device_id:int):
 with conn() as c:
  device=c.execute('SELECT * FROM devices WHERE id=?',(device_id,)).fetchone()
  if not device:raise HTTPException(404)
  history=c.execute('SELECT l.*,s.name,s.class_name FROM loans l JOIN students s ON s.id=l.student_id WHERE l.device_id=? ORDER BY l.id DESC',(device_id,)).fetchall()
  barcode=c.execute('SELECT code FROM scan_codes WHERE kind=? AND entity_id=?',('device',device_id)).fetchone()
 rows=''.join(f'<tr><td>{esc(r["name"])} ({esc(r["class_name"])})</td><td>{esc(r["issued"][:16].replace("T"," "))}</td><td>{esc(r["returned"][:16].replace("T"," ")) if r["returned"] else "Aktiv"}</td><td><a href="/receipt/{r["id"]}">Beleg</a></td></tr>' for r in history)
 body=f'<div class="actions"><a class="btn secondary" href="/devices">Zurück zu Geräten</a><a class="btn secondary" href="/devices/{device_id}/edit">Bearbeiten</a><a class="btn secondary" href="/labels/devices.pdf">Etiketten drucken</a></div><div class="card"><h3>{esc(device["inventory"])}</h3><p><b>Scan-Code:</b> {esc(barcode["code"] if barcode else "—")} &nbsp; <b>Modell:</b> {esc(device["model"])} &nbsp; <b>Seriennummer:</b> {esc(device["serial"])}</p><p><b>Zustand:</b> {esc(device["condition"])} &nbsp; <b>Notizen:</b> {esc(device["notes"])}</p></div><div class="card"><h3>Ausleihhistorie</h3><table><thead><tr><th>Schüler</th><th>Ausgabe (UTC)</th><th>Rückgabe (UTC)</th><th>Beleg</th></tr></thead><tbody>{rows}</tbody></table></div>'
 return page('Geräteverlauf',body,'/devices')

@app.get('/classes')
def classes():
 with conn() as c:rows=c.execute('SELECT c.id,c.name,count(s.id) AS total FROM classes c LEFT JOIN students s ON s.class_name=c.name GROUP BY c.id ORDER BY c.name').fetchall()
 cards=''.join(f'<div class="card statcard"><div class="stat">{r["total"]}</div><b>Klasse {esc(r["name"])}</b><p class="sub">Schülerinnen und Schüler</p><div class="actions"><a href="/classes/{r["id"]}">Klasse öffnen</a><a href="/classes/{r["id"]}/edit">Bearbeiten</a></div></div>' for r in rows)
 return page('Klassen',f'<div class="card"><h3>Klasse anlegen</h3><form method="post" action="/classes" class="actions"><input name="name" required maxlength="40" placeholder="z. B. 7a"><button>Klasse hinzufügen</button></form></div><div class="grid">{cards}</div>','/classes')
@app.post('/classes')
def add_class(name:str=Form(...)):
 name=name.strip()
 if not name:raise HTTPException(400)
 try:
  with conn() as c:c.execute('INSERT INTO classes(name) VALUES(?)',(name,))
 except sqlite3.IntegrityError:raise HTTPException(409,'Klasse existiert bereits')
 return go('/classes')
@app.get('/classes/{class_id}')
def class_detail(class_id:int):
 with conn() as c:
  cl=c.execute('SELECT * FROM classes WHERE id=?',(class_id,)).fetchone()
  if not cl:raise HTTPException(404)
  rows=c.execute("""SELECT s.id,s.name,s.class_name,d.id AS device_id,d.inventory,l.issued
    FROM students s LEFT JOIN loans l ON l.student_id=s.id AND l.returned IS NULL
    LEFT JOIN devices d ON d.id=l.device_id
    WHERE s.class_name=? ORDER BY s.name,d.inventory""",(cl['name'],)).fetchall()
  total=c.execute('SELECT count(*) FROM students WHERE class_name=?',(cl['name'],)).fetchone()[0]
  assigned=c.execute('SELECT count(DISTINCT student_id) FROM loans l JOIN students s ON s.id=l.student_id WHERE s.class_name=? AND l.returned IS NULL',(cl['name'],)).fetchone()[0]
 tr=''
 for r in rows:
  device_link = ('<a href="/devices/{}/history">{}</a>'.format(r['device_id'],esc(r['inventory'])) if r['inventory'] else '—')
  status = 'Ausgeliehen' if r['inventory'] else 'Kein Gerät'
  status_class = '' if r['inventory'] else 'gray'
  tr += '<tr><td><b>{}</b></td><td>{}</td><td><span class="pill {}">{}</span></td><td><a href="/students/{}/edit">Bearbeiten</a></td></tr>'.format(esc(r['name']),device_link,status_class,status,r['id'])
 body=f'<div class="actions"><a class="btn secondary" href="/classes">Alle Klassen</a><a class="btn secondary" href="/students?class_name={esc(cl["name"])}">Schüler verwalten</a><a class="btn secondary" href="/scan">Scan-Ausleihe</a></div><div class="grid"><div class="card statcard"><div class="stat">{total}</div>Schüler</div><div class="card statcard"><div class="stat">{assigned}</div>Mit mindestens einem Gerät</div><div class="card statcard"><div class="stat">{total-assigned}</div>Ohne Gerät</div></div><div class="card"><h3>Klasse {esc(cl["name"])}</h3><input class="search" placeholder="Schüler suchen" oninput="filterTable(&quot;class-table&quot;,this.value)"><table id="class-table"><thead><tr><th>Schüler</th><th>Gerät</th><th>Status</th><th></th></tr></thead><tbody>{tr}</tbody></table></div>'
 return page('Klasse '+cl['name'],body,'/classes')

@app.get('/classes/{class_id}/edit')
def edit_class(class_id:int):
 with conn() as c:r=c.execute('SELECT * FROM classes WHERE id=?',(class_id,)).fetchone()
 if not r:raise HTTPException(404)
 return page('Klasse bearbeiten',f'<div class="card"><form method="post" action="/classes/{class_id}/edit">'+field('Klassenbezeichnung','name',r['name'],True)+'<p><button>Speichern</button> <a href="/classes">Abbrechen</a></p></form></div>','/classes')
@app.post('/classes/{class_id}/edit')
def update_class(class_id:int,name:str=Form(...)):
 name=name.strip()
 if not name:raise HTTPException(400)
 try:
  with conn() as c:
   old=c.execute('SELECT name FROM classes WHERE id=?',(class_id,)).fetchone()
   if not old:raise HTTPException(404)
   c.execute('UPDATE classes SET name=? WHERE id=?',(name,class_id))
   c.execute('UPDATE students SET class_name=? WHERE class_name=?',(name,old['name']))
 except sqlite3.IntegrityError:raise HTTPException(409,'Klasse existiert bereits')
 return go('/classes')
@app.get('/students')
def students(class_name:str=''):
 with conn() as c:
  rows=c.execute('SELECT * FROM students WHERE (?="" OR class_name=?) ORDER BY class_name,name',(class_name,class_name)).fetchall()
  cs=c.execute('SELECT name FROM classes ORDER BY name').fetchall()
 opts=''.join(f'<option value="{esc(r["name"])}" {"selected" if r["name"]==class_name else ""}>{esc(r["name"])}</option>' for r in cs)
 tr=''.join(f'<tr><td><b>{esc(r["name"])}</b></td><td>{esc(r["class_name"])}</td><td><a href="/students/{r["id"]}/edit">Bearbeiten</a></td></tr>' for r in rows)
 return page('Schülerverwaltung',f'<div class="card"><h3>Schüler hinzufügen</h3><form method="post" action="/students" class="actions"><input name="name" required placeholder="Name (nur Testdaten)"><select name="class_name" required><option value="">Klasse wählen</option>{opts}</select><button>Hinzufügen</button></form></div><div class="card"><h3>Schülerübersicht · {len(rows)}</h3><form method="get" class="actions"><select name="class_name" onchange="this.form.submit()"><option value="">Alle Klassen</option>{opts}</select><a href="/classes">Klassen verwalten</a></form><p><input class="search" placeholder="Namen suchen …" oninput="filterTable(&quot;studenttable&quot;,this.value)"></p><table id="studenttable"><thead><tr><th>Name</th><th>Klasse</th><th>Aktion</th></tr></thead><tbody>{tr}</tbody></table></div>','/students')
@app.post('/students')
def add_student(name:str=Form(...),class_name:str=Form(...)):
 with conn() as c:
  if not c.execute('SELECT 1 FROM classes WHERE name=?',(class_name,)).fetchone():raise HTTPException(400,'Klasse nicht vorhanden')
  c.execute('INSERT INTO students(name,class_name) VALUES(?,?)',(name.strip(),class_name))
 ensure_scan_code('student', get_last_id('students',name))
 return go('/students')
@app.get('/students/{student_id}/edit')
def edit_student(student_id:int):
 with conn() as c:
  r=c.execute('SELECT * FROM students WHERE id=?',(student_id,)).fetchone()
  cs=c.execute('SELECT name FROM classes ORDER BY name').fetchall()
 if not r:raise HTTPException(404)
 opts=''.join(f'<option value="{esc(x["name"])}" {"selected" if x["name"]==r["class_name"] else ""}>{esc(x["name"])}</option>' for x in cs)
 return page('Schüler bearbeiten',f'<div class="card"><form method="post" action="/students/{student_id}/edit"><div class="formgrid">'+field('Name','name',r['name'],True)+f'<label class="field">Klasse<select name="class_name">{opts}</select></label></div><p><button>Speichern</button> <a href="/students">Abbrechen</a></p></form></div>','/students')
@app.post('/students/{student_id}/edit')
def update_student(student_id:int,name:str=Form(...),class_name:str=Form(...)):
 with conn() as c:
  if not c.execute('SELECT 1 FROM classes WHERE name=?',(class_name,)).fetchone():raise HTTPException(400)
  if not c.execute('UPDATE students SET name=?,class_name=? WHERE id=?',(name.strip(),class_name,student_id)).rowcount:raise HTTPException(404)
 return go('/students')
@app.get('/privacy')
def privacy_get():
 with conn() as c:
  students=c.execute("SELECT s.id,s.name,s.class_name,COUNT(l.id) AS total, SUM(CASE WHEN l.returned IS NULL AND l.id IS NOT NULL THEN 1 ELSE 0 END) AS active FROM students s LEFT JOIN loans l ON l.student_id=s.id GROUP BY s.id ORDER BY s.class_name,s.name").fetchall()
  audit_count=c.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
 rows=''
 for r in students:
  if r['name'].startswith('Gelöschter Datensatz '):continue
  if r['active']:
   action='Aktive Ausleihe'
  else:
   action=f'<form method="post" action="/privacy/anonymize/{r["id"]}" onsubmit="return confirm(\'Schülerdatensatz anonymisieren?\')"><button>Anonymisieren</button></form>'
  rows+=f'<tr><td>{esc(r["name"])}</td><td>{esc(r["class_name"])}</td><td>{r["total"]}</td><td>{action}</td></tr>'
 body=f'''<div class="card"><h3>Personenbezogene Daten</h3><p>Schüler ohne aktive Ausleihe können anonymisiert werden. Die Ausleihhistorie bleibt erhalten, Name und Klasse werden ersetzt. Heruntergeladene PDFs und alte Backups bleiben unverändert.</p><table><thead><tr><th>Schüler</th><th>Klasse</th><th>Vorgänge</th><th>Aktion</th></tr></thead><tbody>{rows}</tbody></table></div><div class="card"><h3>Technische Protokolle</h3><p>{audit_count} Protokolleinträge</p><form method="post" action="/privacy/cleanup"><label class="field">Audit-Einträge älter als (Tage)<input type="number" name="days" value="90" min="30" max="3650" required></label><p><button>Alte Protokolle und abgelaufene Sitzungen bereinigen</button></p></form><p class="sub">Aufbewahrungsfristen für Verträge und Ausleihdaten müssen schulisch festgelegt werden.</p></div>'''
 return page('Datenschutz und Löschung',body,'/privacy')

@app.post('/privacy/anonymize/{student_id}')
def privacy_anonymize(student_id:int):
 with conn() as c:
  r=c.execute('SELECT id,name FROM students WHERE id=?',(student_id,)).fetchone()
  if not r:raise HTTPException(404)
  if c.execute('SELECT 1 FROM loans WHERE student_id=? AND returned IS NULL',(student_id,)).fetchone():raise HTTPException(409,'Aktive Ausleihe vorhanden')
  c.execute('UPDATE students SET name=?,class_name=? WHERE id=?',(f'Gelöschter Datensatz {student_id}','—',student_id))
  c.execute("DELETE FROM scan_codes WHERE kind='student' AND entity_id=?",(student_id,))
 audit('student_anonymized',f'id={student_id}')
 return go('/privacy')

@app.post('/privacy/cleanup')
def privacy_cleanup(days:int=Form(90)):
 if not 30<=days<=3650:raise HTTPException(400)
 cutoff=datetime.fromtimestamp(time.time()-days*86400,timezone.utc).isoformat()
 with conn() as c:
  c.execute('DELETE FROM audit_log WHERE at<?',(cutoff,))
  c.execute('DELETE FROM sessions WHERE expires<?',(int(time.time()),))
  c.execute('DELETE FROM login_attempts WHERE timestamp<?',(int(time.time())-900,))
 audit('privacy_cleanup',f'audit_retention_days={days}')
 return go('/privacy')

@app.get('/loans')
def loans():
 with conn() as c:
  ds=c.execute("SELECT * FROM devices WHERE operational_state='Aktiv' AND id NOT IN (SELECT device_id FROM loans WHERE returned IS NULL) ORDER BY inventory").fetchall()
  ss=c.execute('SELECT * FROM students ORDER BY class_name,name').fetchall()
  ls=c.execute('SELECT l.*,d.inventory,s.name FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id ORDER BY l.id DESC').fetchall()
 optionsd=''.join(f'<option value="{r["id"]}">{esc(r["inventory"])}</option>' for r in ds)
 optionss=''.join(f'<option value="{r["id"]}">{esc(r["name"])} ({esc(r["class_name"])})</option>' for r in ss)
 tr=''.join(f'<tr><td>{esc(r["inventory"])}</td><td>{esc(r["name"])}</td><td>{esc(r["issued"][:10])}</td><td>{"Zurück " + esc(r["returned"][:10]) if r["returned"] else "Aktiv"}</td><td><a href="/receipt/{r["id"]}">PDF</a> '+(f'<form style="display:inline" method="post" action="/return/{r["id"]}"><button>Rückgabe</button></form>' if not r['returned'] else '')+'</td></tr>' for r in ls)
 return page('Ausleihen',f'<div class="card"><h3>Neue Ausgabe</h3><form method="post" action="/loans"><label>Gerät <select name="device_id">{optionsd}</select></label><label>Schüler <select name="student_id">{optionss}</select></label><input name="accessories" placeholder="Zubehör (optional)"><button {"disabled" if not ds or not ss else ""}>Ausgeben</button></form></div><div class="card"><table><tr><th>Gerät</th><th>Schüler</th><th>Ausgabe</th><th>Status</th><th>Aktion</th></tr>{tr}</table></div>')
@app.post('/loans')
def create_loan(device_id:int=Form(...),student_id:int=Form(...),accessories:str=Form('')):
 try:
  with conn() as c:
   if not can_issue(c,device_id):raise HTTPException(409,'Gerät nicht ausleihbar')
   c.execute('INSERT INTO loans(device_id,student_id,issued,accessories) VALUES(?,?,?,?)',(device_id,student_id,datetime.now(timezone.utc).isoformat(),accessories))
 except sqlite3.IntegrityError:raise HTTPException(409,'Gerät bereits ausgeliehen oder ungültige Zuordnung')
 return go('/loans')
@app.post('/return/{loan_id}')
def return_loan(loan_id:int):
 with conn() as c:c.execute('UPDATE loans SET returned=? WHERE id=? AND returned IS NULL',(datetime.now(timezone.utc).isoformat(),loan_id))
 return go('/loans')
@app.get('/receipt/{loan_id}')
def receipt(loan_id:int):
 with conn() as c:
  r=c.execute('SELECT l.*,d.inventory,d.serial,s.name,s.class_name FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id WHERE l.id=?',(loan_id,)).fetchone()
  school=c.execute("SELECT value FROM settings WHERE key='school'").fetchone()[0]
 if not r:raise HTTPException(404)
 b=io.BytesIO();p=canvas.Canvas(b,pagesize=(595,842));p.setFont('Helvetica-Bold',18);p.drawString(48,780,'relay. - DEMO-Ausleihbeleg');p.setFont('Helvetica',11)
 lines=[f'Schule: {school}',f'Belegnummer: {r["id"]}',f'Schueler: {r["name"]} / {r["class_name"]}',f'Inventarnummer: {r["inventory"]}',f'Seriennummer: {r["serial"] or "-"}',f'Ausgabe (UTC): {r["issued"][:19]}',f'Zubehoer: {r["accessories"] or "-"}',f'Rueckgabe (UTC): {r["returned"][:19] if r["returned"] else "offen"}']
 for i,line in enumerate(lines):p.drawString(48,730-i*32,line[:95].encode('latin-1','replace').decode('latin-1'))
 p.setFont('Helvetica-Bold',11);p.drawString(48,390,'NUR TESTBELEG - KEIN RECHTLICH GEPRUEFTER LEIHVERTRAG');p.line(48,280,250,280);p.line(320,280,545,280);p.setFont('Helvetica',10);p.drawString(48,265,'Ausgebende Person');p.drawString(320,265,'Empfang bestaetigt');p.save();b.seek(0)
 return StreamingResponse(b,media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="demo-beleg-{loan_id}.pdf"'})

def get_last_id(table, value):
 column='inventory' if table=='devices' else 'name'
 with conn() as c:
  r=c.execute(f'SELECT id FROM {table} WHERE {column}=? ORDER BY id DESC LIMIT 1',(value.strip(),)).fetchone()
 return r[0] if r else None

def ensure_scan_code(kind,entity_id):
 if entity_id is None:return
 with conn() as c:
  c.execute('INSERT OR IGNORE INTO scan_codes(kind,entity_id,code) VALUES(?,?,?)',(kind,entity_id,('S' if kind=='student' else 'G')+f'{entity_id:07d}'))

def lookup_scan(raw):
 code=raw.strip().upper()
 with conn() as c:
  row=c.execute('SELECT kind,entity_id FROM scan_codes WHERE code=?',(code,)).fetchone()
  if row:return row['kind'],row['entity_id']
  # Existing inventory numbers can also be scanned, including printed inventory labels.
  row=c.execute('SELECT id FROM devices WHERE upper(inventory)=?',(code,)).fetchone()
  if row:return 'device',row['id']
 return None,None

def scan_panel(message='',kind='issue',student_id=None,device_id=None,return_loan=None):
 with conn() as c:
  students=c.execute('SELECT id,name,class_name FROM students ORDER BY class_name,name').fetchall()
  st=c.execute('SELECT id,name,class_name FROM students WHERE id=?',(student_id,)).fetchone() if student_id else None
  dev=c.execute('SELECT inventory,model FROM devices WHERE id=?',(device_id,)).fetchone() if device_id else None
 mode='return' if kind=='return' else 'issue'
 opts='<option value="">Schüler aus Liste auswählen …</option>'+''.join(f'<option value="{r["id"]}" {"selected" if student_id==r["id"] else ""}>{esc(r["class_name"])} · {esc(r["name"])}</option>' for r in students)
 with conn() as c:
  free=c.execute("SELECT d.id,d.inventory,COALESCE(d.model,'') model FROM devices d WHERE d.operational_state='Aktiv' AND NOT EXISTS (SELECT 1 FROM loans l WHERE l.device_id=d.id AND l.returned IS NULL) ORDER BY d.inventory").fetchall()
  busy=c.execute("SELECT l.id,d.inventory,s.name,s.class_name FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id WHERE l.returned IS NULL ORDER BY d.inventory").fetchall()
 classes=sorted({r['class_name'] for r in students})
 class_opts='<option value="">Alle Klassen</option>'+''.join(f'<option value="{esc(x)}">{esc(x)}</option>' for x in classes)
 free_opts='<option value="">Gerät auswählen …</option>'+''.join(f'<option value="{r["id"]}">{esc(r["inventory"])} · {esc(r["model"] or "iPad")}</option>' for r in free)
 busy_opts='<option value="">Ausgeliehenes Gerät auswählen …</option>'+''.join(f'<option value="{r["id"]}">{esc(r["inventory"])} · {esc(r["name"])} ({esc(r["class_name"])})</option>' for r in busy)
 manual_issue=f'''<form method="post" action="/scan/manual/issue" class="manual-form"><div class="formgrid"><label class="field">Klasse<select id="manual-class">{class_opts}</select></label><label class="field">Schüler<select id="manual-student" name="student_id" required><option value="">Schüler auswählen …</option>{opts.split('</option>',1)[1] if False else ''.join(f'<option data-class="{esc(r["class_name"])}" value="{r["id"]}" {"selected" if student_id==r["id"] else ""}>{esc(r["name"])} · {esc(r["class_name"])} (S{r["id"]:07d})</option>' for r in students)}</select></label><label class="field">Verfügbares Gerät<select name="device_id" required>{free_opts}</select></label></div><p><button>Auswahl prüfen</button></p></form>'''
 manual_return=f'''<form method="post" action="/scan/manual/return" class="manual-form"><label class="field">Ausgeliehenes Gerät<select name="loan_id" required>{busy_opts}</select></label><p><button>Rückgabe prüfen</button></p></form>'''
 manual=f'''<div class="card" style="margin-top:20px"><div class="eyebrow">OHNE SCANNER</div><h3>Manuelle {"Rückgabe" if mode=="return" else "Ausleihe"}</h3><p class="scan-help">Auswählen statt Barcode eingeben. Die Bestätigung erfolgt im nächsten Schritt.</p>{manual_return if mode=="return" else manual_issue}</div><script>document.addEventListener('DOMContentLoaded',()=>{{const cl=document.getElementById('manual-class'),st=document.getElementById('manual-student');if(!cl||!st)return;cl.addEventListener('change',()=>{{st.value='';for(const o of st.options){{if(!o.value)continue;o.hidden=!!cl.value&&o.dataset.class!==cl.value;}}}});}});</script>'''
 note=f'<div class="scan-alert" role="status">{esc(message)}</div>' if message else ''
 selected=f'<strong>{esc(st["name"])}</strong><span>{esc(st["class_name"])}</span>' if st else '<span>Warte auf Schülerbarcode</span>'
 content=f'''<div class="scan-layout"><section class="scan-primary"><div class="scan-heading"><div><div class="eyebrow">SCHNELLERFASSUNG</div><h3>Scannen und zuordnen</h3><p>Ein Eingabefeld für Schüler und Geräte. Der Scanner sendet den Code mit Enter.</p></div><span class="scan-counter">Code 128</span></div>
 <div class="mode-switch"><a class="{"selected" if mode=="issue" else ""}" href="/scan?mode=issue">Ausgabe</a><a class="{"selected" if mode=="return" else ""}" href="/scan?mode=return">Rückgabe</a></div>
 {note}
 <form method="post" action="/scan/resolve" id="scanform"><input type="hidden" name="mode" value="{mode}"><input type="hidden" name="student_id" value="{student_id or ''}"><label for="scan-code" class="scan-label">Barcode</label><div class="scan-input-row"><input id="scan-code" name="code" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="{"Gerät scannen …" if mode=="return" else "Schüler- oder Gerätebarcode scannen …"}" required autofocus><button type="submit">Prüfen</button></div><p class="scan-help">Nach dem Scan wird automatisch geprüft. Keine Ausgabe ohne Bestätigung.</p></form>
 <div class="scan-current"><div><div class="eyebrow">AKTUELLER SCHÜLER</div><div class="scan-person">{selected}</div></div>{'<a href="/scan" class="text-link">Auswahl aufheben</a>' if st else ''}</div>
 {f'<div class="scan-confirm"><div class="eyebrow">AUSGABE PRÜFEN</div><h3>{esc(dev["inventory"])} <span>→ {esc(st["name"])}</span></h3><form method="post" action="/scan/confirm"><input type="hidden" name="student_id" value="{student_id}"><input type="hidden" name="device_id" value="{device_id}"><label class="field">Mitgegebenes Zubehör<input name="accessories" placeholder="z. B. Hülle, Ladekabel"></label><div class="actions"><button>Ausgabe bestätigen</button><a href="/scan" class="btn secondary">Abbrechen</a></div></form></div>' if st and dev else ''}
 {f'<div class="scan-confirm"><div class="eyebrow">RÜCKGABE PRÜFEN</div><h3>{esc(return_loan["inventory"])} <span>· {esc(return_loan["name"])}, {esc(return_loan["class_name"])}</span></h3><form method="post" action="/scan/return"><input type="hidden" name="loan_id" value="{return_loan["id"]}"><div class="actions"><button>Rückgabe bestätigen</button><a href="/scan?mode=return" class="btn secondary">Abbrechen</a></div></form></div>' if return_loan else ''}
 </section><aside class="scan-side"><div class="eyebrow">ABLAUF</div><h3>So funktioniert’s</h3><div class="step"><b>01</b><div><strong>Schüler scannen</strong><p>Schülerkarte oder Auswahl aus der Liste.</p></div></div><div class="step"><b>02</b><div><strong>Gerät scannen</strong><p>Die Verfügbarkeit wird geprüft.</p></div></div><div class="step"><b>03</b><div><strong>Bestätigen</strong><p>Die Zuordnung wird gespeichert.</p></div></div><div class="aside-rule"></div><form method="post" action="/scan/select"><label class="scan-label">Ohne Schülerkarte</label><select name="student_id" required>{opts}</select><button class="secondary" style="margin-top:10px">Schüler auswählen</button></form><div class="aside-rule"></div><div class="eyebrow">ETIKETTEN</div><p class="scan-help">Druckvorlagen für Geräte und Schüler-Testkarten.</p><div class="label-links"><a href="/labels/devices.pdf">Geräte-PDF</a><a href="/labels/students.pdf">Schüler-PDF</a></div></aside></div>
 <script>document.addEventListener('DOMContentLoaded',()=>{{const f=document.getElementById('scanform'),i=document.getElementById('scan-code');if(!f||!i)return;i.focus();document.addEventListener('keydown',e=>{{if(e.key==='Escape'){{i.value='';i.focus()}}}});document.addEventListener('click',e=>{{if(!e.target.closest('input,select,button,a,textarea'))i.focus()}})}});</script>'''
 return page('Scan-Ausleihe',content+manual,'/scan')

@app.get('/scan')
def scan_home(mode:str='issue'):return scan_panel(kind='return' if mode=='return' else 'issue')

@app.post('/scan/select')
def scan_select(student_id:int=Form(...)):
 with conn() as c:r=c.execute('SELECT id FROM students WHERE id=?',(student_id,)).fetchone()
 if not r:raise HTTPException(404,'Schüler nicht gefunden')
 return scan_panel(student_id=student_id)

@app.post('/scan/manual/issue')
def manual_issue(student_id:int=Form(...),device_id:int=Form(...)):
 with conn() as c:
  st=c.execute('SELECT id FROM students WHERE id=?',(student_id,)).fetchone()
  dev=c.execute("SELECT id FROM devices WHERE id=? AND operational_state='Aktiv'",(device_id,)).fetchone()
  active=c.execute('SELECT 1 FROM loans WHERE device_id=? AND returned IS NULL',(device_id,)).fetchone()
 if not st or not dev:return scan_panel('Schüler oder Gerät nicht gefunden.')
 if active:return scan_panel('Gerät bereits ausgeliehen. Bitte anderes Gerät auswählen.',student_id=student_id)
 return scan_panel(student_id=student_id,device_id=device_id)

@app.post('/scan/manual/return')
def manual_return(loan_id:int=Form(...)):
 with conn() as c:
  r=c.execute('SELECT l.id,d.inventory,s.name,s.class_name FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id WHERE l.id=? AND l.returned IS NULL',(loan_id,)).fetchone()
 if not r:return scan_panel('Keine aktive Ausleihe gefunden.',kind='return')
 return scan_panel(kind='return',return_loan=r)

@app.post('/scan/resolve')
def scan_resolve(code:str=Form(...),mode:str=Form('issue'),student_id:str=Form('')):
 sid=int(student_id) if student_id.isdigit() else None
 kind,entity_id=lookup_scan(code)
 if not kind:return scan_panel('Barcode nicht gefunden. Kennung bitte prüfen.',kind=mode,student_id=sid)
 if mode=='return':
  if kind!='device':return scan_panel('Für eine Rückgabe bitte einen Gerätebarcode scannen.',kind='return')
  with conn() as c:
   r=c.execute('SELECT l.id,d.inventory,s.name,s.class_name FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id WHERE l.device_id=? AND l.returned IS NULL',(entity_id,)).fetchone()
  if not r:return scan_panel('Dieses Gerät ist nicht ausgeliehen.',kind='return')
  return scan_panel(kind='return',return_loan=r)
 if kind=='student':return scan_panel(student_id=entity_id)
 if not sid:return scan_panel('Zuerst einen Schüler auswählen oder scannen.')
 with conn() as c:
  existing=c.execute('SELECT 1 FROM loans WHERE device_id=? AND returned IS NULL',(entity_id,)).fetchone()
  issuable=can_issue(c,entity_id)
  student=c.execute('SELECT 1 FROM students WHERE id=?',(sid,)).fetchone()
 if not student:return scan_panel('Schüler nicht gefunden.')
 if existing:return scan_panel('Gerät bereits ausgeliehen. Keine Doppelvergabe möglich.',student_id=sid)
 if not issuable:return scan_panel('Gerät ist gesperrt (Reparatur/Defekt/Verlust/Aussonderung).',student_id=sid)
 return scan_panel(student_id=sid,device_id=entity_id)

@app.post('/scan/confirm')
def scan_confirm(student_id:int=Form(...),device_id:int=Form(...),accessories:str=Form('')):
 try:
  with conn() as c:
   if not c.execute('SELECT 1 FROM students WHERE id=?',(student_id,)).fetchone():raise HTTPException(404)
   if not can_issue(c,device_id):raise HTTPException(409,'Gerät nicht ausleihbar')
   c.execute('INSERT INTO loans(device_id,student_id,issued,accessories) VALUES(?,?,?,?)',(device_id,student_id,datetime.now(timezone.utc).isoformat(),accessories.strip()))
 except sqlite3.IntegrityError:return scan_panel('Ausgabe nicht möglich: Gerät bereits verliehen oder ungültige Zuordnung.')
 return scan_panel('Ausgabe erfolgreich gespeichert. Nächsten Schüler scannen.')

@app.post('/scan/return')
def scan_return(loan_id:int=Form(...)):
 with conn() as c:
  changed=c.execute('UPDATE loans SET returned=? WHERE id=? AND returned IS NULL',(datetime.now(timezone.utc).isoformat(),loan_id)).rowcount
 return scan_panel('Rückgabe gespeichert.' if changed else 'Ausleihe nicht mehr aktiv.',kind='return')

@app.get('/labels/{kind}.pdf')
def barcode_labels(kind:str):
 if kind not in ('devices','students'):raise HTTPException(404)
 with conn() as c:
  table='devices' if kind=='devices' else 'students'
  rows=c.execute(f'''SELECT s.code, t.* FROM {table} t JOIN scan_codes s ON s.entity_id=t.id AND s.kind=? ORDER BY t.id''',('device' if kind=='devices' else 'student',)).fetchall()
 b=io.BytesIO();p=canvas.Canvas(b,pagesize=(595,842))
 for i,r in enumerate(rows):
  slot=i%16
  if i and slot==0:p.showPage()
  col=slot%2;row=slot//2;x=35+col*282;y=760-row*94
  p.setStrokeColorRGB(.75,.8,.87);p.rect(x,y-20,265,82)
  p.setFillColorRGB(0,0,0);p.setFont('Helvetica-Bold',10)
  title=r['inventory'] if kind=='devices' else r['name']
  p.drawString(x+9,y+44,str(title)[:38].encode('latin-1','replace').decode('latin-1'))
  if kind=='students':p.setFont('Helvetica',9);p.drawString(x+9,y+32,str(r['class_name'])[:24])
  code128.Code128(r['code'],barHeight=26,barWidth=1.05,humanReadable=True).drawOn(p,x+9,y-7)
 p.save();b.seek(0)
 return StreamingResponse(b,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="leihpilot-{kind}-barcodes.pdf"'})

@app.get('/settings')
def settings():
 with conn() as c:
  school=c.execute("SELECT value FROM settings WHERE key='school'").fetchone()[0]
  template=c.execute("SELECT value FROM settings WHERE key='contract_template'").fetchone()[0]
 body=f'''<div class="card"><h3>Schule</h3><form method="post" action="/settings"><label class="field">Schulname<input name="school" value="{esc(school)}" required></label><p><button>Speichern</button></p></form></div><div class="card"><h3>Vertragsvorlage</h3><p class="sub">Entwurf für den Testbetrieb. Vertragsbedingungen müssen vor dem realen Einsatz fachlich und rechtlich geprüft werden.</p><form method="post" action="/settings/template"><label class="field">Vertragstext<textarea name="template" rows="13" maxlength="12000" required>{esc(template)}</textarea></label><p><button>Vorlage speichern</button></p></form></div>'''
 return page('Schuleinstellungen',body,'/settings')
@app.post('/settings')
def save_settings(school:str=Form(...)):
 with conn() as c:c.execute("UPDATE settings SET value=? WHERE key='school'",(school.strip(),))
 return go('/settings')
@app.post('/settings/template')
def save_contract_template(template:str=Form(...)):
 if not template.strip() or len(template)>12000:raise HTTPException(400,'Vorlage ungültig')
 with conn() as c:c.execute("UPDATE settings SET value=? WHERE key='contract_template'",(template.strip(),))
 return go('/settings')

@app.get('/contracts')
def contracts():
 with conn() as c:
  rows=c.execute('''SELECT l.id,l.issued,l.returned,d.inventory,s.name,s.class_name,COALESCE(cd.status,'Entwurf') AS status
  FROM loans l JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id
  LEFT JOIN contract_docs cd ON cd.loan_id=l.id ORDER BY l.id DESC''').fetchall()
 tr=''.join(f'''<tr><td>LV-{r['id']:05d}</td><td>{esc(r['name'])} · {esc(r['class_name'])}</td><td>{esc(r['inventory'])}</td><td>{esc(r['status'])}</td><td><a href="/contracts/{r['id']}">Öffnen</a></td></tr>''' for r in rows)
 return page('Verträge',f'''<div class="card"><h3>Leihverträge</h3><p class="sub">Dokumente werden aus vorhandenen Ausleihen erzeugt. Unterschriften werden nicht digital erfasst.</p><input class="search" placeholder="Suche" oninput="filterTable('contracttable',this.value)"><table id="contracttable"><thead><tr><th>Nummer</th><th>Schüler</th><th>Gerät</th><th>Status</th><th></th></tr></thead><tbody>{tr}</tbody></table></div>''','/contracts')

def loan_contract_data(loan_id):
 with conn() as c:
  r=c.execute('''SELECT l.*,d.inventory,d.serial,d.model,d.condition,s.name,s.class_name FROM loans l
  JOIN devices d ON d.id=l.device_id JOIN students s ON s.id=l.student_id WHERE l.id=?''',(loan_id,)).fetchone()
  school=c.execute("SELECT value FROM settings WHERE key='school'").fetchone()[0]
  template=c.execute("SELECT value FROM settings WHERE key='contract_template'").fetchone()[0]
 if not r:raise HTTPException(404,'Ausleihe nicht gefunden')
 return dict(r),school,template

@app.get('/contracts/{loan_id}')
def contract_detail(loan_id:int):
 r,school,template=loan_contract_data(loan_id)
 with conn() as c:st=c.execute('SELECT status FROM contract_docs WHERE loan_id=?',(loan_id,)).fetchone()
 status=st['status'] if st else 'Entwurf'
 options=''.join(f'<option value="{x}" {"selected" if x==status else ""}>{x}</option>' for x in ('Entwurf','Ausgedruckt','Unterschrieben'))
 body=f'''<div class="card"><h3>Leihvertrag LV-{loan_id:05d}</h3><div class="formgrid"><div><b>Schüler</b><p>{esc(r['name'])} · {esc(r['class_name'])}</p></div><div><b>Gerät</b><p>{esc(r['inventory'])} · {esc(r['serial'] or 'ohne Seriennummer')}</p></div><div><b>Ausgabe</b><p>{esc(r['issued'][:10])}</p></div></div><div class="actions"><a class="btn" href="/contracts/{loan_id}/pdf">Leihvertrag als PDF</a><a class="btn secondary" href="/contracts/{loan_id}/protocol.pdf">Übergabe-/Rückgabeprotokoll</a></div><form method="post" action="/contracts/{loan_id}/status"><label class="field">Dokumentstatus<select name="status">{options}</select></label><p><button>Status speichern</button></p></form><p class="sub">Status wird manuell gesetzt; relay. prüft keine Unterschriften.</p></div>'''
 return page('Vertrag LV-'+str(loan_id),body,'/contracts')

@app.post('/contracts/{loan_id}/status')
def contract_status(loan_id:int,status:str=Form(...)):
 if status not in ('Entwurf','Ausgedruckt','Unterschrieben'):raise HTTPException(400)
 loan_contract_data(loan_id)
 with conn() as c:
  c.execute('''INSERT INTO contract_docs(loan_id,status,updated) VALUES(?,?,?)
  ON CONFLICT(loan_id) DO UPDATE SET status=excluded.status,updated=excluded.updated''',(loan_id,status,datetime.now(timezone.utc).isoformat()))
 return go(f'/contracts/{loan_id}')

from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,KeepTogether
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from xml.sax.saxutils import escape as xml_escape
FONT_PATH='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
PDF_FONT='Helvetica'
if os.path.exists(FONT_PATH):
 pdfmetrics.registerFont(TTFont('LeihPilotSans',FONT_PATH));PDF_FONT='LeihPilotSans'

def doc_pdf(loan_id,protocol=False):
 r,school,template=loan_contract_data(loan_id)
 b=io.BytesIO()
 doc=SimpleDocTemplate(b,pagesize=A4,rightMargin=20*mm,leftMargin=20*mm,topMargin=20*mm,bottomMargin=20*mm)
 styles=getSampleStyleSheet()
 styles.add(ParagraphStyle(name='LPTitle',fontName=PDF_FONT,fontSize=17,leading=23,spaceAfter=12))
 styles.add(ParagraphStyle(name='LPBody',fontName=PDF_FONT,fontSize=9.5,leading=15,spaceAfter=8))
 styles.add(ParagraphStyle(name='LPSub',fontName=PDF_FONT,fontSize=10,leading=15,spaceBefore=14,spaceAfter=7))
 styles.add(ParagraphStyle(name='LPFoot',fontName=PDF_FONT,fontSize=8,leading=12,textColor=colors.HexColor('#6a7481')))
 def para(s,style='LPBody'):return Paragraph(xml_escape(str(s)),styles[style])
 def table(items):
  t=Table([[para(k),para(v or '—')] for k,v in items],colWidths=[42*mm,125*mm],hAlign='LEFT')
  t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,-1),.3,colors.HexColor('#e0e5e9'))]))
  return t
 story=[para(school,'LPSub'),para('Übergabe- und Rückgabeprotokoll' if protocol else 'iPad-Leihvertrag – Entwurf','LPTitle'),para('TESTDOKUMENT – Vertragsbedingungen nicht rechtlich geprüft','LPFoot'),Spacer(1,8*mm)]
 story.append(table([('Vorgangsnummer',f'LV-{loan_id:05d}'),('Schülerin / Schüler',r['name']),('Klasse',r['class_name']),('Inventarnummer',r['inventory']),('Seriennummer',r['serial']),('Modell',r['model']),('Ausgabe',r['issued'][:10]),('Rückgabe',r['returned'][:10] if r['returned'] else 'noch offen'),('Zubehör',r['accessories'])]))
 if protocol:
  story.extend([para('Übergabe','LPSub'),para('Gerätezustand bei Ausgabe: __________________________________________'),para('Mitgegebenes Zubehör / Bemerkungen: __________________________________'),Spacer(1,7*mm),para('Rückgabe','LPSub'),para('Datum: ____________________  Zustand: ________________________________'),para('Fehlendes Zubehör / Schäden: _________________________________________')])
 else:
  story.append(para('Vertragsbedingungen (bearbeitbarer Entwurf)','LPSub'))
  for paragraph in template.split('\n\n'):
   if paragraph.strip():story.append(para(paragraph.replace('\n',' ')))
  story.extend([para('Sorgeberechtigte / Kontakt (bei Bedarf handschriftlich ergänzen)','LPSub'),para('Name: ______________________________________________________________'),para('Anschrift: ___________________________________________________________')])
 story.extend([Spacer(1,10*mm),para('Ort, Datum: __________________________________________'),Spacer(1,8*mm),para('_______________________________     _______________________________'),para('Ausgebende / entgegennehmende Person          Sorgeberechtigte / empfangende Person','LPFoot'),Spacer(1,7*mm),para('Weitere Unterschrift (falls erforderlich): ___________________________________')])
 doc.build(story);b.seek(0)
 return StreamingResponse(b,media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="leihpilot-{ "protokoll" if protocol else "vertrag" }-{loan_id}.pdf"'})

@app.get('/contracts/{loan_id}/pdf')
def contract_pdf(loan_id:int):return doc_pdf(loan_id)
@app.get('/contracts/{loan_id}/protocol.pdf')
def protocol_pdf(loan_id:int):return doc_pdf(loan_id,True)


# v0.11 – sequential class issue. Existing scan and manual workflows remain unchanged.
@app.get('/class-issue')
def class_issue(class_name:str=''):
 with conn() as c:
  classes=[r['class_name'] for r in c.execute("SELECT DISTINCT class_name FROM students WHERE trim(class_name)<>'' AND class_name<>'—' ORDER BY class_name COLLATE NOCASE")]
  if class_name not in classes:class_name=''
  students=[dict(r) for r in c.execute('SELECT id,name FROM students WHERE class_name=? ORDER BY name COLLATE NOCASE,id',(class_name,))] if class_name else []
 import json
 options='<option value="">Klasse auswählen …</option>'+''.join(f'<option value="{esc(x)}" {"selected" if x==class_name else ""}>{esc(x)}</option>' for x in classes)
 body='''<div class="card"><h3>Klassenausleihe</h3><p class="sub">Klasse wählen, Gerät scannen, nächste Person. Buchung erfolgt ohne zusätzlichen Bestätigungsschritt.</p><label class="field" style="max-width:340px">Klasse<select id="ci-class">__OPTIONS__</select></label></div>
 <div class="card" id="ci-panel" __HIDDEN__><div class="actions" style="justify-content:space-between"><b id="ci-progress">0 / 0</b><span class="sub" id="ci-next"></span></div><div style="height:7px;background:#e5e9ed;border-radius:5px;margin:14px 0"><div id="ci-bar" style="height:100%;width:0;background:#2e7755;border-radius:5px"></div></div>
 <div style="background:#f3f6f8;padding:22px;border-radius:6px;margin:18px 0"><div class="eyebrow">AKTUELLE PERSON</div><h2 id="ci-name" style="margin:9px 0 0"></h2></div>
 <form id="ci-form" method="post" action="/class-issue/scan"><input type="hidden" name="_csrf" value="__CSRF__"><input type="hidden" id="ci-student" name="student_id"><label class="field">Gerätebarcode<input id="ci-code" name="code" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Gerät scannen oder Inventarnummer eingeben …" required autofocus></label><p><button id="ci-submit">Gerät ausleihen</button> <button type="button" class="secondary" id="ci-skip">Überspringen</button> <button type="button" class="secondary" id="ci-back">Zurück</button></p></form>
 <div id="ci-message" role="status" aria-live="polite" style="min-height:45px;font-weight:600"></div><p class="sub">Ein Erfolgston bestätigt die gespeicherte Ausleihe. Bei Fehlern bleibt die Person ausgewählt. Bei Bedarf kann jederzeit zurückgesprungen werden.</p></div>
 <div class="card" id="ci-list-card" __HIDDEN__><h3>Klassenübersicht</h3><table><thead><tr><th>Schüler/in</th><th>Status dieser Sitzung</th><th></th></tr></thead><tbody id="ci-list"></tbody></table></div>
 <script>
 (()=>{
 const students=__STUDENTS__,cls=document.getElementById('ci-class'),panel=document.getElementById('ci-panel'),listCard=document.getElementById('ci-list-card'),name=document.getElementById('ci-name'),progress=document.getElementById('ci-progress'),next=document.getElementById('ci-next'),bar=document.getElementById('ci-bar'),form=document.getElementById('ci-form'),student=document.getElementById('ci-student'),code=document.getElementById('ci-code'),msg=document.getElementById('ci-message'),submit=document.getElementById('ci-submit'),skip=document.getElementById('ci-skip'),back=document.getElementById('ci-back'),list=document.getElementById('ci-list');
 let index=0,busy=false,audio=null;const status={};
 cls.addEventListener('change',()=>{location.href='/class-issue?class_name='+encodeURIComponent(cls.value)});
 function sound(ok){try{audio=audio||new (window.AudioContext||window.webkitAudioContext)();audio.resume();const o=audio.createOscillator(),g=audio.createGain();o.type='sine';o.frequency.value=ok?880:220;g.gain.setValueAtTime(.07,audio.currentTime);g.gain.exponentialRampToValueAtTime(.001,audio.currentTime+.16);o.connect(g);g.connect(audio.destination);o.start();o.stop(audio.currentTime+.17)}catch(e){}}
 function draw(){if(!students.length)return;const finished=index>=students.length;name.textContent=finished?'Klasse abgeschlossen':students[index].name;student.value=finished?'':students[index].id;progress.textContent=Math.min(index,students.length)+' / '+students.length;bar.style.width=(100*Math.min(index,students.length)/students.length)+'%';next.textContent=finished?'':('Danach: '+(students[index+1]?.name||'Abschluss'));code.disabled=finished;submit.disabled=finished;skip.disabled=finished;back.disabled=index===0;list.replaceChildren();students.forEach((s,i)=>{const tr=document.createElement('tr'),td1=document.createElement('td'),td2=document.createElement('td'),td3=document.createElement('td'),b=document.createElement('button');td1.textContent=s.name;td2.textContent=status[s.id]||'Offen';b.textContent='Auswählen';b.type='button';b.className='secondary';b.addEventListener('click',()=>{if(busy)return;index=i;msg.textContent='';draw()});td3.append(b);tr.append(td1,td2,td3);list.append(tr)});if(!finished)code.focus()}
 function move(delta){if(busy)return;index=Math.max(0,Math.min(students.length,index+delta));msg.textContent='';draw()}
 skip.addEventListener('click',()=>{if(index<students.length)status[students[index].id]='Übersprungen';move(1)});back.addEventListener('click',()=>move(-1));
 form.addEventListener('submit',async e=>{e.preventDefault();if(busy||index>=students.length||!code.value.trim())return;busy=true;submit.disabled=true;const current=students[index],data=new FormData(form);try{const response=await fetch('/class-issue/scan',{method:'POST',body:new URLSearchParams(data),headers:{'Content-Type':'application/x-www-form-urlencoded'}});const result=await response.json();if(!response.ok||!result.ok){msg.style.color='#a62d2d';msg.textContent=result.message||'Ausleihe fehlgeschlagen';sound(false)}else{status[current.id]='Ausgeliehen: '+result.inventory;msg.style.color='#237044';msg.textContent=current.name+' · '+result.inventory+' erfolgreich ausgeliehen';sound(true);index++;code.value='';draw()}}catch(err){msg.style.color='#a62d2d';msg.textContent='Verbindungsfehler. Bitte Ausleihstatus prüfen, bevor erneut gescannt wird.';sound(false)}finally{busy=false;submit.disabled=index>=students.length;code.focus()}});
 document.addEventListener('keydown',e=>{if(e.key==='Escape'){code.value='';code.focus()}});draw();
 })();
 </script>'''
 body=body.replace('__OPTIONS__',options).replace('__STUDENTS__',json.dumps(students,ensure_ascii=False).replace('<','\\u003c')).replace('__CSRF__',esc(CSRF_CONTEXT.get())).replace('__HIDDEN__','' if students else 'hidden')
 return page('Klassenausleihe',body,'/class-issue')

@app.post('/class-issue/scan')
def class_issue_scan(student_id:int=Form(...),code:str=Form(...)):
 kind,device_id=lookup_scan(code)
 if kind!='device':return JSONResponse({'ok':False,'message':'Kein gültiger Gerätebarcode.'},status_code=422)
 try:
  with conn() as c:
   student=c.execute('SELECT id FROM students WHERE id=?',(student_id,)).fetchone()
   device=c.execute('SELECT inventory,operational_state FROM devices WHERE id=?',(device_id,)).fetchone()
   if not student:return JSONResponse({'ok':False,'message':'Schüler nicht gefunden.'},status_code=404)
   if not device:return JSONResponse({'ok':False,'message':'Gerät nicht gefunden.'},status_code=404)
   if device['operational_state']!='Aktiv':return JSONResponse({'ok':False,'message':'Gerät ist gesperrt: '+device['operational_state']},status_code=409)
   if c.execute('SELECT 1 FROM loans WHERE device_id=? AND returned IS NULL',(device_id,)).fetchone():return JSONResponse({'ok':False,'message':'Gerät ist bereits ausgeliehen.'},status_code=409)
   c.execute('INSERT INTO loans(device_id,student_id,issued,accessories) VALUES(?,?,?,?)',(device_id,student_id,datetime.now(timezone.utc).isoformat(),''))
   inventory=device['inventory']
 except sqlite3.IntegrityError:
  return JSONResponse({'ok':False,'message':'Gerät wurde bereits ausgeliehen. Bitte Status prüfen.'},status_code=409)
 return JSONResponse({'ok':True,'inventory':inventory})
