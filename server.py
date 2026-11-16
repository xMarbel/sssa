"""VILO — local-first live chat server. Not audited for public Internet deployment."""
import os, time, json, secrets, hashlib, hmac, re, sqlite3, asyncio, threading, mimetypes, uuid
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('VILO_DATA_DIR',ROOT/'data')).resolve()
DATA.mkdir(parents=True,exist_ok=True)
UPLOADS=DATA/'uploads'; UPLOADS.mkdir(exist_ok=True)
DB_PATH=DATA/'vilo.db'
LOCK=threading.RLock()
app=FastAPI(title='VILO',docs_url=None,redoc_url=None,openapi_url=None)
# An instance runs with a single uvicorn worker.
connected:dict[int,set[WebSocket]]={}
rate:dict[str,list[float]]={}

def db():
    c=sqlite3.connect(DB_PATH,timeout=20,check_same_thread=False)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=20000')
    return c

@contextmanager
def transaction():
    with LOCK:
        c=db()
        try:
            c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except Exception:
            c.rollback(); raise
        finally:
            c.close()

def one(query,*args):
    with db() as c: return c.execute(query,args).fetchone()
def allrows(query,*args):
    with db() as c: return [dict(r) for r in c.execute(query,args).fetchall()]

def init_db():
    with transaction() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL UNIQUE COLLATE NOCASE, pw TEXT NOT NULL, display_name TEXT NOT NULL, about TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#7c5cf0', created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS rooms(id INTEGER PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('dm','group','server')),name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',owner_id INTEGER REFERENCES users(id),created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS members(room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL DEFAULT 'member',joined INTEGER NOT NULL,PRIMARY KEY(room_id,user_id));
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,user_id INTEGER REFERENCES users(id),bot_name TEXT,body TEXT NOT NULL DEFAULT '',kind TEXT NOT NULL DEFAULT 'text',ref_id INTEGER,attachment_id TEXT,attachment_name TEXT,created INTEGER NOT NULL,edited INTEGER,deleted INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id,id);
        CREATE TABLE IF NOT EXISTS reactions(message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,emoji TEXT NOT NULL,PRIMARY KEY(message_id,user_id,emoji));
        CREATE TABLE IF NOT EXISTS friendships(id INTEGER PRIMARY KEY, sender INTEGER NOT NULL REFERENCES users(id),receiver INTEGER NOT NULL REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending',created INTEGER NOT NULL, UNIQUE(sender,receiver));
        CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,by_user INTEGER NOT NULL REFERENCES users(id),max_uses INTEGER NOT NULL DEFAULT 30,used INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS polls(id INTEGER PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,question TEXT NOT NULL,creator INTEGER NOT NULL REFERENCES users(id),multiple INTEGER NOT NULL DEFAULT 0,anonymous INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS poll_options(id INTEGER PRIMARY KEY,poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,label TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS poll_votes(poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,option_id INTEGER NOT NULL REFERENCES poll_options(id),user_id INTEGER NOT NULL REFERENCES users(id),PRIMARY KEY(poll_id,option_id,user_id));
        CREATE TABLE IF NOT EXISTS bots(id INTEGER PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,owner_id INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,trigger TEXT NOT NULL,response TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,by_user INTEGER NOT NULL REFERENCES users(id),filename TEXT NOT NULL,stored TEXT NOT NULL,size INTEGER NOT NULL,created INTEGER NOT NULL);
        ''')
init_db()

class Credentials(BaseModel):
    username:str=Field(min_length=3,max_length=24)
    password:str=Field(min_length=8,max_length=128)
    email:Optional[str]=None
class LoginIn(BaseModel):
    username:str=Field(min_length=3,max_length=254)
    password:str=Field(min_length=1,max_length=128)
class RoomIn(BaseModel):
    name:str=Field(min_length=2,max_length=70)
    kind:str='group'
class DMIn(BaseModel): username:str
class MsgIn(BaseModel): body:str=Field(min_length=1,max_length=4000)
class PollIn(BaseModel):
    question:str=Field(min_length=3,max_length=200)
    options:list[str]
    multiple:bool=False
    anonymous:bool=False
class VoteIn(BaseModel): option_ids:list[int]
class BotIn(BaseModel):
    name:str=Field(min_length=2,max_length=32)
    trigger:str=Field(min_length=2,max_length=30)
    response:str=Field(min_length=1,max_length=500)
class ProfileIn(BaseModel):
    display_name:str=Field(min_length=1,max_length=32)
    about:str=Field(max_length=220)
    color:str='#7c5cf0'
class ReactionIn(BaseModel): emoji:str
class InviteIn(BaseModel): code:str
class RoleIn(BaseModel): role:str

USERNAME_RE=re.compile(r'^[a-zA-Z0-9_]{3,24}$')
EMAIL_RE=re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
COLOR_RE=re.compile(r'^#[0-9a-fA-F]{6}$')

def tick(): return int(time.time())
def pw_hash(p):
    salt=secrets.token_bytes(16)
    return 'pbkdf2$'+salt.hex()+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,310_000).hex()
def pw_check(p,encoded):
    try:
        _,salt,key=encoded.split('$')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(salt),310_000),bytes.fromhex(key))
    except (ValueError,TypeError): return False

def make_session(resp,uid,req):
    token=secrets.token_urlsafe(40)
    with transaction() as c:
        c.execute('INSERT INTO sessions VALUES (?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),uid,tick()+30*86400))
    secure=req.url.scheme=='https' or os.getenv('VILO_SECURE_COOKIES')=='1'
    resp.set_cookie('vilo_session',token,max_age=30*86400,httponly=True,secure=secure,samesite='lax',path='/')

def session_user(token):
    if not token: return None
    return one('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?',hashlib.sha256(token.encode()).hexdigest(),tick())
def current(req:Request):
    u=session_user(req.cookies.get('vilo_session'))
    if not u: raise HTTPException(401,'Zaloguj się, aby kontynuować.')
    return u

def user_public(u):
    return {k:u[k] for k in ('id','username','display_name','about','color','created')}

def room_member(room_id, uid):
    m=one('SELECT m.*,r.kind,r.name,r.owner_id FROM members m JOIN rooms r ON r.id=m.room_id WHERE m.room_id=? AND m.user_id=?',room_id,uid)
    if not m: raise HTTPException(403,'Nie masz dostępu do tej rozmowy.')
    return m

def room_admin(room_id,uid):
    m=room_member(room_id,uid)
    if m['role'] not in ('owner','admin'): raise HTTPException(403,'Tylko administrator grupy może to zrobić.')
    return m

def limit(key, n=15, secs=60):
    now=time.monotonic(); prev=[t for t in rate.get(key,[]) if t>now-secs]
    if len(prev)>=n: raise HTTPException(429,'Zbyt wiele prób. Spróbuj później.')
    prev.append(now);rate[key]=prev
    if len(rate)>2000:
        for k in list(rate)[:500]: rate.pop(k,None)

@app.middleware('http')
async def basic_security(req:Request,call_next):
    # Stops cross-site form/API requests in browsers. Local HTTP is for trusted networks only.
    if req.url.path.startswith('/api/') and req.method not in ('GET','HEAD','OPTIONS'):
        origin=req.headers.get('origin','')
        if origin:
            from urllib.parse import urlparse
            o=urlparse(origin)
            if o.netloc != req.headers.get('host','') or o.scheme != req.url.scheme:
                return JSONResponse({'detail':'Nieprawidłowe pochodzenie żądania.'},status_code=403)
    res=await call_next(req)
    res.headers['X-Content-Type-Options']='nosniff'
    res.headers['X-Frame-Options']='DENY'
    res.headers['Referrer-Policy']='same-origin'
    res.headers['Cache-Control']='no-store' if req.url.path.startswith('/api/') else 'no-cache'
    res.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; frame-ancestors 'none'"
    return res

@app.post('/api/register')
def register(inp:Credentials,req:Request,response:Response):
    limit('reg:'+str(req.client.host),5,3600)
    if not USERNAME_RE.fullmatch(inp.username): raise HTTPException(400,'Nick: 3–24 znaki, litery, cyfry lub _.')
    if not inp.email or len(inp.email)>254 or not EMAIL_RE.fullmatch(inp.email): raise HTTPException(400,'Podaj prawidłowy adres e-mail.')
    if inp.password.lower() in ('password123','12345678','qwerty123'): raise HTTPException(400,'Wybierz silniejsze hasło.')
    with transaction() as c:
        try:
            cur=c.execute('INSERT INTO users(username,email,pw,display_name,created) VALUES (?,?,?,?,?)',(inp.username,inp.email,pw_hash(inp.password),inp.username,tick()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Nick lub e-mail jest już zajęty.')
    make_session(response,cur.lastrowid,req)
    return {'ok':True}

@app.post('/api/login')
def login(inp:LoginIn,req:Request,response:Response):
    limit('login:'+str(req.client.host),12,900)
    u=one('SELECT * FROM users WHERE username=? OR email=?',inp.username,inp.username)
    if not u or not pw_check(inp.password,u['pw']): raise HTTPException(401,'Nieprawidłowy login lub hasło.')
    make_session(response,u['id'],req)
    return {'ok':True}

@app.post('/api/logout')
def logout(req:Request,response:Response,u=Depends(current)):
    token=req.cookies.get('vilo_session')
    with transaction() as c: c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie('vilo_session',path='/');return {'ok':True}

@app.get('/api/me')
def me(u=Depends(current)): return user_public(u)
@app.patch('/api/me')
def patch_me(data:ProfileIn,u=Depends(current)):
    if not COLOR_RE.fullmatch(data.color):raise HTTPException(400,'Nieprawidłowy kolor.')
    with transaction() as c:c.execute('UPDATE users SET display_name=?,about=?,color=? WHERE id=?',(data.display_name.strip(),data.about.strip(),data.color,u['id']))
    return {'ok':True}

@app.get('/api/users')
def users(q:str='',u=Depends(current)):
    if len(q.strip())<2:return []
    return [user_public(x) for x in allrows('SELECT id,username,display_name,about,color,created FROM users WHERE username LIKE ? AND id<>? LIMIT 15',('%'+q.strip()+'%',u['id']))]

@app.get('/api/friends')
def friends(u=Depends(current)):
    rows=allrows('''SELECT f.id friendship_id,f.sender,f.receiver,f.status, x.id,x.username,x.display_name,x.about,x.color,x.created
     FROM friendships f JOIN users x ON x.id=(CASE WHEN f.sender=? THEN f.receiver ELSE f.sender END)
     WHERE f.sender=? OR f.receiver=? ORDER BY f.created DESC''',u['id'],u['id'],u['id'])
    for r in rows:r['direction']='incoming' if r['receiver']==u['id'] else 'outgoing'
    return rows

@app.post('/api/friends/request/{other_id}')
async def friend_request(other_id:int,u=Depends(current)):
    if other_id==u['id']:raise HTTPException(400,'Nie możesz zaprosić siebie.')
    if not one('SELECT id FROM users WHERE id=?',other_id):raise HTTPException(404,'Nie znaleziono użytkownika.')
    with transaction() as c:
        existing=c.execute('SELECT * FROM friendships WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)',(u['id'],other_id,other_id,u['id'])).fetchone()
        if existing:
            if existing['status']=='accepted':raise HTTPException(409,'Jesteście już znajomymi.')
            if existing['receiver']==u['id']:
                c.execute("UPDATE friendships SET status='accepted' WHERE id=?",(existing['id'],))
            else:raise HTTPException(409,'Zaproszenie już wysłane.')
        else:c.execute('INSERT INTO friendships(sender,receiver,created) VALUES (?,?,?)',(u['id'],other_id,tick()))
    await push_users([u['id'],other_id]);return {'ok':True}

@app.post('/api/friends/{friendship_id}/accept')
async def friend_accept(friendship_id:int,u=Depends(current)):
    f=one('SELECT * FROM friendships WHERE id=?',friendship_id)
    if not f or f['receiver']!=u['id']:raise HTTPException(403,'Brak dostępu.')
    with transaction() as c:c.execute("UPDATE friendships SET status='accepted' WHERE id=?",(friendship_id,))
    await push_users([f['sender'],f['receiver']]);return {'ok':True}

@app.get('/api/rooms')
def rooms(u=Depends(current)):
    rows=allrows('''SELECT r.*,m.role,(SELECT COUNT(*) FROM members WHERE room_id=r.id) member_count,
       (SELECT body FROM messages WHERE room_id=r.id ORDER BY id DESC LIMIT 1) last_message,
       (SELECT created FROM messages WHERE room_id=r.id ORDER BY id DESC LIMIT 1) last_at
       FROM members m JOIN rooms r ON m.room_id=r.id WHERE m.user_id=? ORDER BY COALESCE(last_at,r.created) DESC''',u['id'])
    for row in rows:
        if row['kind']=='dm':
            other=one('SELECT u.id,u.username,u.display_name,u.color FROM members m JOIN users u ON u.id=m.user_id WHERE m.room_id=? AND u.id<>?',row['id'],u['id'])
            if other: row['name']=other['display_name'];row['other']=dict(other)
    return rows

async def push_users(ids):
    for uid in set(ids):
        for ws in list(connected.get(uid,set())):
            try:await ws.send_json({'type':'refresh','at':tick()})
            except Exception:connected.get(uid,set()).discard(ws)
async def push_room(room_id):
    ids=[r['user_id'] for r in allrows('SELECT user_id FROM members WHERE room_id=?',room_id)]
    await push_users(ids)

@app.post('/api/rooms')
async def room_create(v:RoomIn,u=Depends(current)):
    if v.kind not in ('group','server'):raise HTTPException(400,'Nieprawidłowy rodzaj grupy.')
    with transaction() as c:
        cur=c.execute('INSERT INTO rooms(kind,name,owner_id,created) VALUES (?,?,?,?)',(v.kind,v.name.strip(),u['id'],tick()))
        room_id=cur.lastrowid
        c.execute('INSERT INTO members VALUES (?,?,?,?)',(room_id,u['id'],'owner',tick()))
    await push_users([u['id']]);return {'id':room_id}

@app.post('/api/dm/{other_id}')
async def dm_create(other_id:int,u=Depends(current)):
    if other_id==u['id']:raise HTTPException(400,'Nie możesz pisać sam do siebie.')
    f=one('SELECT * FROM friendships WHERE status=? AND ((sender=? AND receiver=?) OR (sender=? AND receiver=?))','accepted',u['id'],other_id,other_id,u['id'])
    if not f:raise HTTPException(403,'Najpierw musicie zaakceptować zaproszenie do znajomych.')
    match=one('''SELECT r.id FROM rooms r JOIN members a ON a.room_id=r.id AND a.user_id=? JOIN members b ON b.room_id=r.id AND b.user_id=? WHERE r.kind='dm' LIMIT 1''',u['id'],other_id)
    if match:return {'id':match['id']}
    with transaction() as c:
        cur=c.execute("INSERT INTO rooms(kind,name,owner_id,created) VALUES ('dm','Prywatna rozmowa',?,?)",(u['id'],tick()))
        rid=cur.lastrowid
        for uid in (u['id'],other_id):c.execute('INSERT INTO members VALUES (?,?,?,?)',(rid,uid,'member',tick()))
    await push_users([u['id'],other_id]);return {'id':rid}

@app.get('/api/rooms/{rid}/members')
def members(rid:int,u=Depends(current)):
    room_member(rid,u['id'])
    return allrows('SELECT u.id,u.username,u.display_name,u.color,u.about,m.role FROM members m JOIN users u ON u.id=m.user_id WHERE m.room_id=? ORDER BY CASE m.role WHEN "owner" THEN 0 WHEN "admin" THEN 1 ELSE 2 END,u.username',rid)

@app.post('/api/rooms/{rid}/members/{other_id}/role')
async def set_role(rid:int,other_id:int,data:RoleIn,u=Depends(current)):
    m=room_member(rid,u['id'])
    if m['role']!='owner' or data.role not in ('admin','member'):raise HTTPException(403,'Tylko właściciel może zmieniać role.')
    if other_id==u['id']:raise HTTPException(400,'Nie możesz zmienić własnej roli.')
    with transaction() as c:
        if not c.execute('SELECT 1 FROM members WHERE room_id=? AND user_id=?',(rid,other_id)).fetchone():raise HTTPException(404,'Nie ma takiej osoby w grupie.')
        c.execute('UPDATE members SET role=? WHERE room_id=? AND user_id=?',(data.role,rid,other_id))
    await push_room(rid);return {'ok':True}

@app.post('/api/rooms/{rid}/invites')
def invite_create(rid:int,u=Depends(current)):
    m=room_admin(rid,u['id'])
    if m['kind']=='dm':raise HTTPException(400,'Nie możesz zapraszać do prywatnego czatu.')
    code=secrets.token_urlsafe(10)
    with transaction() as c:c.execute('INSERT INTO invites VALUES (?,?,?,?,?,?)',(code,rid,u['id'],30,0,tick()+7*86400))
    return {'code':code,'expires':tick()+7*86400,'limit':30}

@app.post('/api/invites/join')
async def invite_join(data:InviteIn,u=Depends(current)):
    code=data.code.strip().split('invite=')[-1]
    with transaction() as c:
        inv=c.execute('SELECT * FROM invites WHERE code=?',(code,)).fetchone()
        if not inv or inv['expires']<tick() or inv['used']>=inv['max_uses']:raise HTTPException(404,'Zaproszenie wygasło albo jest nieprawidłowe.')
        existing=c.execute('SELECT 1 FROM members WHERE room_id=? AND user_id=?',(inv['room_id'],u['id'])).fetchone()
        if not existing:
            c.execute('INSERT INTO members VALUES (?,?,?,?)',(inv['room_id'],u['id'],'member',tick()))
            c.execute('UPDATE invites SET used=used+1 WHERE code=?',(code,))
    await push_room(inv['room_id']);return {'id':inv['room_id']}

@app.post('/api/rooms/{rid}/leave')
async def leave_room(rid:int,u=Depends(current)):
    m=room_member(rid,u['id'])
    if m['role']=='owner':raise HTTPException(400,'Właściciel musi najpierw przekazać grupę. Ta opcja będzie dostępna w kolejnej wersji.')
    with transaction() as c:c.execute('DELETE FROM members WHERE room_id=? AND user_id=?',(rid,u['id']))
    await push_room(rid);return {'ok':True}

def poll_data(pid,uid):
    p=one('SELECT * FROM polls WHERE id=?',pid)
    if not p:return None
    room_member(p['room_id'],uid)
    choices=allrows('SELECT o.id,o.label,COUNT(v.user_id) count FROM poll_options o LEFT JOIN poll_votes v ON v.option_id=o.id WHERE o.poll_id=? GROUP BY o.id ORDER BY o.id',pid)
    selected=[x['option_id'] for x in allrows('SELECT option_id FROM poll_votes WHERE poll_id=? AND user_id=?',pid,uid)]
    return {'id':pid,'question':p['question'],'multiple':bool(p['multiple']),'anonymous':bool(p['anonymous']),'choices':choices,'selected':selected,'total':sum(x['count'] for x in choices)}

def serialize_message(m,uid):
    d=dict(m)
    if m['kind']=='poll':d['poll']=poll_data(m['ref_id'],uid)
    d['reactions']=allrows('SELECT emoji,COUNT(*) count,MAX(CASE WHEN user_id=? THEN 1 ELSE 0 END) mine FROM reactions WHERE message_id=? GROUP BY emoji',uid,m['id'])
    return d

@app.get('/api/rooms/{rid}/messages')
def get_messages(rid:int,before:int=0,u=Depends(current)):
    room_member(rid,u['id'])
    if before:
        rows=allrows('''SELECT m.*,u.username,u.display_name,u.color FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=? AND m.id<? ORDER BY m.id DESC LIMIT 60''',rid,before)
    else:
        rows=allrows('''SELECT m.*,u.username,u.display_name,u.color FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=? ORDER BY m.id DESC LIMIT 60''',rid)
    return [serialize_message(m,u['id']) for m in reversed(rows)]

@app.post('/api/rooms/{rid}/messages')
async def post_message(rid:int,data:MsgIn,req:Request,u=Depends(current)):
    room_member(rid,u['id']);limit('msg:'+str(u['id']),35,30)
    body=data.body.strip()
    if not body:raise HTTPException(400,'Wiadomość jest pusta.')
    with transaction() as c:
        cur=c.execute('INSERT INTO messages(room_id,user_id,body,created) VALUES (?,?,?,?)',(rid,u['id'],body,tick()))
        bots=c.execute('SELECT * FROM bots WHERE room_id=? AND enabled=1',(rid,)).fetchall()
        # Safe predefined responses only; never execute arbitrary bot code.
        for bot in bots:
            if body.casefold().strip()==bot['trigger'].casefold().strip():
                c.execute("INSERT INTO messages(room_id,bot_name,body,kind,created) VALUES (?,?,?,'bot',?)",(rid,bot['name'],bot['response'],tick()))
    await push_room(rid);return {'id':cur.lastrowid}

@app.patch('/api/messages/{mid}')
async def edit_message(mid:int,data:MsgIn,u=Depends(current)):
    m=one('SELECT * FROM messages WHERE id=?',mid)
    if not m or m['user_id']!=u['id'] or m['kind']!='text' or m['deleted']:raise HTTPException(403,'Nie możesz edytować tej wiadomości.')
    with transaction() as c:c.execute('UPDATE messages SET body=?,edited=? WHERE id=?',(data.body.strip(),tick(),mid))
    await push_room(m['room_id']);return {'ok':True}

@app.delete('/api/messages/{mid}')
async def delete_message(mid:int,u=Depends(current)):
    m=one('SELECT * FROM messages WHERE id=?',mid)
    if not m:raise HTTPException(404,'Brak wiadomości.')
    membership=room_member(m['room_id'],u['id'])
    if m['user_id']!=u['id'] and membership['role'] not in ('owner','admin'):raise HTTPException(403,'Brak uprawnień.')
    with transaction() as c:c.execute("UPDATE messages SET body='',deleted=1 WHERE id=?",(mid,))
    await push_room(m['room_id']);return {'ok':True}

@app.post('/api/messages/{mid}/react')
async def react(mid:int,data:ReactionIn,u=Depends(current)):
    if data.emoji not in ['👍','❤️','😂','🎉','🔥','👀','💜']:raise HTTPException(400,'Nieznana reakcja.')
    m=one('SELECT * FROM messages WHERE id=?',mid)
    if not m:raise HTTPException(404,'Brak wiadomości.')
    room_member(m['room_id'],u['id'])
    with transaction() as c:
        if c.execute('SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?',(mid,u['id'],data.emoji)).fetchone():
            c.execute('DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?',(mid,u['id'],data.emoji))
        else:c.execute('INSERT INTO reactions VALUES (?,?,?)',(mid,u['id'],data.emoji))
    await push_room(m['room_id']);return {'ok':True}

@app.post('/api/rooms/{rid}/polls')
async def create_poll(rid:int,data:PollIn,u=Depends(current)):
    room_member(rid,u['id'])
    options=[v.strip() for v in data.options if v.strip()]
    if not 2<=len(options)<=8 or any(len(x)>80 for x in options):raise HTTPException(400,'Ankieta musi mieć od 2 do 8 odpowiedzi (maks. 80 znaków).')
    with transaction() as c:
        p=c.execute('INSERT INTO polls(room_id,question,creator,multiple,anonymous,created) VALUES (?,?,?,?,?,?)',(rid,data.question.strip(),u['id'],int(data.multiple),int(data.anonymous),tick())).lastrowid
        for opt in options:c.execute('INSERT INTO poll_options(poll_id,label) VALUES (?,?)',(p,opt))
        c.execute("INSERT INTO messages(room_id,user_id,body,kind,ref_id,created) VALUES (?,?,?,'poll',?,?)",(rid,u['id'],data.question.strip(),p,tick()))
    await push_room(rid);return {'id':p}

@app.post('/api/polls/{pid}/vote')
async def vote(pid:int,data:VoteIn,u=Depends(current)):
    p=one('SELECT * FROM polls WHERE id=?',pid)
    if not p:raise HTTPException(404,'Brak ankiety.')
    room_member(p['room_id'],u['id'])
    requested=list(dict.fromkeys(data.option_ids))
    allowed={x['id'] for x in allrows('SELECT id FROM poll_options WHERE poll_id=?',pid)}
    if not requested or any(x not in allowed for x in requested) or (not p['multiple'] and len(requested)!=1):raise HTTPException(400,'Nieprawidłowy głos.')
    with transaction() as c:
        c.execute('DELETE FROM poll_votes WHERE poll_id=? AND user_id=?',(pid,u['id']))
        for oid in requested:c.execute('INSERT INTO poll_votes VALUES (?,?,?)',(pid,oid,u['id']))
    await push_room(p['room_id']);return {'ok':True}

@app.get('/api/rooms/{rid}/bots')
def bots(rid:int,u=Depends(current)):
    room_member(rid,u['id'])
    return allrows('SELECT id,name,trigger,response,enabled,owner_id FROM bots WHERE room_id=? ORDER BY id DESC',rid)

@app.post('/api/rooms/{rid}/bots')
async def bot_create(rid:int,data:BotIn,u=Depends(current)):
    room_admin(rid,u['id'])
    if not data.trigger.startswith('/'):raise HTTPException(400,'Komenda bota musi zaczynać się od /, np. /pomoc.')
    with transaction() as c:
        count=c.execute('SELECT COUNT(*) FROM bots WHERE room_id=?',(rid,)).fetchone()[0]
        if count>=12:raise HTTPException(400,'Limit 12 prostych botów na grupę w tej wersji.')
        c.execute('INSERT INTO bots(room_id,owner_id,name,trigger,response,created) VALUES (?,?,?,?,?,?)',(rid,u['id'],data.name.strip(),data.trigger.strip(),data.response.strip(),tick()))
    await push_room(rid);return {'ok':True}

@app.delete('/api/rooms/{rid}/bots/{bid}')
async def bot_remove(rid:int,bid:int,u=Depends(current)):
    room_admin(rid,u['id'])
    with transaction() as c:c.execute('DELETE FROM bots WHERE id=? AND room_id=?',(bid,rid))
    await push_room(rid);return {'ok':True}

ALLOWED={'.png','.jpg','.jpeg','.webp','.gif','.pdf','.txt','.zip','.schem','.json','.md','.csv','.docx','.xlsx','.pptx','.mp4'}
MAX_UPLOAD=10*1024*1024
@app.post('/api/rooms/{rid}/upload')
async def upload(rid:int,req:Request,file:UploadFile=File(...),u=Depends(current)):
    room_member(rid,u['id']);limit('up:'+str(u['id']),12,60)
    name=Path((file.filename or 'plik').replace('\\','/')).name[:100]
    ext=Path(name).suffix.lower()
    if ext not in ALLOWED:raise HTTPException(400,'Ten rodzaj pliku jest niedozwolony w wersji testowej.')
    contents=await file.read(MAX_UPLOAD+1)
    if len(contents)>MAX_UPLOAD:raise HTTPException(413,'Maksymalny rozmiar pliku to 10 MB.')
    ident=uuid.uuid4().hex;stored=ident+ext
    (UPLOADS/stored).write_bytes(contents)
    try:
        with transaction() as c:
            c.execute('INSERT INTO uploads VALUES (?,?,?,?,?,?,?)',(ident,rid,u['id'],name,stored,len(contents),tick()))
            c.execute("INSERT INTO messages(room_id,user_id,body,kind,attachment_id,attachment_name,created) VALUES (?,?,?,'file',?,?,?)",(rid,u['id'],name,ident,name,tick()))
    except Exception:
        (UPLOADS/stored).unlink(missing_ok=True);raise
    await push_room(rid)
    return {'ok':True}

@app.get('/api/uploads/{ident}')
def download(ident:str,u=Depends(current)):
    record=one('SELECT * FROM uploads WHERE id=?',ident)
    if not record:raise HTTPException(404,'Nie znaleziono pliku.')
    room_member(record['room_id'],u['id'])
    path=UPLOADS/record['stored']
    if not path.is_file():raise HTTPException(404,'Plik nie jest dostępny.')
    return FileResponse(path,filename=record['filename'],media_type='application/octet-stream',content_disposition_type='attachment')

@app.websocket('/ws')
async def ws(websocket:WebSocket):
    origin=websocket.headers.get('origin','')
    if origin:
        from urllib.parse import urlparse
        if urlparse(origin).netloc!=websocket.headers.get('host',''):
            await websocket.close(code=1008);return
    u=session_user(websocket.cookies.get('vilo_session'))
    if not u:await websocket.close(code=1008);return
    await websocket.accept()
    connected.setdefault(u['id'],set()).add(websocket)
    await push_users([u['id']])
    try:
        while True:
            msg=await websocket.receive_text()
            if msg=='ping':await websocket.send_json({'type':'pong'})
    except (WebSocketDisconnect,RuntimeError): pass
    finally:
        connected.get(u['id'],set()).discard(websocket)
        await push_users([u['id']])

@app.get('/api/online')
def online(u=Depends(current)):
    return {'ids':[uid for uid,ws in connected.items() if ws]}

@app.get('/')
def index():return FileResponse(ROOT/'static'/'index.html')
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
