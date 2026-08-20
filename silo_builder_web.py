# **********************************************
# Copyright 2026 by Silo Client
# https://github.com/pabqp/silo-client
# **********************************************

from __future__ import annotations

import io
import json
import re
import secrets
import string
import threading
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BUILDER_VERSION = "2.0"
REQUIRED_TEMPLATE_VERSION = "2.0.2-configurable-dual-aead"
HOST = "127.0.0.1"
MAX_REQUEST = 2_000_000
TOKEN = secrets.token_urlsafe(32)


def find_template() -> str:
    builder_dir = Path(__file__).resolve().parent
    candidates = [
        builder_dir / "silo_client_template.py",
        builder_dir / "_silo_client_template.py",
        Path.cwd() / "silo_client_template.py",
        Path.cwd() / "_silo_client_template.py",
    ]
    for path in candidates:
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if f'TEMPLATE_VERSION = "{REQUIRED_TEMPLATE_VERSION}"' not in text:
                raise ValueError(f"Template version mismatch. Required: {REQUIRED_TEMPLATE_VERSION}")
            return text
    raise FileNotFoundError(
        f"Missing silo_client_template.py. Put it beside the Builder in: {builder_dir}"
    )


def boolean(data: dict, name: str, default: bool = True) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool): raise ValueError(f"{name} must be true or false")
    return value


def validate_and_build(data: dict) -> bytes:
    if not isinstance(data, dict): raise ValueError("Invalid configuration")
    server, channel = str(data.get("server_id", "")).strip(), str(data.get("channel_id", "")).strip()
    primary, secondary = str(data.get("shared_key", "")), str(data.get("secondary_key", ""))
    users = data.get("users", [])
    if not server.isdigit() or int(server) <= 0: raise ValueError("SERVER_ID must be a positive integer")
    if not channel.isdigit() or int(channel) <= 0: raise ValueError("CHANNEL_ID must be a positive integer")
    if len(primary) < 16: raise ValueError("Primary key must contain at least 16 characters")
    dual = boolean(data, "dual_layer_encryption", True)
    if dual and len(secondary) < 16: raise ValueError("Secondary key must contain at least 16 characters")
    if dual and secrets.compare_digest(primary, secondary): raise ValueError("Primary and secondary keys must differ")
    if not isinstance(users, list) or not 1 <= len(users) <= 100: raise ValueError("Configure between 1 and 100 users")
    try:
        start_port = int(data.get("start_port", 8081)); auto_lock = int(data.get("auto_lock_seconds", 300)); rotation = int(data.get("key_rotation_interval", 50))
    except (TypeError, ValueError): raise ValueError("Ports and security intervals must be integers") from None
    if start_port < 1024 or start_port + len(users) - 1 > 65535: raise ValueError("Generated ports must remain between 1024 and 65535")
    if not 30 <= auto_lock <= 3600: raise ValueError("Auto-lock must be between 30 and 3600 seconds")
    if not 1 <= rotation <= 10000: raise ValueError("Key rotation must be between 1 and 10000 messages")
    ids, names = set(), set()
    room_salt = secrets.token_urlsafe(24)
    template = find_template()
    output = io.BytesIO()
    feature_names = ("show_security_panel", "show_statistics", "enable_topics", "enable_search", "enable_presence",
        "enable_attachments", "enable_voice_notes", "enable_polls", "enable_view_once", "enable_disappearing",
        "enable_wallpapers", "enable_mobile_access", "enable_panic", "read_receipts")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for index, user in enumerate(users, 1):
            if not isinstance(user, dict): raise ValueError(f"User {index} is invalid")
            token, uid, name = str(user.get("token", "")).strip(), str(user.get("user_id", "")).strip(), str(user.get("username", "")).strip()
            if len(token) < 30 or token.count(".") < 2: raise ValueError(f"User {index}: invalid Discord bot token")
            if not uid.isdigit() or int(uid) <= 0 or uid in ids: raise ValueError(f"User {index}: invalid or duplicated ID")
            if not name or len(name) > 40 or any(c in name for c in "\r\n\t") or name.casefold() in names: raise ValueError(f"User {index}: invalid or duplicated name")
            ids.add(uid); names.add(name.casefold())
            config = {"bot_token": token, "server_id": int(server), "channel_id": int(channel), "shared_key": primary,
                "secondary_key": secondary, "kdf_salt": room_salt, "web_access_token": secrets.token_urlsafe(32),
                "user_id": int(uid), "username": name, "port": start_port + index - 1,
                "memory_only": boolean(data, "memory_only", False), "dual_layer_encryption": dual,
                "encrypted_local_history": boolean(data, "encrypted_local_history", True),
                "auto_lock_seconds": auto_lock, "key_rotation_interval": rotation}
            config.update({name: boolean(data, name, True) for name in feature_names})
            code = template.replace("__CONFIG_JSON__", repr(config), 1)
            compile(code, f"user_{index}.py", "exec")
            archive.writestr(f"Silo_Clients/user_{index}.py", code)
        archive.writestr("Silo_Clients/README.txt",
            "Silo Client bundle generated locally. Keep BOTH encryption keys private and regenerate every client together.\n")
    return output.getvalue()


def save_clients_beside_builder(archive_bytes: bytes) -> list[str]:
    """Write generated clients beside this Builder and return their filenames."""
    destination = Path(__file__).resolve().parent
    saved: list[str] = []
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        client_entries = sorted(name for name in archive.namelist() if name.endswith(".py"))
        if not client_entries:
            raise ValueError("No clients were generated")
        for index, entry in enumerate(client_entries, 1):
            filename = f"silo_client_{index}.py"
            target = destination / filename
            temporary = destination / f".{filename}.tmp"
            temporary.write_bytes(archive.read(entry))
            temporary.replace(target)
            saved.append(filename)
    return saved


HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Silo Builder __VERSION__</title><style>
:root{--bg:#050609;--panel:#0c0e14;--card:#11141c;--line:#242836;--text:#f2f4fa;--muted:#8c93a4;--a:#786cff;--b:#bd56f4;--ok:#54dda9;--danger:#ff6e87}*{box-sizing:border-box}html{background:var(--bg);color:var(--text);font:14px Inter,Segoe UI,sans-serif}body{margin:0;min-height:100vh;overflow-x:hidden;background:radial-gradient(circle at 12% -10%,#6f62ff27,transparent 30%),radial-gradient(circle at 92% 18%,#bd56f41b,transparent 28%),var(--bg)}body:before{content:'';position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(#ffffff04 1px,transparent 1px),linear-gradient(90deg,#ffffff04 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,#0008,transparent 80%)}button,input,select{font:inherit}.top{position:sticky;z-index:30;top:0;display:flex;align-items:center;gap:14px;height:72px;padding:0 max(20px,calc((100vw - 1240px)/2));border-bottom:1px solid #ffffff0d;background:#07080bd9;backdrop-filter:blur(22px)}.mark{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--a),var(--b));font-size:21px;font-weight:900;box-shadow:0 0 34px #786cff55;animation:float 4s ease-in-out infinite}.brand b,.brand small{display:block}.brand small{margin-top:3px;color:var(--muted);font-size:10px}.status{margin-left:auto;color:var(--ok);font:11px Consolas}.status:before{content:'';display:inline-block;width:7px;height:7px;margin-right:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok);animation:pulse 1.8s infinite}.shell{position:relative;width:min(1240px,calc(100% - 28px));margin:28px auto 110px}.hero{display:flex;align-items:end;justify-content:space-between;gap:20px;margin:8px 4px 24px}.hero h1{max-width:720px;margin:0;font-size:clamp(27px,4vw,48px);line-height:1.05;letter-spacing:-2px}.hero h1 span{color:transparent;background:linear-gradient(90deg,#a49cff,#df83ff);background-clip:text}.hero p{max-width:440px;margin:12px 0 0;color:var(--muted);line-height:1.6}.privacy{padding:9px 13px;border:1px solid #285846;border-radius:99px;color:#7ce8bc;background:#10231b;font-size:10px;white-space:nowrap}.layout{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(330px,.7fr);gap:16px;align-items:start}.panel{position:relative;padding:19px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,#ffffff07,#ffffff02),#0b0d12e8;box-shadow:0 18px 60px #0004;backdrop-filter:blur(18px);animation:rise .45s both}.panel:nth-child(2){animation-delay:.08s}.panel h2{margin:0 0 15px;font-size:12px;letter-spacing:1.2px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field{display:grid;gap:6px}.field.wide{grid-column:1/-1}.field>span,.section-label{color:var(--muted);font-size:9px;font-weight:700;letter-spacing:.8px}.input-wrap{display:flex;gap:7px}input,select{width:100%;min-width:0;height:42px;padding:0 12px;border:1px solid var(--line);border-radius:10px;outline:0;color:var(--text);background:#090b10;transition:.2s}input:focus,select:focus{border-color:var(--a);box-shadow:0 0 0 3px #786cff1c}.btn{min-height:40px;padding:0 14px;border:1px solid var(--line);border-radius:10px;color:var(--text);background:#151822;cursor:pointer;transition:.2s}.btn:hover{transform:translateY(-2px);border-color:#655bcc;background:#1b1f2b}.tabs{display:flex;gap:6px;margin:20px 0 12px;padding:5px;border-radius:12px;background:#080a0e}.tab{flex:1;padding:9px;border:0;border-radius:8px;color:var(--muted);background:transparent;cursor:pointer}.tab.active{color:#fff;background:#1a1d28;box-shadow:0 5px 18px #0005}.tab-page{display:none}.tab-page.active{display:grid;animation:page .22s ease}.switches{grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.switch{display:flex;align-items:center;gap:9px;min-height:42px;padding:8px 10px;border:1px solid #1c202b;border-radius:10px;color:#bec3ce;background:#0d0f15;cursor:pointer}.switch input{display:none}.switch i{position:relative;flex:0 0 34px;width:34px;height:19px;border-radius:99px;background:#303442;transition:.22s}.switch i:after{content:'';position:absolute;width:13px;height:13px;left:3px;top:3px;border-radius:50%;background:#979dac;transition:.22s}.switch input:checked+i{background:linear-gradient(90deg,var(--a),var(--b));box-shadow:0 0 16px #786cff44}.switch input:checked+i:after{left:18px;background:#fff}.switch span{font-size:11px}.key-state{margin-top:7px;color:var(--ok);font:9px Consolas}.users-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.users{display:grid;gap:9px}.user{display:grid;grid-template-columns:38px 1.5fr 1fr 1fr 54px;gap:8px;align-items:center;padding:10px;border:1px solid #1f2330;border-radius:13px;background:#0d0f15;animation:userIn .3s both}.num{display:grid;place-items:center;width:32px;height:32px;border-radius:9px;color:#d8d5ff;background:#786cff20;font-weight:800}.port{color:#8f96a7;font:9px Consolas;text-align:center}.sticky{position:fixed;z-index:40;left:0;right:0;bottom:0;padding:13px max(20px,calc((100vw - 1240px)/2));border-top:1px solid #ffffff0f;background:#08090de6;backdrop-filter:blur(22px)}.sticky-inner{display:flex;align-items:center;gap:14px}.summary{color:var(--muted);font-size:11px}.generate{margin-left:auto;min-width:220px;height:48px;border:0;border-radius:13px;color:#fff;background:linear-gradient(135deg,var(--a),var(--b));font-weight:800;cursor:pointer;box-shadow:0 10px 35px #786cff48;transition:.25s}.generate:hover{transform:translateY(-3px) scale(1.02);box-shadow:0 15px 48px #786cff66}.generate.busy{pointer-events:none;animation:busy 1s infinite}.toast{position:fixed;z-index:90;right:20px;bottom:88px;max-width:420px;padding:13px 17px;border:1px solid var(--line);border-radius:12px;background:#141722ee;transform:translateY(25px);opacity:0;transition:.3s}.toast.show{transform:none;opacity:1}.toast.error{border-color:#733242;color:#ff9caf}@keyframes float{50%{transform:translateY(-3px) rotate(3deg)}}@keyframes pulse{50%{opacity:.35}}@keyframes rise{from{opacity:0;transform:translateY(14px)}}@keyframes page{from{opacity:0;transform:translateY(5px)}}@keyframes userIn{from{opacity:0;transform:scale(.98)}}@keyframes busy{50%{filter:brightness(1.3)}}@media(max-width:900px){.layout{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}.switches{grid-template-columns:1fr}}@media(max-width:620px){.shell{width:min(100% - 18px,1240px);margin-top:15px}.top{height:62px;padding:0 12px}.hero h1{letter-spacing:-1px}.panel{padding:14px;border-radius:15px}.grid{grid-template-columns:1fr}.field.wide{grid-column:auto}.user{grid-template-columns:34px 1fr 1fr}.user .token{grid-column:2/-1}.user .port{display:none}.sticky{padding:9px}.summary{display:none}.generate{width:100%;min-width:0}.privacy{white-space:normal}.switches{grid-template-columns:1fr}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}</style></head><body>
<header class="top"><div class="mark">S</div><div class="brand"><b>Silo Builder</b><small>Local secure deployment · v__VERSION__</small></div><div class="status">LOCALHOST ONLY</div></header><main class="shell"><section class="hero"><div><h1>Build a room that is <span>secure by design.</span></h1><p>Configure every client locally. Credentials remain in this browser-to-localhost session and the generated ZIP.</p></div><div class="privacy">● No cloud · No telemetry · In-memory ZIP</div></section><div class="layout"><section class="panel"><h2>ROOM & CRYPTOGRAPHY</h2><div class="grid"><label class="field"><span>SERVER ID</span><input id="server" inputmode="numeric" autocomplete="off"></label><label class="field"><span>CHANNEL ID</span><input id="channel" inputmode="numeric" autocomplete="off"></label><label class="field wide"><span>PRIMARY KEY · AES-256-GCM</span><div class="input-wrap"><input id="primary" type="password" autocomplete="new-password"><button class="btn" data-gen="primary">Generate</button><button class="btn" data-copy="primary">Copy</button></div><small class="key-state" id="primaryState"></small></label><label class="field wide"><span>SECONDARY KEY · CHACHA20-POLY1305</span><div class="input-wrap"><input id="secondary" type="password" autocomplete="new-password"><button class="btn" data-gen="secondary">Generate</button><button class="btn" data-copy="secondary">Copy</button></div><small class="key-state" id="secondaryState"></small></label><label class="field"><span>STARTING PORT</span><input id="port" type="number" min="1024" max="65535" value="8081"></label><label class="field"><span>USERS</span><select id="count"></select></label></div><nav class="tabs"><button class="tab active" data-tab="interface">Interface</button><button class="tab" data-tab="features">Features</button><button class="tab" data-tab="security">Security</button></nav><div class="tab-page switches active" id="interface"></div><div class="tab-page switches" id="features"></div><div class="tab-page grid" id="security"><label class="switch"><input id="dual_layer_encryption" type="checkbox" checked><i></i><span>Dual independent AEAD</span></label><label class="switch"><input id="encrypted_local_history" type="checkbox" checked><i></i><span>Encrypted local history</span></label><label class="field"><span>AUTO-LOCK SECONDS</span><input id="auto_lock_seconds" type="number" min="30" max="3600" value="300"></label><label class="field"><span>ROTATE AFTER MESSAGES</span><input id="key_rotation_interval" type="number" min="1" max="10000" value="50"></label></div></section><section class="panel"><div class="users-head"><h2>PARTICIPANTS</h2><small id="portRange"></small></div><div class="users" id="users"></div></section></div></main><footer class="sticky"><div class="sticky-inner"><div class="summary" id="summary">Ready to configure</div><button class="generate" id="generate">Generate encrypted clients ↓</button></div></footer><div class="toast" id="toast"></div>
<script nonce="__NONCE__">const csrf='__CSRF__',alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+',byId=x=>document.getElementById(x);const defs={interface:[['show_security_panel','Security Center'],['show_statistics','Statistics & diagnostics'],['enable_presence','Presence'],['enable_wallpapers','Wallpaper customization'],['enable_topics','Topics'],['enable_search','Global search']],features:[['enable_attachments','Encrypted attachments'],['enable_voice_notes','Encrypted voice notes'],['enable_polls','Polls'],['enable_view_once','View-once messages'],['enable_disappearing','Disappearing messages'],['enable_mobile_access','Mobile QR access'],['enable_panic','Emergency panic mode'],['read_receipts','Encrypted read receipts'],['memory_only','Memory-only storage',false]]};function switchHtml(id,label,on=true){return `<label class="switch"><input id="${id}" type="checkbox" ${on?'checked':''}><i></i><span>${label}</span></label>`}for(const [page,items] of Object.entries(defs))byId(page).innerHTML=items.map(x=>switchHtml(x[0],x[1],x[2]!==false)).join('');for(let i=1;i<=100;i++)byId('count').add(new Option(i,i));byId('count').value=2;function secureKey(){let a=new Uint32Array(32);crypto.getRandomValues(a);return [...a].map(x=>alphabet[x%alphabet.length]).join('')}function updateKey(id){let v=byId(id).value,bits=Math.round(v.length*Math.log2(alphabet.length));byId(id+'State').textContent=`${v.length} characters · ~${bits} bits · ${bits>=180?'Excellent':bits>=110?'Strong':'Increase length'}`}document.querySelectorAll('[data-gen]').forEach(b=>b.onclick=()=>{byId(b.dataset.gen).value=secureKey();updateKey(b.dataset.gen)});document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{await navigator.clipboard.writeText(byId(b.dataset.copy).value);notify('Key copied')});['primary','secondary'].forEach(id=>byId(id).addEventListener('input',()=>updateKey(id)));byId('primary').value=secureKey();byId('secondary').value=secureKey();updateKey('primary');updateKey('secondary');document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab,.tab-page').forEach(x=>x.classList.remove('active'));b.classList.add('active');byId(b.dataset.tab).classList.add('active')});function rebuild(){let count=+byId('count').value,old=[...document.querySelectorAll('.user')].map(n=>({token:n.querySelector('.token').value,id:n.querySelector('.uid').value,name:n.querySelector('.uname').value}));byId('users').innerHTML='';for(let i=0;i<count;i++){let v=old[i]||{token:'',id:'',name:`User ${i+1}`},n=document.createElement('div');n.className='user';n.innerHTML=`<div class="num">${i+1}</div><input class="token" type="password" autocomplete="off" placeholder="Discord bot token" value="${escapeAttr(v.token)}"><input class="uid" inputmode="numeric" placeholder="Bot / User ID" value="${escapeAttr(v.id)}"><input class="uname" maxlength="40" placeholder="Username" value="${escapeAttr(v.name)}"><div class="port">:${+byId('port').value+i}</div>`;byId('users').appendChild(n)}updateSummary()}function escapeAttr(v){return String(v).replace(/[&"<>]/g,c=>({'&':'&amp;','"':'&quot;','<':'&lt;','>':'&gt;'}[c]))}function updateSummary(){let n=+byId('count').value,p=+byId('port').value;byId('portRange').textContent=`Ports ${p}–${p+n-1}`;byId('summary').textContent=`${n} client${n===1?'':'s'} · dual AEAD · local ZIP`;document.querySelectorAll('.port').forEach((x,i)=>x.textContent=':'+(p+i))}byId('count').onchange=rebuild;byId('port').oninput=updateSummary;function notify(text,error=false){let t=byId('toast');t.textContent=text;t.className='toast show'+(error?' error':'');setTimeout(()=>t.className='toast',3200)}function value(id){return byId(id).checked}function payload(){let data={server_id:byId('server').value,channel_id:byId('channel').value,shared_key:byId('primary').value,secondary_key:byId('secondary').value,start_port:+byId('port').value,auto_lock_seconds:+byId('auto_lock_seconds').value,key_rotation_interval:+byId('key_rotation_interval').value,users:[...document.querySelectorAll('.user')].map(n=>({token:n.querySelector('.token').value,user_id:n.querySelector('.uid').value,username:n.querySelector('.uname').value}))};for(const id of [...Object.values(defs).flat().map(x=>x[0]),'dual_layer_encryption','encrypted_local_history'])data[id]=value(id);return data}byId('generate').onclick=async()=>{let b=byId('generate');b.classList.add('busy');b.textContent='Building securely…';try{let r=await fetch('/generate',{method:'POST',headers:{'Content-Type':'application/json','X-Silo-CSRF':csrf},body:JSON.stringify(payload())});if(!r.ok){let d=await r.json();throw Error(d.error||'Generation failed')}let blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='Silo_Clients.zip';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000);notify('Clients generated successfully')}catch(e){notify(e.message,true)}finally{b.classList.remove('busy');b.textContent='Generate encrypted clients ↓'}};rebuild();</script></body></html>'''

# Keep the embedded UI compact while switching generation from browser downloads
# to direct, local files beside the Builder.
HTML = HTML.replace("generated ZIP", "generated local files")
HTML = HTML.replace("local ZIP", "local files")
HTML = HTML.replace("fetch('/generate'", "fetch(window.location.href")
HTML = HTML.replace(
    "let blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='Silo_Clients.zip';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000);notify('Clients generated successfully')",
    "let d=await r.json();notify(`${d.count} client${d.count===1?'':'s'} saved beside the Builder`)",
)


class Handler(BaseHTTPRequestHandler):
    server_version = "SiloLocalBuilder"
    def log_message(self, *_args): pass
    def trusted_host(self) -> bool:
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
        return host in {"127.0.0.1", "localhost"}
    def security_headers(self, content_type: str, length: int):
        self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store"); self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{TOKEN}'; connect-src 'self'")
    def send_bytes(self, status: int, body: bytes, content_type: str):
        self.send_response(status); self.security_headers(content_type, len(body)); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if not self.trusted_host():
            self.send_bytes(403, b"Forbidden", "text/plain"); return
        if urlparse(self.path).path == "/":
            body = HTML.replace("__VERSION__", BUILDER_VERSION).replace("__CSRF__", TOKEN).replace("__NONCE__", TOKEN).encode()
            self.send_bytes(200, body, "text/html; charset=utf-8")
        elif urlparse(self.path).path == "/health": self.send_bytes(200, b'{"ok":true}', "application/json")
        else: self.send_bytes(404, b"Not found", "text/plain")
    def do_POST(self):
        try:
            if not self.trusted_host(): raise PermissionError("Invalid host")
            if self.headers.get("X-Silo-CSRF") != TOKEN: raise PermissionError("Invalid local session")
            origin = self.headers.get("Origin", "")
            if origin and urlparse(origin).hostname not in {"127.0.0.1", "localhost"}: raise PermissionError("Invalid origin")
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= MAX_REQUEST: raise ValueError("Invalid request size")
            archive = validate_and_build(json.loads(self.rfile.read(size)))
            saved = save_clients_beside_builder(archive)
            body = json.dumps({"ok": True, "count": len(saved), "files": saved}).encode()
            self.send_bytes(200, body, "application/json")
        except FileNotFoundError as exc:
            body = json.dumps({"error": str(exc)}).encode(); self.send_bytes(400, body, "application/json")
        except (ValueError, PermissionError, json.JSONDecodeError) as exc:
            body = json.dumps({"error": str(exc)}).encode(); self.send_bytes(400, body, "application/json")
        except Exception:
            self.send_bytes(500, b'{"error":"The clients could not be generated"}', "application/json")


def main(port: int = 0):
    server = ThreadingHTTPServer((HOST, port), Handler)
    url = f"http://{HOST}:{server.server_port}/"
    print(f"Silo Web Builder {BUILDER_VERSION} · {url}")
    threading.Timer(0.45, lambda: webbrowser.open(url)).start()
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__": main()
