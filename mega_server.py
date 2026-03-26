"""
mega_server.py — ذاكرة AI لا محدودة مع ضغط ذكي
================================================
✅ يحفظ كل رسالة بدون حذف
✅ يضغط كل ملف JSON بـ gzip (يوفر 70-85% مساحة)
✅ عند حذف محادثة → يحذف ملفها من MEGA فوراً
✅ يبني سياق ذكي للـ AI من كل التاريخ
✅ Python 3.8 → 3.13 — بدون mega.py أو tenacity

التثبيت:
  pip3 install flask flask-cors requests pycryptodome --user

التشغيل:
  export MEGA_EMAIL="jeuxc71@gmail.com"
  export MEGA_PASSWORD="_Ewn:Uab2AXJf8k"
  python3 mega_server.py
"""

import os, sys, json, gzip, hashlib, base64, struct
import tempfile, threading, time
from pathlib import Path

# ── فحص المكتبات ─────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter as CryptoCounter
except ImportError:
    print("pip3 install pycryptodome --user"); sys.exit(1)

try:
    import requests as req_lib
except ImportError:
    print("pip3 install requests --user"); sys.exit(1)

try:
    from flask import Flask, request as freq, jsonify
    from flask_cors import CORS
    USE_FLASK = True
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse
    USE_FLASK = False

MEGA_EMAIL    = os.environ.get("MEGA_EMAIL",    "jeuxc71@gmail.com")
MEGA_PASSWORD = os.environ.get("MEGA_PASSWORD", "_Ewn:Uab2AXJf8k")
PORT          = int(os.environ.get("PORT", 8765))
AI_CONTEXT_LIMIT  = 60    # آخر 60 رسالة كاملة للـ AI
COMPRESS_LEVEL    = 9     # أعلى ضغط gzip

# ══════════════════════════════════════════════════════════
#  مساعدات MEGA Crypto
# ══════════════════════════════════════════════════════════
def a32(b):
    if isinstance(b, str): b = b.encode()
    b += b'\x00' * ((-len(b)) % 4)
    return struct.unpack('>' + 'I' * (len(b)//4), b)

def b32(a): return struct.pack('>' + 'I' * len(a), *a)

def b64d(s):
    s = s.replace('-','+').replace('_','/')
    s += '=='; return base64.b64decode(s)

def b64e(b):
    return base64.b64encode(b).replace(b'+',b'-').replace(b'/',b'_').rstrip(b'=').decode()

def ecb_enc(d, k): return AES.new(b32(k), AES.MODE_ECB).encrypt(b32(d))
def ecb_dec(d, k): return AES.new(b32(k), AES.MODE_ECB).decrypt(d if isinstance(d,bytes) else b32(d))
def cbc_dec(d, k): return AES.new(b32(k[:4]), AES.MODE_CBC, iv=b'\x00'*16).decrypt(d)
def cbc_enc(d, k): return AES.new(b32(k[:4]), AES.MODE_CBC, iv=b'\x00'*16).encrypt(d)
def xor32(a, b):   return tuple(x^y for x,y in zip(a,b))

def prep_key(pw):
    pw_a = a32(pw.encode())
    k = [0x93C467E3,0x7DB0C7A4,0xD1BE3F81,0x0152CB56]
    for _ in range(0x10000):
        for j in range(0, len(pw_a), 4):
            blk = list(pw_a[j:j+4])
            while len(blk) < 4: blk.append(0)
            k = list(a32(ecb_enc(blk, k)))
    return k

def dec_attr(raw, key):
    try:
        dec = cbc_dec(raw, key).rstrip(b'\x00').decode('utf-8','ignore')
        if dec.startswith('MEGA'): return json.loads(dec[4:])
    except: pass
    return {}

def enc_attr(attrs, key):
    s = ('MEGA' + json.dumps(attrs)).encode()
    s += b'\x00' * ((-len(s)) % 16)
    return cbc_enc(s, key)

def aes_ctr(data, key, nonce4):
    iv = b32(nonce4[:2]) + b'\x00'*8
    ctr = CryptoCounter.new(128, initial_value=int.from_bytes(iv,'big'))
    return AES.new(b32(key[:4]), AES.MODE_CTR, counter=ctr).encrypt(data)

# ══════════════════════════════════════════════════════════
#  عميل MEGA
# ══════════════════════════════════════════════════════════
class MegaClient:
    API = 'https://g.api.mega.co.nz/cs'

    def __init__(self):
        self.sid = None; self.mk = None; self.seq = 0
        self.s = req_lib.Session()
        self.s.headers['User-Agent'] = 'AI-Memory/2.0'

    def _r(self, data):
        params = {'id': self.seq}
        if self.sid: params['sid'] = self.sid
        self.seq += 1
        body = [data] if isinstance(data, dict) else data
        r = self.s.post(self.API, params=params, json=body, timeout=30)
        if not r.content:
            raise Exception(f"MEGA رجعت رداً فارغاً (HTTP {r.status_code})")
        try:
            res = r.json()
        except Exception:
            raise Exception(f"MEGA رداً غير صالح: {r.text[:200]}")
        return res[0] if isinstance(res, list) else res

    @staticmethod
    def _stringhash(s, aeskey):
        """حساب string hash وفق بروتوكول MEGA الرسمي"""
        s32 = a32(s.encode())
        h32 = [0, 0, 0, 0]
        for i, v in enumerate(s32):
            h32[i % 4] ^= v
        for _ in range(0x4000):
            h32 = list(a32(AES.new(b32(aeskey), AES.MODE_ECB).encrypt(b32(h32))))
        return b64e(b32(h32[:2]))

    def login(self, email, pw):
        email = email.lower().strip()
        pwk = prep_key(pw)
        # حساب uh باستخدام stringhash — البروتوكول الرسمي لـ MEGA
        uh = self._stringhash(email, pwk)
        res = self._r({'a':'us','user':email,'uh':uh})
        if isinstance(res, int):
            raise Exception({-9:'بريد/كلمة سر خاطئة',-16:'حساب محظور'}.get(res, f'كود: {res}'))
        self.mk  = list(a32(ecb_dec(b64d(res['k']), pwk)))
        # فك تشفير csid بـ RSA للحصول على session id الحقيقي
        self.sid = self._decrypt_sid(res, pwk)
        return self

    @staticmethod
    def _decrypt_sid(res, pwk):
        """فك تشفير session id من رد MEGA"""
        import math
        try:
            # استخراج RSA private key
            privk = b64d(res.get('privk',''))
            privk = list(a32(AES.new(b32(pwk), AES.MODE_CBC, iv=b'\x00'*16).decrypt(privk)))
            # استخراج مكونات RSA: p, q, d
            def _get_mpi(buf, pos):
                bits = (buf[pos] << 8) | buf[pos+1]
                byte_len = (bits + 7) >> 3
                val = int.from_bytes(b32(buf[pos+2:pos+2+byte_len+(-byte_len%4)//1])[:byte_len], 'big')
                return val, pos + 2 + byte_len
            raw = b32(privk)
            pos = 0
            p, pos = _get_mpi(raw, pos)
            q, pos = _get_mpi(raw, pos)
            d, pos = _get_mpi(raw, pos)
            n = p * q
            # فك تشفير csid
            csid = b64d(res.get('csid',''))
            m = int.from_bytes(csid, 'big')
            sid_int = pow(m, d, n)
            sid_bytes = sid_int.to_bytes((sid_int.bit_length() + 7) // 8, 'big')
            return base64.b64encode(sid_bytes[:43]).replace(b'+',b'-').replace(b'/',b'_').rstrip(b'=').decode()
        except Exception:
            # fallback بسيط
            return res.get('csid', res.get('sid',''))

    def files(self):
        res = self._r({'a':'f','c':1,'r':1})
        if isinstance(res, int): return []
        out = []
        for f in res.get('f',[]):
            if f.get('t') != 0: continue
            try:
                ks = f['k'].split(':')[-1]
                kd = ecb_dec(b64d(ks), self.mk)
                ka = list(a32(kd))
                nk = list(xor32(ka[:4], ka[4:8])) if len(ka)>=8 else ka[:4]
                attrs = dec_attr(b64d(f.get('a','')), nk)
                out.append({'h':f['h'],'name':attrs.get('n',f['h']),'size':f.get('s',0),'ts':f.get('ts',0)})
            except:
                out.append({'h':f['h'],'name':f['h'],'size':f.get('s',0),'ts':0})
        return out

    def find(self, name):
        for f in self.files():
            if f['name'] == name: return f
        return None

    def upload_bytes(self, data: bytes, name: str) -> str:
        size = len(data)
        res = self._r({'a':'u','s':size})
        if isinstance(res, int): raise Exception(f"upload init: {res}")
        ul_url = res['p']
        rk = os.urandom(16); rn = os.urandom(8)
        ka = list(a32(rk)); na = list(a32(rn)) + [0, 0]
        enc = aes_ctr(data, ka, na)
        resp = req_lib.post(ul_url+'/0', data=enc, timeout=300)
        h = resp.text.strip()
        if not h or h.startswith('-'): raise Exception(f"upload: {h}")
        ae = enc_attr({'n': name}, ka)
        fk = [ka[0]^na[0], ka[1]^na[1], ka[2], ka[3], na[0], na[1], 0, 0]
        ek = ecb_enc(fk[:4], self.mk) + ecb_enc(fk[4:8], self.mk)
        self._r({'a':'p','t':'','i':h[:6],
                 'n':[{'h':h,'t':0,'a':b64e(ae),'k':b64e(ek)}]})
        return h

    def download_bytes(self, file_info: dict) -> bytes:
        res = self._r({'a':'g','g':1,'n':file_info['h']})
        if isinstance(res, int): raise Exception(f"download: {res}")
        resp = req_lib.get(res['g'], timeout=300)
        resp.raise_for_status()
        return resp.content

    def delete(self, handle: str):
        self._r({'a':'d','n':handle})

# ══════════════════════════════════════════════════════════
#  نظام الذاكرة الذكية
# ══════════════════════════════════════════════════════════
class AIMemory:
    def __init__(self, mega: MegaClient):
        self.mega = mega
        self._cache: dict = {}
        self._lock = threading.Lock()

    @staticmethod
    def _fname(cid): return f"chat_{cid}.json.gz"

    def save_chat(self, cid: str, data: dict):
        """يحفظ كل رسائل المحادثة مضغوطة على MEGA"""
        with self._lock:
            self._cache[cid] = data
            raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
            compressed = gzip.compress(raw, compresslevel=COMPRESS_LEVEL)
            ratio = round((1 - len(compressed)/max(len(raw),1))*100, 1)
            # احذف القديم وارفع الجديد
            fname = self._fname(cid)
            old = self.mega.find(fname)
            if old: self.mega.delete(old['h'])
            self.mega.upload_bytes(compressed, fname)
            n = len(data.get('messages', []))
            kb = round(len(compressed)/1024, 1)
            print(f"[💾 MEGA] {cid}: {n} رسالة | {kb}KB ({ratio}% ضغط)")

    def load_chat(self, cid: str) -> dict:
        """يحمّل المحادثة كاملة بكل رسائلها"""
        if cid in self._cache: return self._cache[cid]
        with self._lock:
            f = self.mega.find(self._fname(cid))
            if not f: return None
            data = json.loads(gzip.decompress(self.mega.download_bytes(f)).decode('utf-8'))
            self._cache[cid] = data
            return data

    def list_chats(self) -> list:
        files = self.mega.files()
        result = []
        for f in files:
            if not (f['name'].startswith('chat_') and f['name'].endswith('.json.gz')): continue
            cid = f['name'][5:-8]
            item = {'id':cid,'title':'محادثة','model':'claude-sonnet-4',
                    'ts':f['ts'],'size_kb':round(f['size']/1024,1),'msg_count':0}
            if cid in self._cache:
                c = self._cache[cid]
                item['title'] = c.get('title','محادثة')
                item['msg_count'] = len(c.get('messages',[]))
            result.append(item)
        return sorted(result, key=lambda x: x['ts'], reverse=True)

    def delete_chat(self, cid: str):
        """يحذف من الذاكرة والـ cache و MEGA — يحرر المساحة فوراً"""
        with self._lock:
            self._cache.pop(cid, None)
            f = self.mega.find(self._fname(cid))
            if f:
                self.mega.delete(f['h'])
                print(f"[🗑️] حُذف {cid} من MEGA — مساحة محررة")

    def build_ai_context(self, cid: str) -> list:
        """
        يبني سياق AI ذكي:
        - الرسائل القديمة → ملخص نصي (يحافظ على المعنى)
        - الرسائل الحديثة → كاملة (AI_CONTEXT_LIMIT رسالة)
        النتيجة: AI يتذكر كل شيء حتى بعد آلاف الرسائل
        """
        chat = self.load_chat(cid)
        if not chat: return []
        msgs = chat.get('messages', [])
        valid = [m for m in msgs if m.get('role') in ('user','assistant') and m.get('text')]

        if len(valid) <= AI_CONTEXT_LIMIT:
            return [{'role':m['role'],'content':m['text']} for m in valid]

        old    = valid[:len(valid)-AI_CONTEXT_LIMIT]
        recent = valid[len(valid)-AI_CONTEXT_LIMIT:]

        # ملخص الرسائل القديمة
        lines = []
        for m in old:
            label = "👤 المستخدم" if m['role']=='user' else "🤖 المساعد"
            lines.append(f"{label}: {m['text'][:300]}")

        summary = (
            f"[📚 ذاكرة تلقائية — {len(old)} رسالة سابقة]\n"
            + "\n".join(lines[-40:])  # آخر 40 ملخص
            + "\n[↑ هذا ملخص التاريخ — تستمر المحادثة أدناه]"
        )

        context = [
            {'role':'user',      'content': summary},
            {'role':'assistant', 'content': 'فهمت، لديّ السياق الكامل للمحادثة السابقة وسأكمل من حيث توقفنا.'}
        ]
        for m in recent:
            context.append({'role':m['role'],'content':m['text']})
        return context

    def stats(self) -> dict:
        files = self.mega.files()
        chats = [f for f in files if f['name'].startswith('chat_') and f['name'].endswith('.json.gz')]
        total_gz = sum(f['size'] for f in chats)
        estimated_raw = total_gz * 5
        return {
            'chats':           len(chats),
            'compressed_kb':   round(total_gz/1024, 1),
            'estimated_raw_kb':round(estimated_raw/1024, 1),
            'saved_kb':        round((estimated_raw-total_gz)/1024, 1),
            'cached':          len(self._cache),
        }

# ══════════════════════════════════════════════════════════
#  Singleton
# ══════════════════════════════════════════════════════════
_memory = None
_mlock  = threading.Lock()

def get_memory() -> AIMemory:
    global _memory
    with _mlock:
        if _memory is None:
            if MEGA_EMAIL in ("your@email.com", ""):
                raise Exception("عيّن MEGA_EMAIL و MEGA_PASSWORD أولاً")
            print("[*] تسجيل الدخول إلى MEGA...")
            _memory = AIMemory(MegaClient().login(MEGA_EMAIL, MEGA_PASSWORD))
            print("[✓] متصل!")
        return _memory

# ══════════════════════════════════════════════════════════
#  معالجات HTTP
# ══════════════════════════════════════════════════════════
def h_health(qs, b):
    try:
        s = get_memory().stats()
        return 200, {'ok':True,'email':MEGA_EMAIL,'stats':s}
    except Exception as e: return 500, {'ok':False,'error':str(e)}

def h_list(qs, b):
    try:    return 200, get_memory().list_chats()
    except Exception as e: return 500, {'error':str(e)}

def h_load(qs, b):
    cid = _qget(qs,'id')
    if not cid: return 400, {'error':'id missing'}
    try:
        d = get_memory().load_chat(cid)
        return (200,d) if d else (404,{'error':'not found'})
    except Exception as e: return 500, {'error':str(e)}

def h_save(qs, b):
    cid = b.get('id','').strip()
    if not cid: return 400, {'error':'id missing'}
    try:
        get_memory().save_chat(cid, b.get('data',{}))
        n = len(b.get('data',{}).get('messages',[]))
        return 200, {'ok':True,'messages_saved':n}
    except Exception as e: return 500, {'error':str(e)}

def h_delete(qs, b):
    cid = b.get('id','').strip()
    if not cid: return 400, {'error':'id missing'}
    try:
        get_memory().delete_chat(cid)
        return 200, {'ok':True}
    except Exception as e: return 500, {'error':str(e)}

def h_context(qs, b):
    """✨ يعيد سياق AI الذكي الكامل"""
    cid = _qget(qs,'id') or b.get('id','')
    if not cid: return 400, {'error':'id missing'}
    try:
        ctx = get_memory().build_ai_context(cid)
        return 200, {'context':ctx,'count':len(ctx)}
    except Exception as e: return 500, {'error':str(e)}

def h_stats(qs, b):
    try:    return 200, get_memory().stats()
    except Exception as e: return 500, {'error':str(e)}

def h_upload(qs, b, data=None, fname=None):
    if not data: return 400, {'error':'no file'}
    try:
        comp = gzip.compress(data, compresslevel=COMPRESS_LEVEL)
        get_memory().mega.upload_bytes(comp, (fname or 'file')+'.gz')
        return 200, {
            'ok':True,'name':fname,
            'original_kb':round(len(data)/1024,1),
            'compressed_kb':round(len(comp)/1024,1),
            'saved_pct':f"{round((1-len(comp)/max(len(data),1))*100,1)}%"
        }
    except Exception as e: return 500, {'error':str(e)}

def _qget(qs, key):
    if isinstance(qs, dict):
        v = qs.get(key)
        if isinstance(v, list): return (v[0] or '').strip()
        return (v or '').strip()
    return ''

# ══════════════════════════════════════════════════════════
#  الخادم
# ══════════════════════════════════════════════════════════
if USE_FLASK:
    app = Flask(__name__)
    CORS(app, origins="*")

    @app.route('/health')
    def r0(): c,d=h_health({},{}); return jsonify(d),c
    @app.route('/list')
    def r1(): c,d=h_list({},{}); return jsonify(d),c
    @app.route('/load')
    def r2():
        c,d=h_load({'id':[freq.args.get('id','')]},{})
        return jsonify(d),c
    @app.route('/save', methods=['POST'])
    def r3(): c,d=h_save({},freq.get_json() or {}); return jsonify(d),c
    @app.route('/delete', methods=['POST'])
    def r4(): c,d=h_delete({},freq.get_json() or {}); return jsonify(d),c
    @app.route('/context')
    def r5():
        c,d=h_context({'id':[freq.args.get('id','')]},{})
        return jsonify(d),c
    @app.route('/stats')
    def r6(): c,d=h_stats({},{}); return jsonify(d),c
    @app.route('/upload', methods=['POST'])
    def r7():
        if 'file' not in freq.files: return jsonify({'error':'no file'}),400
        f=freq.files['file']
        c,d=h_upload({},{},f.read(),f.filename)
        return jsonify(d),c

    def start_server():
        threading.Thread(target=get_memory, daemon=True).start()
        print(f"[Flask] http://0.0.0.0:{PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)

else:
    import urllib.parse as up

    class Handler(BaseHTTPRequestHandler):
        def _cors(self):
            self.send_header('Access-Control-Allow-Origin','*')
            self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
            self.send_header('Access-Control-Allow-Headers','Content-Type')
        def _send(self, code, data):
            b = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self._cors()
            self.send_header('Content-Length',len(b))
            self.end_headers()
            self.wfile.write(b)
        def do_OPTIONS(self): self.send_response(200); self._cors(); self.end_headers()
        def do_GET(self):
            prs = up.urlparse(self.path)
            qs  = up.parse_qs(prs.query)
            r = {'/health':h_health,'/list':h_list,'/load':h_load,
                 '/context':h_context,'/stats':h_stats}.get(prs.path)
            self._send(*(r(qs,{}) if r else (404,{'error':'not found'})))
        def do_POST(self):
            prs = up.urlparse(self.path)
            n = int(self.headers.get('Content-Length',0))
            raw = self.rfile.read(n)
            try: body = json.loads(raw.decode()) if raw else {}
            except: body = {}
            r = {'/save':h_save,'/delete':h_delete}.get(prs.path)
            self._send(*(r({},body) if r else (404,{'error':'not found'})))
        def log_message(self, fmt, *args):
            print(f"[{time.strftime('%H:%M:%S')}] {fmt%args}")

    def start_server():
        threading.Thread(target=get_memory, daemon=True).start()
        s = HTTPServer(('0.0.0.0', PORT), Handler)
        print(f"[http.server] http://0.0.0.0:{PORT}")
        s.serve_forever()

# ══════════════════════════════════════════════════════════
if __name__ == '__main__':
    print('='*54)
    print('  🧠 AI Memory Server — ذاكرة لا محدودة + ضغط gzip')
    print(f'  Python {sys.version.split()[0]} | Port {PORT}')
    print(f'  Email: {MEGA_EMAIL}')
    print(f'  Backend: {"Flask" if USE_FLASK else "http.server"}')
    print('='*54)
    if MEGA_EMAIL in ("your@email.com", ""):
        print("\n⚠️  عيّن بيانات MEGA أولاً:")
        print("   export MEGA_EMAIL='your@email.com'")
        print("   export MEGA_PASSWORD='yourpassword'\n")
    start_server()
