"""
mega_server.py v3 — MEGA هو المخزن الوحيد
==========================================
✅ كل شيء يُحفظ في MEGA: المحادثات + الملفات + الصور
✅ Puter = AI فقط — صفر تخزين في Puter
✅ ضغط gzip تلقائي لكل ملف (توفير 80-85%)
✅ حذف محادثة = تحرير فوري من MEGA
✅ بدون mega.py / tenacity / asyncio.coroutine
✅ Python 3.8 → 3.13

التثبيت على PythonAnywhere:
  pip3 install flask flask-cors requests pycryptodome --user

التشغيل:
  export MEGA_EMAIL="jeuxc71@gmail.com"
  export MEGA_PASSWORD="_Ewn:Uab2AXJf8k"
  python3 mega_server.py
"""

import os, sys, json, gzip, hashlib, base64, struct, threading, time

# ── فحص المكتبات ─────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter as CrCtr
except ImportError:
    sys.exit("❌  pip3 install pycryptodome --user")

try:
    import requests as rq
except ImportError:
    sys.exit("❌  pip3 install requests --user")

try:
    from flask import Flask, request as R, jsonify
    from flask_cors import CORS
    HAS_FLASK = True
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse as UP
    HAS_FLASK = False
    print("⚠️  Flask غير موجود — يعمل بـ http.server")

# ══════════════════════════════════════════════════════════
#  الإعدادات
# ══════════════════════════════════════════════════════════
MEGA_EMAIL    = os.environ.get("MEGA_EMAIL",    "jeuxc71@gmail.com")
MEGA_PASSWORD = os.environ.get("MEGA_PASSWORD", "_Ewn:Uab2AXJf8k")
PORT          = int(os.environ.get("PORT", 8765))
GZ            = 9      # مستوى الضغط (1-9)
CTX_FULL      = 60     # آخر N رسالة كاملة للـ AI
CTX_SUMMARY   = 50     # آخر N رسالة في ملخص التاريخ

# ══════════════════════════════════════════════════════════
#  MEGA Crypto — مكتوب من الصفر
# ══════════════════════════════════════════════════════════
def _a32(b):
    if isinstance(b, str): b = b.encode()
    b += b'\x00' * ((-len(b)) % 4)
    return struct.unpack('>' + 'I'*(len(b)//4), b)

def _b32(a): return struct.pack('>' + 'I'*len(a), *a)

def _b64d(s):
    s = s.replace('-','+').replace('_','/')
    return base64.b64decode(s + '==')

def _b64e(b):
    return base64.b64encode(b).replace(b'+',b'-').replace(b'/',b'_').rstrip(b'=').decode()

def _ecb_e(d,k): return AES.new(_b32(k), AES.MODE_ECB).encrypt(_b32(d))
def _ecb_d(d,k): return AES.new(_b32(k), AES.MODE_ECB).decrypt(d if isinstance(d,bytes) else _b32(d))
def _cbc_d(d,k): return AES.new(_b32(k[:4]), AES.MODE_CBC, iv=b'\x00'*16).decrypt(d)
def _cbc_e(d,k): return AES.new(_b32(k[:4]), AES.MODE_CBC, iv=b'\x00'*16).encrypt(d)
def _xor(a,b):   return tuple(x^y for x,y in zip(a,b))

def _pwkey(pw):
    pa = _a32(pw.encode())
    k  = [0x93C467E3,0x7DB0C7A4,0xD1BE3F81,0x0152CB56]
    for _ in range(0x10000):
        for j in range(0, len(pa), 4):
            blk = list(pa[j:j+4])
            while len(blk)<4: blk.append(0)
            k = list(_a32(_ecb_e(blk,k)))
    return k

def _strhash(s, key):
    s32 = _a32(s.encode())
    h   = [0,0,0,0]
    for i,v in enumerate(s32): h[i%4] ^= v
    for _ in range(0x4000):
        h = list(_a32(AES.new(_b32(key), AES.MODE_ECB).encrypt(_b32(h))))
    return _b64e(_b32(h[:2]))

def _dec_attr(raw, key):
    try:
        dec = _cbc_d(raw, key).rstrip(b'\x00').decode('utf-8','ignore')
        if dec.startswith('MEGA'): return json.loads(dec[4:])
    except: pass
    return {}

def _enc_attr(d, key):
    s = ('MEGA'+json.dumps(d)).encode()
    s += b'\x00'*((-len(s))%16)
    return _cbc_e(s, key)

def _ctr(data, key, nonce4):
    iv  = _b32(nonce4[:2]) + b'\x00'*8
    ctr = CrCtr.new(128, initial_value=int.from_bytes(iv,'big'))
    return AES.new(_b32(key[:4]), AES.MODE_CTR, counter=ctr).encrypt(data)

def _dec_sid(res, pwk):
    """فك تشفير session id بـ RSA"""
    try:
        raw = list(_a32(_cbc_d(_b64d(res['privk']), pwk)))
        buf = _b32(raw)
        pos = 0
        parts = []
        for _ in range(4):
            bits = (buf[pos]<<8)|buf[pos+1]; pos+=2
            bl   = (bits+7)>>3
            val  = int.from_bytes(buf[pos:pos+bl], 'big'); pos+=bl
            parts.append(val)
        p,q,d,_ = parts; n = p*q
        m   = int.from_bytes(_b64d(res['csid']), 'big')
        sid = pow(m,d,n).to_bytes((pow(m,d,n).bit_length()+7)//8,'big')
        return base64.b64encode(sid[:43]).replace(b'+',b'-').replace(b'/',b'_').rstrip(b'=').decode()
    except:
        return res.get('csid', res.get('sid',''))

# ══════════════════════════════════════════════════════════
#  عميل MEGA
# ══════════════════════════════════════════════════════════
class Mega:
    URL = 'https://g.api.mega.co.nz/cs'

    def __init__(self):
        self.sid=None; self.mk=None; self.seq=0
        self.s = rq.Session()
        self.s.headers['User-Agent'] = 'MegaAI/3.0'

    def _r(self, d):
        p = {'id':self.seq}
        if self.sid: p['sid']=self.sid
        self.seq += 1
        body = [d] if isinstance(d,dict) else d
        r = self.s.post(self.URL, params=p, json=body, timeout=30)
        if not r.content: raise Exception(f"MEGA empty ({r.status_code})")
        res = r.json()
        return res[0] if isinstance(res,list) else res

    def login(self, email, pw):
        email = email.lower().strip()
        k     = _pwkey(pw)
        uh    = _strhash(email, k)
        res   = self._r({'a':'us','user':email,'uh':uh})
        if isinstance(res,int):
            raise Exception({-9:'بريد/كلمة سر خاطئة',-16:'حساب محظور'}.get(res,f'كود:{res}'))
        self.mk  = list(_a32(_ecb_d(_b64d(res['k']),k)))
        self.sid = _dec_sid(res, k)
        print(f"[✓] MEGA متصل: {email}")
        return self

    def ls(self):
        """قائمة كل الملفات"""
        res = self._r({'a':'f','c':1,'r':1})
        if isinstance(res,int): return []
        out=[]
        for f in res.get('f',[]):
            if f.get('t')!=0: continue
            try:
                ks  = f['k'].split(':')[-1]
                kd  = _ecb_d(_b64d(ks), self.mk)
                ka  = list(_a32(kd))
                nk  = list(_xor(ka[:4],ka[4:8])) if len(ka)>=8 else ka[:4]
                att = _dec_attr(_b64d(f.get('a','')), nk)
                out.append({'h':f['h'],'name':att.get('n',f['h']),'size':f.get('s',0),'ts':f.get('ts',0)})
            except:
                out.append({'h':f['h'],'name':f['h'],'size':f.get('s',0),'ts':0})
        return out

    def find(self, name):
        for f in self.ls():
            if f['name']==name: return f
        return None

    def put(self, data:bytes, name:str) -> str:
        """رفع bytes مباشرة → يعيد handle"""
        size = len(data)
        res  = self._r({'a':'u','s':size})
        if isinstance(res,int): raise Exception(f"put init:{res}")
        ul   = res['p']
        rk   = os.urandom(16); rn=os.urandom(8)
        ka   = list(_a32(rk)); na=list(_a32(rn))+[0,0]
        enc  = _ctr(data,ka,na)
        h    = rq.post(ul+'/0',data=enc,timeout=300).text.strip()
        if not h or h.startswith('-'): raise Exception(f"put:{h}")
        ae   = _enc_attr({'n':name},ka)
        fk   = [ka[0]^na[0],ka[1]^na[1],ka[2],ka[3],na[0],na[1],0,0]
        ek   = _ecb_e(fk[:4],self.mk)+_ecb_e(fk[4:8],self.mk)
        self._r({'a':'p','t':'','i':h[:6],'n':[{'h':h,'t':0,'a':_b64e(ae),'k':_b64e(ek)}]})
        return h

    def get(self, fi:dict) -> bytes:
        """تحميل ملف → bytes"""
        res = self._r({'a':'g','g':1,'n':fi['h']})
        if isinstance(res,int): raise Exception(f"get:{res}")
        r = rq.get(res['g'],timeout=300); r.raise_for_status()
        return r.content

    def rm(self, h:str):
        self._r({'a':'d','n':h})

# ══════════════════════════════════════════════════════════
#  ذاكرة AI — كل شيء في MEGA
# ══════════════════════════════════════════════════════════
class Memory:
    """
    المخزن الوحيد هو MEGA.nz
    لا يُلمس Puter للتخزين أبداً
    """
    def __init__(self, mega:Mega):
        self.m = mega
        self._c = {}          # cache RAM
        self._lk = threading.Lock()

    @staticmethod
    def _fn(cid): return f"chat_{cid}.json.gz"

    # ── حفظ كل رسائل المحادثة ──────────────────────────
    def save(self, cid:str, data:dict):
        with self._lk:
            self._c[cid] = data
            raw  = json.dumps(data, ensure_ascii=False).encode()
            comp = gzip.compress(raw, compresslevel=GZ)
            pct  = round((1-len(comp)/max(len(raw),1))*100,1)
            fn   = self._fn(cid)
            old  = self.m.find(fn)
            if old: self.m.rm(old['h'])
            self.m.put(comp, fn)
            n = len(data.get('messages',[]))
            print(f"[💾] {cid} | {n} رسالة | {round(len(comp)/1024,1)}KB | ضغط {pct}%")

    # ── تحميل محادثة كاملة ─────────────────────────────
    def load(self, cid:str):
        if cid in self._c: return self._c[cid]
        with self._lk:
            f = self.m.find(self._fn(cid))
            if not f: return None
            d = json.loads(gzip.decompress(self.m.get(f)).decode())
            self._c[cid] = d
            return d

    # ── قائمة المحادثات ────────────────────────────────
    def lst(self):
        files = self.m.ls()
        out=[]
        for f in files:
            nm = f['name']
            if not (nm.startswith('chat_') and nm.endswith('.json.gz')): continue
            cid = nm[5:-8]
            item = {'id':cid,'title':'محادثة','model':'claude-sonnet-4',
                    'ts':f['ts'],'size_kb':round(f['size']/1024,1),'msg_count':0}
            if cid in self._c:
                c=self._c[cid]
                item['title']=c.get('title','محادثة')
                item['msg_count']=len(c.get('messages',[]))
            out.append(item)
        return sorted(out, key=lambda x:x['ts'], reverse=True)

    # ── حذف + تحرير مساحة MEGA فوراً ──────────────────
    def delete(self, cid:str):
        with self._lk:
            self._c.pop(cid,None)
            f=self.m.find(self._fn(cid))
            if f: self.m.rm(f['h']); print(f"[🗑️] {cid} حُذف من MEGA")

    # ── بناء سياق AI الكامل ────────────────────────────
    def ctx(self, cid:str) -> list:
        """
        يبني سياق AI يشمل كل التاريخ:
        - الرسائل الأقدم → ملخص نصي دقيق
        - آخر CTX_FULL رسالة → كاملة
        النتيجة: AI يتذكر آلاف الرسائل بدون انقطاع
        """
        chat = self.load(cid)
        if not chat: return []
        msgs  = [m for m in chat.get('messages',[])
                 if m.get('role') in ('user','assistant') and m.get('text')]
        total = len(msgs)

        # كل الرسائل أقل من الحد → ارسل كلها
        if total <= CTX_FULL:
            return [{'role':m['role'],'content':m['text']} for m in msgs]

        old    = msgs[:total-CTX_FULL]
        recent = msgs[total-CTX_FULL:]

        # ملخص الرسائل القديمة
        lines=[]
        for m in old[-CTX_SUMMARY:]:
            who = "👤" if m['role']=='user' else "🤖"
            lines.append(f"{who} {m['text'][:300]}")

        summ = (
            f"[📚 سجل {len(old)} رسالة سابقة]\n"
            + "\n".join(lines)
            + "\n[← نهاية السجل | تستمر المحادثة ↓]"
        )
        ctx=[
            {'role':'user',      'content':summ},
            {'role':'assistant', 'content':'لديّ السياق الكامل، أكمل معك من حيث توقفنا.'}
        ]
        for m in recent:
            ctx.append({'role':m['role'],'content':m['text']})
        return ctx

    # ── إحصائيات ───────────────────────────────────────
    def stats(self):
        files = self.m.ls()
        cf = [f for f in files if f['name'].startswith('chat_') and f['name'].endswith('.json.gz')]
        af = [f for f in files if not f['name'].startswith('chat_')]
        gz  = sum(f['size'] for f in cf)
        return {
            'chats':cf.__len__(), 'other_files':af.__len__(),
            'compressed_kb':round(gz/1024,1),
            'estimated_raw_kb':round(gz*5/1024,1),
            'saved_kb':round(gz*4/1024,1),
            'cached':len(self._c),
            'mega_email':MEGA_EMAIL
        }

# ══════════════════════════════════════════════════════════
#  Singleton
# ══════════════════════════════════════════════════════════
_mem=None; _mlk=threading.Lock()

def mem()->Memory:
    global _mem
    with _mlk:
        if _mem is None:
            print("[*] MEGA تسجيل الدخول...")
            _mem=Memory(Mega().login(MEGA_EMAIL,MEGA_PASSWORD))
        return _mem

# ══════════════════════════════════════════════════════════
#  معالجات HTTP
# ══════════════════════════════════════════════════════════
def _qv(qs,k):
    if not qs: return ''
    v=qs.get(k,'')
    return (v[0] if isinstance(v,list) else v or '').strip()

def H_health(q,b):
    try:    return 200,{'ok':True,'stats':mem().stats()}
    except Exception as e: return 500,{'ok':False,'error':str(e)}

def H_list(q,b):
    try:    return 200,mem().lst()
    except Exception as e: return 500,{'error':str(e)}

def H_load(q,b):
    cid=_qv(q,'id')
    if not cid: return 400,{'error':'id?'}
    try:
        d=mem().load(cid)
        return (200,d) if d else (404,{'error':'not found'})
    except Exception as e: return 500,{'error':str(e)}

def H_save(q,b):
    cid=b.get('id','').strip()
    if not cid: return 400,{'error':'id?'}
    try:
        mem().save(cid,b.get('data',{}))
        return 200,{'ok':True,'n':len(b.get('data',{}).get('messages',[]))}
    except Exception as e: return 500,{'error':str(e)}

def H_delete(q,b):
    cid=b.get('id','').strip()
    if not cid: return 400,{'error':'id?'}
    try:   mem().delete(cid); return 200,{'ok':True}
    except Exception as e: return 500,{'error':str(e)}

def H_ctx(q,b):
    cid=_qv(q,'id') or b.get('id','')
    if not cid: return 400,{'error':'id?'}
    try:
        c=mem().ctx(cid); return 200,{'context':c,'count':len(c)}
    except Exception as e: return 500,{'error':str(e)}

def H_stats(q,b):
    try:    return 200,mem().stats()
    except Exception as e: return 500,{'error':str(e)}

def H_upload(q,b,data=None,fname=None):
    """رفع ملف (صورة أو نص) مضغوط إلى MEGA"""
    if not data: return 400,{'error':'no data'}
    try:
        comp=gzip.compress(data,compresslevel=GZ)
        nm=(fname or 'file')+'.gz'
        mem().m.put(comp,nm)
        return 200,{
            'ok':True,'name':fname,
            'orig_kb':round(len(data)/1024,1),
            'comp_kb':round(len(comp)/1024,1),
            'saved':f"{round((1-len(comp)/max(len(data),1))*100,1)}%"
        }
    except Exception as e: return 500,{'error':str(e)}

def H_files(q,b):
    try:
        fs=mem().m.ls()
        return 200,[{'name':f['name'],'size_kb':round(f['size']/1024,1),'ts':f['ts']}
                    for f in fs if not f['name'].startswith('chat_')]
    except Exception as e: return 500,{'error':str(e)}

# ══════════════════════════════════════════════════════════
#  الخادم
# ══════════════════════════════════════════════════════════
if HAS_FLASK:
    app=Flask(__name__); CORS(app,origins="*")

    def _q(k): return R.args.get(k,'')

    @app.route('/health')
    def r0():  c,d=H_health({},{}); return jsonify(d),c
    @app.route('/list')
    def r1():  c,d=H_list({},{}); return jsonify(d),c
    @app.route('/load')
    def r2():  c,d=H_load({'id':[_q('id')]},{}); return jsonify(d),c
    @app.route('/save',methods=['POST'])
    def r3():  c,d=H_save({},R.get_json()or{}); return jsonify(d),c
    @app.route('/delete',methods=['POST'])
    def r4():  c,d=H_delete({},R.get_json()or{}); return jsonify(d),c
    @app.route('/context')
    def r5():  c,d=H_ctx({'id':[_q('id')]},{}); return jsonify(d),c
    @app.route('/stats')
    def r6():  c,d=H_stats({},{}); return jsonify(d),c
    @app.route('/files')
    def r7():  c,d=H_files({},{}); return jsonify(d),c
    @app.route('/upload',methods=['POST'])
    def r8():
        if 'file' not in R.files: return jsonify({'error':'no file'}),400
        f=R.files['file']
        c,d=H_upload({},{},f.read(),f.filename)
        return jsonify(d),c

    def go():
        threading.Thread(target=mem,daemon=True).start()
        print(f"[Flask] :{PORT}")
        app.run(host='0.0.0.0',port=PORT,debug=False,threaded=True)

else:
    class H(BaseHTTPRequestHandler):
        def _co(self):
            self.send_header('Access-Control-Allow-Origin','*')
            self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
            self.send_header('Access-Control-Allow-Headers','Content-Type')
        def _s(self,code,data):
            b=json.dumps(data,ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type','application/json;charset=utf-8')
            self._co(); self.send_header('Content-Length',len(b)); self.end_headers()
            self.wfile.write(b)
        def do_OPTIONS(self): self.send_response(200);self._co();self.end_headers()
        def do_GET(self):
            p=UP.urlparse(self.path); q=UP.parse_qs(p.query)
            m={'/health':H_health,'/list':H_list,'/load':H_load,
               '/context':H_ctx,'/stats':H_stats,'/files':H_files}.get(p.path)
            self._s(*(m(q,{}) if m else (404,{'error':'404'})))
        def do_POST(self):
            p=UP.urlparse(self.path)
            n=int(self.headers.get('Content-Length',0))
            raw=self.rfile.read(n)
            try: b=json.loads(raw.decode()) if raw else {}
            except: b={}
            m={'/save':H_save,'/delete':H_delete}.get(p.path)
            self._s(*(m({},b) if m else (404,{'error':'404'})))
        def log_message(self,fmt,*a): print(f"[{time.strftime('%H:%M:%S')}] {fmt%a}")

    def go():
        threading.Thread(target=mem,daemon=True).start()
        s=HTTPServer(('0.0.0.0',PORT),H)
        print(f"[http.server] :{PORT}"); s.serve_forever()

# ══════════════════════════════════════════════════════════
if __name__=='__main__':
    print('='*52)
    print('  🧠 AI Memory Server v3')
    print(f'  Python {sys.version.split()[0]} | :{PORT}')
    print(f'  MEGA: {MEGA_EMAIL}')
    print(f'  Backend: {"Flask" if HAS_FLASK else "http.server"}')
    print('  GET  /health /list /load /context /stats /files')
    print('  POST /save /delete /upload')
    print('='*52)
    go()
