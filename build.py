"""把 maction-system.html 加密成需要密码才能打开的 index.html。

用法：
    python build.py            # 运行后输入密码
    MACTION_PW=xxx python build.py

只把生成的 index.html 上传到 GitHub；maction-system.html（明文）已在 .gitignore 里。
"""
import base64
import getpass
import json
import os
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 310_000
ROOT = Path(__file__).parent
SRC = ROOT / "maction-system.html"
OUT = ROOT / "index.html"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    password = os.environ.get("MACTION_PW") or getpass.getpass("页面密码: ")
    src = SRC.read_text(encoding="utf-8")

    # 登录页也要显示 logo 和 favicon，从源文件里取出来
    logo = re.search(r'class="brand-logo" src="([^"]+)"', src).group(1)
    fav = re.search(r'<link rel="icon" type="image/png" href="([^"]+)"', src).group(1)

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(
        password.encode("utf-8")
    )
    ct = AESGCM(key).encrypt(iv, src.encode("utf-8"), None)
    payload = json.dumps({"s": b64(salt), "i": b64(iv), "c": b64(ct), "n": ITERATIONS})

    page = TEMPLATE.replace("__FAV__", fav).replace("__LOGO__", logo).replace("__PAYLOAD__", payload)
    OUT.write_text(page, encoding="utf-8")
    print(f"已生成 {OUT.name}（{OUT.stat().st_size // 1024} KB）")


TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>Maction 企业运营系统</title>
<link rel="icon" type="image/png" href="__FAV__">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;700;900&display=swap">
<style>
:root{--red:#E60012;--gold:#FFD000;--ink:#1A1414;--muted:#6B5E5E;--line:#F0DCDC}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:#fff;color:var(--ink);font-family:"Noto Sans SC",-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;display:grid;place-items:center;padding:24px 16px}
.box{width:100%;max-width:380px;border:1px solid var(--line);border-top:5px solid var(--red);border-radius:14px;padding:32px 28px;box-shadow:0 8px 32px rgba(230,0,18,.08)}
.box img{display:block;width:100%;max-width:240px;height:auto;margin:0 auto 10px}
.tag{display:table;margin:0 auto 26px;font-size:12px;font-weight:700;letter-spacing:.2em;color:var(--gold);background:var(--red);padding:2px 10px;border-radius:4px}
label{display:block;font-size:14px;font-weight:700;margin-bottom:6px}
input{width:100%;font:inherit;font-size:16px;padding:11px 14px;border:1.5px solid var(--line);border-radius:9px}
input:focus{outline:none;border-color:var(--red)}
button{width:100%;margin-top:14px;font:inherit;font-size:16px;font-weight:900;padding:12px;border:0;border-radius:9px;background:var(--red);color:var(--gold);cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.err{min-height:1.5em;margin:10px 0 0;font-size:13px;color:var(--red)}
.foot{margin-top:18px;font-size:12px;color:var(--muted);text-align:center}
</style>
</head>
<body>
<form class="box" id="f">
  <img src="__LOGO__" alt="MACTION 连锁 | 绩效 | 资本">
  <span class="tag">企业运营系统</span>
  <label for="pw">请输入密码</label>
  <input id="pw" type="password" autocomplete="current-password" required autofocus>
  <button id="go" type="submit">登入</button>
  <p class="err" id="err" role="alert"></p>
  <p class="foot">仅限 Maction 内部同事使用</p>
</form>
<script>
const P=__PAYLOAD__;
const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function unlock(pw){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:u(P.s),iterations:P.n,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
  const html=new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:u(P.i)},key,u(P.c)));
  try{sessionStorage.setItem("maction-pw",pw)}catch(e){}
  document.open();
  document.write('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><style>body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style></head><body>'+html+'</body></html>');
  document.close();
}
const f=document.getElementById("f"),go=document.getElementById("go"),err=document.getElementById("err");
f.addEventListener("submit",async e=>{
  e.preventDefault();go.disabled=true;go.textContent="验证中…";err.textContent="";
  try{await unlock(document.getElementById("pw").value)}
  catch(x){go.disabled=false;go.textContent="登入";err.textContent="密码不正确，请重新输入。"}
});
let saved=null;try{saved=sessionStorage.getItem("maction-pw")}catch(e){}
if(saved)unlock(saved).catch(()=>{try{sessionStorage.removeItem("maction-pw")}catch(e){}});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
