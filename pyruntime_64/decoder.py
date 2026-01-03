#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified ZTE config.bin decoder (modular)
- Menampilkan WHICH key/model/generated digunakan (lebih jelas)
- Logging verbose via --verbose
- Opsi tambahan: --show-key (tampilkan kunci lengkap) dan --log-file <path> (simpan log)
- Otomatis ekstrak DevAuthInfo (User & Pass) dan simpan ke file <outfile_basename>_devauth.txt
- Opsi cek login otomatis (--check-login) memakai daftar devauth; safe defaults: max_attempts=3, lockout_delay=60
Mode: normal | skip145 | trykeys | auto
"""
import sys
import argparse
import io
import os
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import csv
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# zcu library expected in environment
import zcu
from zcu import constants
from zcu.xcryptors import Xcryptor, CBCXcryptor

# Global flags (set in main)
VERBOSE = False
SHOW_KEY = False
LOG_FILE = None
_log_fp = None

# ---------- Utility / helpers ----------
def _open_logfile(path):
    global _log_fp
    try:
        _log_fp = open(path, "a", encoding="utf-8")
    except Exception as ex:
        print(f"[ERROR] Tidak dapat membuka log file '{path}': {ex}", file=sys.stderr)
        _log_fp = None

def _close_logfile():
    global _log_fp
    try:
        if _log_fp:
            _log_fp.flush()
            _log_fp.close()
    except Exception:
        pass
    finally:
        _log_fp = None

def _write_logfile(line):
    global _log_fp
    if _log_fp:
        try:
            _log_fp.write(line + "\n")
            _log_fp.flush()
        except Exception:
            pass

def error(msg):
    print(msg, file=sys.stderr)
    _write_logfile("[ERROR] " + str(msg))

def log(msg, /, level="INFO"):
    """Simple logging respecting global VERBOSE and writing to optional logfile."""
    line = f"[{level}] {msg}"
    if level == "ERROR":
        print(line, file=sys.stderr)
    else:
        if VERBOSE:
            print(line)
    _write_logfile(line)

def readable_key(x, maxlen=64):
    """Format key/model/iv for display; hide real content unless SHOW_KEY True."""
    if x is None:
        return "<None>"
    if isinstance(x, (bytes, bytearray)):
        if SHOW_KEY:
            try:
                s = x.decode('utf-8', errors='strict')
                return repr(s)
            except Exception:
                return "hex:" + x.hex()
        else:
            try:
                s = x.decode('utf-8', errors='ignore')
                if not s:
                    hx = x.hex()
                    return "hex:" + (hx[:16] + "..." if len(hx) > 16 else hx) + f" (len={len(x)})"
                return repr(s[:8] + "...") + f" (len={len(x)})"
            except Exception:
                hx = x.hex()
                return "hex:" + (hx[:16] + "...") + f" (len={len(x)})"
    else:
        s = str(x)
        if SHOW_KEY:
            return s
        if len(s) > 24:
            return s[:12] + "..." + s[-6:] + f" (len={len(s)})"
        return s

def read_signature_and_payload(infile):
    """
    membaca header (menggunakan zcu) kemudian signature dan payload_type.
    infile must be at beginning (or appropriate position).
    Returns (signature:str, payload_type:int, start_pos:int)
    """
    try:
        zcu.zte.read_header(infile)
    except Exception as ex:
        log(f"read_header failed or header missing: {ex}", "DEBUG")
    sig = zcu.zte.read_signature(infile)
    signature = ""
    if sig is not None:
        signature = sig.decode() if isinstance(sig, (bytes, bytearray)) else str(sig)
    payload_type = zcu.zte.read_payload_type(infile)
    start_pos = infile.tell()
    return signature, payload_type, start_pos

def try_decrypt_with_keylist(infile, start_pos, key_list, make_decryptor_fn):
    """
    Mencoba list key / model / generated keygens.
    make_decryptor_fn(key_or_model_or_tuple) -> decryptor instance ready to use
    For each candidate: seek(infile, start_pos); decrypt; check payload valid.
    Returns tuple (matched_desc, decrypted_stream) atau (None, None)
    """
    tried = 0
    for cand in key_list:
        tried += 1
        desc = readable_key(cand)
        log(f"Percobaan #{tried}: {desc}", "DEBUG")
        decryptor = None
        try:
            decryptor = make_decryptor_fn(cand)
        except Exception as ex:
            log(f"gagal buat decryptor untuk {desc}: {ex}", "DEBUG")
            continue
        infile.seek(start_pos)
        try:
            decrypted = decryptor.decrypt(infile)
        except Exception as ex:
            log(f"decrypt gagal untuk {desc}: {ex}", "DEBUG")
            continue
        try:
            if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                log(f"payload valid terdeteksi setelah decrypt menggunakan {desc}", "DEBUG")
                return (desc, decrypted)
            else:
                log(f"payload tidak valid setelah decrypt menggunakan {desc}", "DEBUG")
        except Exception as ex:
            log(f"cek payload gagal untuk {desc}: {ex}", "DEBUG")
            continue
    return (None, None)

def decompress_and_write(infile_stream, outfile):
    """
    decompress using zcu.compression.decompress and write result to outfile file-like
    """
    res, _ = zcu.compression.decompress(infile_stream)
    outfile.write(res.read())

# ---------- DevAuthInfo extractor ----------
def append_devauth_from_xml_path(xml_path, target_logpath):
    """
    Baca xml_path, ekstrak DevAuthInfo User/Pass, dan tulis (append) ke target_logpath.
    Hindari menambah entri yang sudah ada (dedupe).
    Returns number of entries newly written.
    """
    try:
        tree = ET.parse(xml_path)
    except Exception as ex:
        log(f"Gagal parse XML {xml_path}: {ex}", "ERROR")
        return 0

    root = tree.getroot()
    # load existing entries to set untuk dedupe
    existing = set()
    try:
        if os.path.exists(target_logpath):
            with open(target_logpath, "r", encoding="utf-8") as ef:
                for line in ef:
                    l = line.strip()
                    if l:
                        existing.add(l)
    except Exception:
        # ignore read issues, continue with empty existing
        pass

    written = 0
    try:
        os.makedirs(os.path.dirname(target_logpath), exist_ok=True)
    except Exception:
        pass

    try:
        with open(target_logpath, "a", encoding="utf-8") as f:
            for tbl in root.findall(".//Tbl"):
                if tbl.get('name') == 'DevAuthInfo':
                    for row in tbl.findall('Row'):
                        user = ''
                        passwd = ''
                        for dm in row.findall('DM'):
                            name = dm.get('name','')
                            v = dm.get('val','') or dm.get('defval','')
                            if name == 'User':
                                user = v
                            elif name == 'Pass':
                                passwd = v
                        line = f"User:{user} Pass:{passwd}"
                        if line not in existing:
                            f.write(line + "\n")
                            existing.add(line)
                            written += 1
    except Exception as ex:
        log(f"Gagal menulis DevAuthInfo ke {target_logpath}: {ex}", "ERROR")
    return written


def determine_devauth_logpath(outfile_path, explicit_logfile):
    """
    Jika explicit_logfile diset, kembalikan itu.
    Jika tidak, buat <outfile_basename>_devauth.txt di folder yang sama.
    Jika outfile_path not usable, fallback ke cwd/devauth_extracted.txt
    """
    if explicit_logfile:
        return explicit_logfile
    try:
        if outfile_path and outfile_path not in (None, '<stdout>'):
            outdir = os.path.dirname(os.path.abspath(outfile_path))
            base = os.path.splitext(os.path.basename(outfile_path))[0]
            return os.path.join(outdir, f"{base}_devauth.txt")
    except Exception:
        pass
    return os.path.join(os.getcwd(), "devauth_extracted.txt")

# ---------- Login checker helpers (full FiberHome + generic support) ----------
import re
import hashlib
from urllib.parse import urljoin

# read devauth file (unchanged)
def read_devauth_file(path):
    """Baca file hasil devauth (format: User:... Pass:...) -> list of (user,pass)."""
    creds = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                user = ""
                pw = ""
                parts = line.split()
                for p in parts:
                    if p.startswith("User:"):
                        user = p.split("User:", 1)[1]
                    elif p.startswith("Pass:"):
                        pw = p.split("Pass:", 1)[1]
                if not user and ":" in line and " " not in line:
                    a, b = line.split(":", 1)
                    user = a.strip()
                    pw = b.strip()
                if user or pw:
                    creds.append((user, pw))
    except Exception as ex:
        log(f"read_devauth_file error: {ex}", "ERROR")
    return creds


# Helpers: HTML detection for FiberHome / ZTE
def detect_fiberhome_by_html(html):
    """Rough detection if page looks like FiberHome / F6xx login page (Frm_Username etc)."""
    if not html:
        return False
    h = html.lower()
    return ("frm_username" in h and "_sessiontoken" in h) or ("f670" in h or "f670l" in h)


def zte_logged_in(html):
    """Tighter ZTE detection (dashboard markers)."""
    h = (html or "").lower()
    pos = [
        "home_category_wlan", "home_category_lan", "home_category_usb",
        "_laninfo", "_wlanstatus", "_systime", "navpanel", "zxhn",
        "var loginlevel", "logofflnk", 'id="loguser"', "_devcurrtime"
    ]
    neg = [
        "frmlogin", "login.asp", "goform/login", "login.html", "web_login",
        "password", "username", "logincheck"
    ]
    if any(n in h for n in neg):
        return False
    return any(p in h for p in pos)


# Token / hidden extraction helpers
def extract_csrf_token(html):
    if not html:
        return None
    m = re.search(r'name=["\']__csrf_token["\']\s+value=["\']([^"\']+)["\']', html, flags=re.I)
    if m:
        return m.group(1)
    m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', html, flags=re.I)
    if m:
        return m.group(1)
    m = re.search(r'name=["\'](?:csrf[_-]?token|token|__requestverificationtoken)["\']\s+value=["\']([^"\']+)["\']', html, flags=re.I)
    if m:
        return m.group(1)
    return None


def extract_hidden_tokens(html):
    tokens = {}
    if not html:
        return tokens
    for m in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', html, flags=re.I):
        tag = m.group(0)
        nm_m = re.search(r'name=["\']([^"\']+)["\']', tag, flags=re.I)
        val_m = re.search(r'value=["\']([^"\']*)["\']', tag, flags=re.I)
        if nm_m:
            name = nm_m.group(1)
            val = val_m.group(1) if val_m else ""
            tokens[name] = val
    for m in re.finditer(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\'][^>]*>', html, flags=re.I):
        name = m.group(1).lower()
        val = m.group(2)
        if "csrf" in name or "token" in name:
            tokens[name] = val
    return tokens


def extract_sid_from_headers(headers):
    """Try to extract SID cookie value from Set-Cookie header string(s)."""
    if not headers:
        return None
    sc = ""
    if isinstance(headers, dict):
        for k in ("set-cookie", "Set-Cookie"):
            if k in headers:
                sc = headers[k]
                break
        if not sc:
            sc = ";".join(v for v in headers.values() if v)
    else:
        sc = str(headers)
    m = re.search(r'\bSID=([A-Fa-f0-9]+)\b', sc)
    if m:
        return m.group(1)
    m2 = re.search(r'\b([A-Za-z0-9_\-]+)=([A-Fa-f0-9]{8,})\b', sc)
    if m2:
        return m2.group(2)
    return None


# ---------------- FiberHome (F670L / F6xx) login flow ----------------
def fh_get_login_token(session, base_url, timeout=5):
    """
    GET login token XML from FiberHome endpoint.
    Endpoint (observed): /?_type=loginData&_tag=login_token
    Returns token string or None.
    """
    try:
        url = base_url.rstrip("/") + "/?_type=loginData&_tag=login_token"
        r = session.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            return None
        txt = r.text or ""
        # token is childNodes[0].textContent in JS — fallback to <loginToken>...</loginToken>
        m = re.search(r'<loginToken>(.*?)</loginToken>', txt, flags=re.I | re.S)
        if m:
            return m.group(1)
        # some variants may embed token directly; fallback to first text content
        # try to extract any <.*>(token)</.*>
        m2 = re.search(r'>([0-9A-Za-z+/=]{8,})<', txt)
        if m2:
            return m2.group(1)
    except Exception:
        return None
    return None


def fh_hash_password(password, token):
    """SHA256(password + token) hex digest."""
    if password is None:
        password = ""
    if token is None:
        token = ""
    h = hashlib.sha256((password + token).encode("utf-8")).hexdigest()
    return h


def fh_login(session, base_url, user, pw, timeout=5):
    """
    Perform FiberHome login sequence:
     - GET token
     - compute SHA256(password + token)
     - POST to /?_type=loginData&_tag=login_entry
    Returns (ok_bool, status/int_or_None, note_str, response_text)
    """
    try:
        token = fh_get_login_token(session, base_url, timeout=timeout)
        # If token is missing, try to GET root to populate _sessionTOKEN hidden field then get token
        if not token:
            try:
                session.get(base_url, timeout=timeout)
            except Exception:
                pass
            token = fh_get_login_token(session, base_url, timeout=timeout)
        if not token:
            return False, None, "fh_no_token", None

        hashed = fh_hash_password(pw, token)
        post_data = {
            "action": "login",
            "Username": user,
            "Password": hashed,
            "_sessionTOKEN": ""  # router may ignore empty; session cookie used
        }
        url = base_url.rstrip("/") + "/?_type=loginData&_tag=login_entry"
        r = session.post(url, data=post_data, timeout=timeout, allow_redirects=True)
        body = r.text or ""
        # success if JSON contains sess_token or login_need_refresh false + no error
        if '"sess_token"' in body or '"login_need_refresh"' in body:
            # Parse for success indicators
            sid = extract_sid_from_headers(r.headers)
            return True, r.status_code, f"fh_login_ok:sid={sid}", body
        # explicit error
        if '"loginErrMsg"' in body or '"lockingTime"' in body:
            return False, r.status_code, "fh_login_failed", body
        # fallback: check for redirect to dashboard or presence of dashboard markers
        if zte_logged_in(body) or any(x in r.url.lower() for x in ("index", "home", "dashboard", "main", "userrpm")):
            sid = extract_sid_from_headers(r.headers)
            return True, r.status_code, f"fh_login_ok_fallback:sid={sid}", body
        return False, r.status_code, "fh_login_unknown", body
    except Exception as ex:
        return False, None, f"fh_error:{ex}", None


# ---------------- Generic/basic/form login helpers (session-aware) ----------------
def try_basic_auth(url, user, pw, timeout, session=None):
    sess = session or requests.Session()
    try:
        r = sess.get(url, auth=(user, pw), timeout=timeout, allow_redirects=True)
        body = (r.text or "").lower()
        # For FiberHome we use fh_login, but for devices that support HTTP Basic:
        if r.status_code == 401:
            return False, 401, "basic_401"
        # Else inspect HTML for dashboard clues (works for some vendors)
        if zte_logged_in(body):
            return True, r.status_code, "basic_html_login"
        return False, r.status_code, "basic_html_no_login"
    except Exception as ex:
        return False, None, f"basic_error:{ex}"


def try_form_auth(base_url, path, user, pw, timeout, session=None):
    sess = session or requests.Session()
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {"User-Agent": "zte-decoder-checker/1.0"}
    # GET page first
    try:
        r_get = sess.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        page_html = r_get.text or ""
    except Exception:
        page_html = ""
    hidden = extract_hidden_tokens(page_html)
    csrf = extract_csrf_token(page_html)
    field_candidates = [
        ("username", "password"), ("user", "pass"),
        ("UserName", "Password"), ("Username", "Password"),
        ("admin_username", "admin_password"), ("Frm_Username", "Frm_Password"),
    ]
    for uname_field, pwd_field in field_candidates:
        data = dict(hidden) if isinstance(hidden, dict) else {}
        data[uname_field] = user
        data[pwd_field] = pw
        if csrf:
            data["__csrf_token"] = csrf
            data["csrf_token"] = data.get("csrf_token", csrf)
            data["__RequestVerificationToken"] = data.get("__RequestVerificationToken", csrf)
        try:
            r = sess.post(url, data=data, timeout=timeout, headers=headers, allow_redirects=True)
        except Exception as ex:
            return False, None, f"form_post_error:{ex}"
        final_url = (r.url or "").lower()
        body = (r.text or "").lower()
        if zte_logged_in(body) or any(x in final_url for x in ("index", "home", "dashboard", "userrpm", "main")):
            sid = extract_sid_from_headers(r.headers)
            return True, r.status_code, f"form_success:{uname_field}:sid={sid}"
        if any(x in body for x in ("incorrect", "invalid", "wrong", "error", "failed")):
            continue
        if re.search(r'input[^>]+type=["\']password["\']', body, flags=re.I):
            continue
    return False, None, "form_all_attempts_failed"


# ---------------- single-credential check orchestration ----------------
def check_single_credential(base_url, user, pw, method, login_paths, timeout):
    """
    Create a session, auto-detect vendor type, and run vendor-appropriate login attempt.
    Returns dict: {user, pass, result, status, note, time_ms}
    """
    start = time.time()
    sess = requests.Session()
    # fetch root to detect
    try:
        r = sess.get(base_url, timeout=timeout, allow_redirects=True)
        root_html = r.text or ""
    except Exception:
        root_html = ""

    # Detect fiberhome first
    if detect_fiberhome_by_html(root_html) or "frm_username" in (root_html or "").lower():
        ok, status, note, resp_text = fh_login(sess, base_url, user, pw, timeout=timeout)
        return {"user": user, "pass": pw, "result": "OK" if ok else "FAIL", "status": status, "note": f"fiberhome:{note}", "time_ms": int((time.time()-start)*1000)}

    # Otherwise try generic/basic/form depending on method
    # Try basic first if requested
    if method in ("auto", "basic"):
        ok, status, note = try_basic_auth(base_url, user, pw, timeout, session=sess)
        if ok:
            return {"user": user, "pass": pw, "result": "OK", "status": status, "note": f"basic:{note}", "time_ms": int((time.time()-start)*1000)}
        if method == "basic":
            return {"user": user, "pass": pw, "result": "FAIL", "status": status, "note": f"basic:{note}", "time_ms": int((time.time()-start)*1000)}

    # form attempts
    last_note = "no_attempt"
    if method in ("auto", "form"):
        if not login_paths:
            login_paths = ["login", "goform/login", "login.cgi", "web_login.html", "login.html",
                           "cgi-bin/webproc", "goform/webLogin", "login.htm", "main/login", "userRpm/LoginRpm.htm"]
        for p in login_paths:
            ok, status, note = try_form_auth(base_url, p, user, pw, timeout, session=sess)
            last_note = note
            if ok:
                return {"user": user, "pass": pw, "result": "OK", "status": status, "note": f"form:{p}:{note}", "time_ms": int((time.time()-start)*1000)}
    return {"user": user, "pass": pw, "result": "FAIL", "status": None, "note": last_note, "time_ms": int((time.time()-start)*1000)}


# ---------------- top-level runner (uses check_single_credential) ----------------
def check_logins_from_devauth(devauth_path, base_url, out_csv_path=None, concurrency=1, csv_sep=";", compact=False,
                              delay=1.0, timeout=5, method="auto", login_paths=None, max_attempts=1, lockout_delay=60,
                              stop_on_success=True):
    """
    Read credentials from devauth_path and try login to base_url.
    Default: max_attempts=1 and stop_on_success=True to avoid lockout.
    """
    creds = read_devauth_file(devauth_path)
    results = []
    if not creds:
        log("No credentials found in devauth file.", "ERROR")
        return results

    if login_paths is None or not login_paths:
        login_paths = ["login", "goform/login", "login.cgi", "web_login.html", "login.html",
                       "cgi-bin/webproc", "goform/webLogin", "login.htm", "main/login", "userRpm/LoginRpm.htm"]

    # dedupe preserving order
    seen = set()
    uniq = []
    for c in creds:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    creds = uniq

    if concurrency > 1:
        log("Concurrency >1 tidak direkomendasikan; mengatur concurrency=1", "INFO")
        concurrency = 1

    if out_csv_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(out_csv_path)), exist_ok=True)
        except Exception:
            pass

    # enforce single attempt default
    max_attempts = 1 if max_attempts < 1 else max_attempts

    for (u, p) in creds:
        attempt = 0
        last_result = None
        while attempt < max_attempts:
            attempt += 1
            log(f"Trying credential {u}:{'***' if not SHOW_KEY else p} (attempt {attempt}/{max_attempts})", "DEBUG")
            r = check_single_credential(base_url, u, p, method, login_paths, timeout)
            last_result = r
            results.append(r)

            if out_csv_path:
                write_csv_results(out_csv_path, [r], write_header=False, sep=csv_sep, compact=compact)

            if r["result"] == "OK":
                log(f"Credential success: {u} (note={r['note']})", "INFO")
                if stop_on_success:
                    return results
                break
            else:
                log(f"Credential fail: {u} (note={r['note']})", "DEBUG")
                time.sleep(delay)

        if last_result and last_result["result"] != "OK":
            log(f"Credential {u} failed {max_attempts}x; waiting lockout_delay={lockout_delay}s", "INFO")
            time.sleep(lockout_delay)

    return results


def write_csv_results(path, rows, write_header=False, sep=";", compact=False):
    """
    Append rows (list of dict) to CSV path.
    - sep: delimiter string, default ';'
    - compact: if True, write compact rows: if user empty -> output start with pass (no empty field)
      compact row format: identifier;result;status;note;time_ms
      standard row format: user;pass;result;status;note;time_ms
    """
    # ensure dir exists
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    except Exception:
        pass

    # decide header presence
    mode = "a"
    need_header = write_header or (not os.path.exists(path))
    with open(path, mode, newline="", encoding="utf-8") as cf:
        if compact:
            # write simple rows without csv module header
            if need_header:
                cf.write("id;result;status;note;time_ms\n")
            for r in rows:
                user = r.get("user","") or ""
                pw = r.get("pass","") or ""
                if user:
                    ident = user
                else:
                    ident = pw
                line = f"{ident}{sep}{r.get('result','')}{sep}{r.get('status','')}{sep}{r.get('note','')}{sep}{r.get('time_ms','')}\n"
                cf.write(line)
        else:
            # standard CSV with header fields
            header = ["user","pass","result","status","note","time_ms"]
            writer = csv.DictWriter(cf, fieldnames=header, delimiter=sep)
            if need_header:
                writer.writeheader()
            for r in rows:
                writer.writerow({"user": r.get("user"), "pass": r.get("pass"), "result": r.get("result"), "status": r.get("status"), "note": r.get("note"), "time_ms": r.get("time_ms")})

# ---------- Mode handlers (core decoding logic) ----------
def mode_normal(infile_fileobj, args, outfile):
    infile = infile_fileobj
    signature, payload_type, start_pos = read_signature_and_payload(infile)
    if signature:
        print(f"Tanda tangan yang terdeteksi: {signature}")
    print(f"Tipe payload yang terdeteksi: {payload_type}")
    _write_logfile(f"[INFO] signature={signature} payload_type={payload_type}")

    params = SimpleNamespace()
    params.signature = args.signature if args.signature else signature
    if args.key: params.key = args.key
    if args.model: params.model = args.model
    if args.serial: params.serial = args.serial if (args.serial != 'NONE') else ''
    if args.mac: params.mac = args.mac if (args.mac != 'NONE') else ''
    if args.longpass: params.longPass = args.longpass if (args.longpass != 'NONE') else ''
    if args.key_prefix: params.key_prefix = args.key_prefix if (args.key_prefix != 'NONE') else ''
    if args.key_suffix: params.key_suffix = args.key_suffix if (args.key_suffix != 'NONE') else ''
    if args.iv_prefix: params.iv_prefix = args.iv_prefix if (args.iv_prefix != 'NONE') else ''
    if args.iv_suffix: params.iv_suffix = args.iv_suffix if (args.iv_suffix != 'NONE') else ''

    matched = None

    def key_bytes(x):
        if isinstance(x, bytes):
            return x
        if x is None:
            return b""
        return x

    if payload_type == 0 or payload_type == 1:
        print("Payload tipe 0/1 (tidak ada dekripsi khusus).")
        infile.seek(start_pos)
        decompress_and_write(infile, outfile)
        print("Berhasil didekode!")
        outfile_path = getattr(outfile, 'name', None)
        devauth_log = determine_devauth_logpath(outfile_path, LOG_FILE)
        entries = append_devauth_from_xml_path(outfile_path, devauth_log) if outfile_path else 0
        if entries:
            print(f"Ekstrak DevAuthInfo: {entries} entri -> {devauth_log}")
        return 0

    if payload_type == 2:
        keys = [args.key] if args.key else []
        if not keys and hasattr(params, 'signature') and params.signature:
            found_key = zcu.known_keys.find_key(params.signature)
            if found_key is not None and found_key not in keys:
                keys.append(found_key)
        if args.try_all_known_keys:
            for k in zcu.known_keys.get_all_keys():
                if k not in keys:
                    keys.append(k)

        if not keys:
            error("Tidak ada --key yang ditentukan atau ditemukan melalui tanda tangan, dan tidak mencoba semua kunci yang diketahui!")
            return 1

        def make_xcryptor(k):
            return Xcryptor(key_bytes(k))

        desc, decrypted = try_decrypt_with_keylist(infile, start_pos, keys, make_xcryptor)
        if desc is None:
            error(f"Gagal mendekripsi payload tipe 2, mencoba {len(keys)} kunci!")
            return 1
        matched = f"kunci: {desc}"
        infile = decrypted

    elif payload_type == 3:
        models = [args.model] if args.model else []
        if args.try_all_known_keys:
            for m in zcu.known_keys.get_all_models():
                if m not in models:
                    models.append(m)
        if not models:
            error("Argumen model tidak ditentukan untuk dekripsi tipe 3 dan tidak mencoba semua kunci yang diketahui!")
            return 1

        def make_cbc(m):
            return CBCXcryptor(m)

        desc, decrypted = try_decrypt_with_keylist(infile, start_pos, models, make_cbc)
        if desc is None:
            error(f"Gagal mendekripsi payload tipe 3, mencoba {len(models)} nama model!")
            return 1
        matched = f"model: {desc}"
        infile = decrypted

    elif payload_type == 4:
        generated = []
        if args.try_all_known_keys:
            generated = zcu.known_keys.run_all_keygens(params)
        else:
            res = zcu.known_keys.run_keygen(params)
            if res is not None:
                generated.append(res)

        if not generated:
            errStr = "Tidak ada pembangkit kunci tipe 4 yang cocok dengan tanda tangan dan parameter yang disediakan/deteksi! "
            if not hasattr(params, 'serial'):
                errStr += "Mungkin menambahkan --try-all-known-keys atau --serial akan membantu."
            error(errStr)
            return 1

        tried = 0
        for gen in generated:
            tried += 1
            key, iv, source = gen
            log(f"Percobaan generated #{tried}: source={source} key={readable_key(key)} iv={readable_key(iv)}", "DEBUG")
            infile.seek(start_pos)
            decryptor = CBCXcryptor()
            try:
                decryptor.set_key(key, iv)
            except Exception as ex:
                log(f"set_key gagal untuk generated {source}: {ex}", "DEBUG")
                continue
            try:
                decrypted = decryptor.decrypt(infile)
            except Exception as ex:
                log(f"decrypt gagal untuk generated {source}: {ex}", "DEBUG")
                continue
            if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                matched = f"generated: {source} key={readable_key(key)} iv={readable_key(iv)}"
                infile = decrypted
                break

        if matched is None:
            error(f"Gagal mendekripsi payload tipe 4, mencoba {len(generated)} kunci yang dihasilkan!")
            return 1

    elif payload_type == 5:
        if args.key is None or args.iv_prefix is None:
            error("Kunci atau Awalan IV tidak boleh kosong untuk payload tipe 5")
            return 1
        print(f"Awalan Kunci: {args.key_prefix}, Awalan Iv: {args.iv_prefix}")
        decryptor = CBCXcryptor()
        decryptor.set_key(args.key_prefix, args.iv_prefix)
        infile.seek(start_pos)
        try:
            decrypted = decryptor.decrypt(infile)
        except Exception:
            error("Gagal mendekripsi payload tipe 5.")
            return 1
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is None:
            error("Payload tipe 5 yang didekripsi tidak valid.")
            return 1
        matched = True
        infile = decrypted

    elif payload_type == 6:
        if len(args.iv_prefix) == 0:
            iv_prefix = "ZTE%FN$GponNJ025"
        else:
            iv_prefix = args.iv_prefix
        if args.serial is None or args.mac is None:
            error("Serial dan Mac tidak boleh kosong untuk payload tipe 6")
            return 1
        mac = args.mac
        if not isinstance(mac, bytes):
            mac = mac.strip().replace(':', '')
            if len(mac) != 12:
                raise ValueError("String Alamat MAC Memiliki Panjang Yang Salah")
            mac = bytes.fromhex(mac)
        if len(mac) != 6:
            raise ValueError("Alamat Mac Memiliki Panjang Yang Salah")
        mac = "%02x%02x%02x%02x%02x%02x" % (
            mac[5], mac[4], mac[3], mac[2], mac[1], mac[0])

        print("Panjang Nomor Seri: %s" % len(args.serial))
        if len(args.serial) == 12:
            kp1 = args.serial[4:]
        elif len(args.serial) == 19:
            kp1 = args.serial[11:]
        else:
            raise ValueError("Nomor Seri Salah")
        kp = kp1 + mac
        print(f"Mac: {mac} Awalan Kunci: {kp}, Awalan Iv: {iv_prefix}")
        decryptor = CBCXcryptor()
        decryptor.set_key(kp, iv_prefix)
        infile.seek(start_pos)
        try:
            decrypted = decryptor.decrypt(infile)
        except Exception:
            error("Gagal mendekripsi payload tipe 6.")
            return 1
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is None:
            error("Payload tipe 6 yang didekripsi tidak valid.")
            return 1
        matched = f"Serial: '{args.serial}' key={readable_key(kp)} iv={readable_key(iv_prefix)}"
        infile = decrypted

    else:
        error(f"Tipe payload tidak dikenal {payload_type}!")
        return 1

    # final decompress & write
    decompress_and_write(infile, outfile)

    # setelah berhasil menulis outfile, coba ekstrak DevAuthInfo User/Pass
    outfile_path = getattr(outfile, 'name', None)
    devauth_log = determine_devauth_logpath(outfile_path, LOG_FILE)
    entries = 0
    try:
        if outfile_path:
            entries = append_devauth_from_xml_path(outfile_path, devauth_log)
    except Exception as ex:
        log(f"Gagal ekstrak DevAuthInfo setelah decode: {ex}", "ERROR")

    if entries:
        print(f"Berhasil didekode menggunakan {matched if matched else 'unknown'}!")
        print(f"Ekstrak DevAuthInfo: {entries} entri -> {devauth_log}")
        _write_logfile(f"[INFO] devauth_extracted={entries} path={devauth_log}")
    else:
        print("Berhasil didekode!")
        _write_logfile("[INFO] success_without_devauth")

    # jika user meminta check-login, jalankan checker sekarang
    if getattr(args, "check_login", None):
        base_url = args.check_login
        # chosen devauth file to use (the one we just wrote or explicit LOG_FILE)
        devauth_file = devauth_log
        if not os.path.exists(devauth_file):
            log(f"Devauth file tidak ditemukan: {devauth_file}", "ERROR")
        else:
            # determine csv output path
            if getattr(args, "check_output", None):
                out_csv = args.check_output
            else:
                try:
                    base = os.path.splitext(os.path.basename(outfile_path))[0] if outfile_path else "check_results"
                    out_csv = os.path.join(os.path.dirname(outfile_path) if outfile_path else os.getcwd(), f"{base}_login_results.csv")
                except Exception:
                    out_csv = os.path.join(os.getcwd(), "login_results.csv")
            # ensure concurrency safety: force to 1 to honor router limit
            concurrency = max(1, int(getattr(args, "concurrency", 1)))
            if concurrency > 1:
                log("Concurrency >1 disarankan TIDAK digunakan untuk router dengan limit percobaan. Mengatur concurrency=1 untuk safety.", "INFO")
                concurrency = 1
            results = check_logins_from_devauth(
                devauth_file,
                base_url,
                out_csv_path=out_csv,
                concurrency=concurrency,
                csv_sep=";",
                compact=False,
                delay=getattr(args, "delay", 1.0),
                timeout=getattr(args, "timeout", 5.0),
                method=getattr(args, "auth_method", "auto"),
                login_paths=getattr(args, "login_path", None),
                max_attempts=getattr(args, "max_attempts", 3),
                lockout_delay=getattr(args, "lockout_delay", 60)
            )
            print(f"Selesai cek login. Hasil ditulis ke {out_csv} (total dicoba: {len(results)})")

    return 0

def mode_skip145(infile_fileobj, args, outfile):
    infile_fileobj.seek(145)
    remaining = infile_fileobj.read()
    infile = io.BytesIO(remaining)
    log("Menggunakan mode skip145: membaca file mulai offset 145", "DEBUG")
    return mode_normal(infile, args, outfile)

def mode_trykeys(infile_fileobj, args, outfile):
    infile_fileobj.seek(0)
    data = infile_fileobj.read()
    infile_buf = io.BytesIO(data)
    log("Trykeys: percobaan normal (default) dimulai", "DEBUG")
    try:
        rc = mode_normal(infile_buf, args, outfile)
        if rc == 0:
            return 0
    except Exception as ex:
        log(f"mode_normal exception: {ex}", "DEBUG")

    infile_buf = io.BytesIO(data)
    log("Trykeys: percobaan skip145 dimulai", "DEBUG")
    try:
        rc = mode_skip145(infile_buf, args, outfile)
        if rc == 0:
            return 0
    except Exception as ex:
        log(f"mode_skip145 exception: {ex}", "DEBUG")

    log("Trykeys: percobaan exhaustif dengan try_all_known_keys=True", "DEBUG")
    args_backup = SimpleNamespace(**vars(args))
    args.try_all_known_keys = True

    infile_buf = io.BytesIO(data)
    try:
        rc = mode_normal(infile_buf, args, outfile)
        if rc == 0:
            args.try_all_known_keys = args_backup.try_all_known_keys
            return 0
    except Exception as ex:
        log(f"exhaustive normal exception: {ex}", "DEBUG")

    infile_buf = io.BytesIO(data)
    try:
        rc = mode_skip145(infile_buf, args, outfile)
        if rc == 0:
            args.try_all_known_keys = args_backup.try_all_known_keys
            return 0
    except Exception as ex:
        log(f"exhaustive skip145 exception: {ex}", "DEBUG")

    for k, v in vars(args_backup).items():
        setattr(args, k, v)

    error("Semua metode percobaan gagal. Coba berikan parameter tambahan seperti --key, --serial, --mac, atau --try-all-known-keys.")
    return 1

# ---------- CLI main ----------
def main():
    global VERBOSE, SHOW_KEY, LOG_FILE
    parser = argparse.ArgumentParser(description="Unified Dekoder config.bin Router ZTE (with verbose, which-key info, devauth extraction, and login checker)", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", type=argparse.FileType("rb"), help="File konfigurasi terenkripsi contoh: config.bin")
    parser.add_argument("outfile", type=argparse.FileType("wb"), help="File output contoh: config.xml")
    parser.add_argument("--key", type=lambda x: x.encode(), default=b"", help="Kunci untuk dekripsi AES")
    parser.add_argument('--file', type=str, default='', help="file")
    parser.add_argument('--model', type=str, default='', help="Model perangkat untuk derivasi kunci Tipe-3")
    parser.add_argument("--serial", type=str, default="", help="Nomor seri untuk pembangkitan kunci Tipe-4")
    parser.add_argument("--mac", type=str, default="", help="Alamat MAC untuk pembangkitan kunci berbasis TagParams")
    parser.add_argument("--longpass", type=str, default="", help="Kata sandi panjang dari TagParams (entri 4100) untuk pembangkitan kunci")
    parser.add_argument("--signature", type=str, default="", help="Penyediaan/penggantian tanda tangan")
    parser.add_argument("--try-all-known-keys", action="store_true", help="Coba dekripsi dengan semua kunci dan generator yang diketahui")
    parser.add_argument("--key-prefix", type=str, default='', help="Mengganti awalan kunci")
    parser.add_argument("--iv-prefix", type=str, default='', help="Mengganti awalan IV")
    parser.add_argument("--key-suffix", type=str, default='', help="Mengganti akhiran kunci")
    parser.add_argument("--iv-suffix", type=str, default='', help="Mengganti akhiran IV")
    parser.add_argument("--mode", type=str, default="auto", choices=["normal", "skip145", "trykeys", "auto"], help="Mode decoder: normal | skip145 | trykeys | auto (default)")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan log lebih detail (debug/info).")
    parser.add_argument("--show-key", action="store_true", help="Tampilkan kunci / IV lengkap yang dipakai (BERHATI-HATI: sensitif).")
    parser.add_argument("--log-file", type=str, default="", help="Simpan log ke file (path). Jika diset, juga akan digunakan untuk simpan DevAuthInfo; jika tidak, DevAuthInfo ditulis ke <outfile_basename>_devauth.txt.")
    # login checker args
    parser.add_argument("--check-login", type=str, default="", help="URL target untuk cek login, mis: http://192.168.1.1")
    parser.add_argument("--check-output", type=str, default="", help="File CSV hasil cek login (default: <outfile_basename>_login_results.csv)")
    parser.add_argument("--concurrency", type=int, default=1, help="Jumlah thread paralel untuk cek login (default 1; >1 tidak direkomendasikan)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay (detik) antara percobaan")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout HTTP (detik)")
    parser.add_argument("--auth-method", type=str, default="auto", choices=["auto","form","basic"], help="Metode auth yang dicoba")
    parser.add_argument("--login-path", type=str, action="append", help="Path login tambahan (boleh dipanggil beberapa kali).")
    parser.add_argument("--max-attempts", type=int, default=3, help="Max attempts per credential (default 3)")
    parser.add_argument("--lockout-delay", type=int, default=60, help="Delay (detik) setelah max_attempts gagal untuk menghindari lockout (default 60s)")
    parser.add_argument("--csv-sep", type=str, default=";", help="Delimiter CSV hasil cek login (default ';')")
    parser.add_argument("--compact-results", action="store_true", help="Tulis hasil cek login dalam format compact (id;result;status;note;time_ms) — jika user kosong, id=pass")
    args = parser.parse_args()

    VERBOSE = args.verbose
    SHOW_KEY = args.show_key
    LOG_FILE = args.log_file if args.log_file else None

    if LOG_FILE:
        _open_logfile(LOG_FILE)
        _write_logfile(f"[INFO] Program started. LOG_FILE={LOG_FILE} VERBOSE={VERBOSE} SHOW_KEY={SHOW_KEY}")

    infile_f = args.infile
    outfile_f = args.outfile

    try:
        if args.mode == "normal":
            rc = mode_normal(infile_f, args, outfile_f)
        elif args.mode == "skip145":
            rc = mode_skip145(infile_f, args, outfile_f)
        elif args.mode == "trykeys":
            rc = mode_trykeys(infile_f, args, outfile_f)
        else:  # auto
            try:
                rc = mode_normal(infile_f, args, outfile_f)
                if rc == 0:
                    return 0
            except Exception as ex:
                log(f"auto: normal failed: {ex}", "DEBUG")
            try:
                infile_f.seek(0)
                rc = mode_skip145(infile_f, args, outfile_f)
                if rc == 0:
                    return 0
            except Exception as ex:
                log(f"auto: skip145 failed: {ex}", "DEBUG")
            rc = mode_trykeys(infile_f, args, outfile_f)
        return rc
    finally:
        try:
            infile_f.close()
        except Exception:
            pass
        try:
            outfile_f.close()
        except Exception:
            pass
        _close_logfile()

if __name__ == "__main__":
    sys.exit(main())
