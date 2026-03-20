# DAZN API

Flask API for DAZN combo checking with TLS fingerprinting, proxy support, and API key auth. All responses are **JSON in the body**. All endpoints (except `/admin`) **require an API key**.

---

## 1. Install and run

```bash
cd api
pip install -r requirements.txt
python app.py
```

Server: `http://0.0.0.0:5000`

---

## 2. Get an API key (required)

1. Open **https://your-domain.com/admin** (or **http://localhost:5000/admin**).
2. Login: **admin00** / **admin00**.
3. Create an API key (set validity: 1/7/30/90 days or custom).
4. Copy the key; use it for every request below.

Without a valid key, all API endpoints return **401** with JSON:  
`{"error": "Invalid or missing API key", "message": "..."}`

---

## 3. How to use the endpoints

- **GET or POST** – same URL; for POST put params in **JSON body** or form.
- **Auth** – send the API key as:
  - Header: `X-API-Key: YOUR_KEY`
  - Or in query/body: `api_key=YOUR_KEY`
- **Responses** – always **JSON in the response body**.

---

### **GET/POST /** (echo)

Echo back email, pass, proxy. Optional `format=hit` returns a built hit line (with extra fields in body).

**Params:** `email`, `pass`, `hit` (email:pass), `proxy`, `url` (optional), `format` (optional: `hit`/`line`).

**Example GET:**  
`/api_key=KEY&email=user@mail.com&pass=secret&proxy=ip:port:user:pass`

**Example POST body (JSON):**
```json
{
  "api_key": "YOUR_KEY",
  "email": "user@mail.com",
  "pass": "secret",
  "proxy": "ip:port:user:pass"
}
```

**Response:** `{"email": "...", "pass": "...", "hit": "...", "proxy": "...", "proxy_parsed": true}`

---

### **GET/POST /dazn** (DAZN check)

Check a DAZN combo (email:pass). Uses script (2).loli flow; supports all proxy formats.

**Params:** `hit` (email:pass) or `email` + `pass`, `proxy` (optional).

**Example GET:**  
`/dazn?api_key=KEY&hit=email%40mail.com%3Apassword&proxy=ip:port:user:pass`

**Example POST body (JSON):**
```json
{
  "api_key": "YOUR_KEY",
  "hit": "diezaragong@hotmail.com:Germesa1965",
  "proxy": "ultra.marsproxies.com:44443:user:pass"
}
```

**Response – success (200):**
```json
{
  "success": true,
  "line": "email:pass | Country = Spain | Status = Active | AutoRenew = false | Plan = ... | Time = 4.94s",
  "data": {
    "country": "Spain",
    "status": "Active",
    "auto_renew": "false",
    "plan": "PAC DAZN Silver Monthly ES",
    "currency": "EUR",
    "price": "18.99",
    "plan_period": "Month",
    "expiry_date": "2026-03-21"
  },
  "time": "4.94s"
}
```

**Response – fail (200):**
```json
{
  "success": false,
  "line": "email:pass | Error = InvalidPassword | Time = 1.02s",
  "error": "InvalidPassword",
  "response": "<full DAZN API response>",
  "time": "1.02s"
}
```

---

### **GET/POST /check** (DAZN check, key in body/header)

Same as `/dazn`; use when you prefer to send `api_key` in body or header.

**Params:** `api_key` (or `X-API-Key` header), `hit` or `email`+`pass`, `proxy`.

**Example POST body (JSON):**
```json
{
  "api_key": "YOUR_KEY",
  "hit": "email@example.com:password",
  "proxy": "ip:port:user:pass"
}
```

**Response:** Same JSON shape as `/dazn` (success/fail with `line`, `data`/`error`, `time`).

---

### **GET/POST /fetch** (TLS-fingerprinted GET)

Request any URL with browser TLS fingerprint; optional proxy.

**Params:** `url`, `proxy` (optional).

**Example POST body (JSON):**
```json
{
  "api_key": "YOUR_KEY",
  "url": "https://example.com",
  "proxy": "ip:port:user:pass"
}
```

**Response:** `{"status_code": 200, "text": "...", "ok": true}` or `{"error": "...", "ok": false}`

---

## 4. Proxy formats

All endpoints that take `proxy` accept:

| Format | Example |
|--------|--------|
| `ip:port` | `1.2.3.4:8080` |
| `ip:port:user:pass` | `1.2.3.4:8080:user:pass` |
| `user:pass@host:port` | `user:pass@1.2.3.4:8080` |
| `http://host:port` | `http://1.2.3.4:8080` |
| `socks5://user:pass@host:port` | `socks5://user:pass@1.2.3.4:1080` |

---

## 5. Admin panel

- **URL:** `/admin` or `/?admin` (redirects to `/admin`).
- **Login:** admin00 / admin00.
- **Actions:** Create API keys with validity (1/7/30/90 days or custom expiry). Keys are stored in `api_keys.json` in the same folder as `app.py`.
- No API key is needed to access `/admin`.

---

## 6. Files in this project

| File | Purpose |
|------|--------|
| **app.py** | Main API, admin, DAZN check, proxy parsing |
| **requirements.txt** | flask, curl_cffi |
| **README.md** | This file – how to use |
| **HOSTING.md** | How to host and deploy |

`api_keys.json` is created automatically when you create your first key in the admin panel.
