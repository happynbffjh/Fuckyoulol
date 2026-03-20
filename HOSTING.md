# Hosting the DAZN API

## Files to upload (all in `api/` folder)

| File | Purpose |
|------|--------|
| **app.py** | Main API (Flask + DAZN check + admin + API keys + proxy parsing) |
| **requirements.txt** | Dependencies (flask, curl_cffi) |
| **README.md** | How to use (endpoints, examples, proxy formats) |
| **HOSTING.md** | This file – deploy and run |

No database. `api_keys.json` is created on the server when the first API key is created in the admin panel.

---

## 1. Install and run (VPS / Linux)

```bash
cd /path/to/api
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Runs on **http://0.0.0.0:5000**.

---

## 2. Production: Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

- `-w 4`: 4 workers  
- `-b 0.0.0.0:5000`: listen on all interfaces, port 5000  

---

## 3. Optional: systemd service

Create `/etc/systemd/system/dazn-api.service`:

```ini
[Unit]
Description=DAZN API
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/api
ExecStart=/path/to/api/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dazn-api
sudo systemctl start dazn-api
```

---

## 4. Quick “how to use” after hosting

1. **Create API key**  
   Open `https://your-domain.com/admin` → login **admin00** / **admin00** → Create API key (set validity).

2. **Call any endpoint**  
   - All endpoints (except `/admin`) need a valid **API key**: header `X-API-Key: YOUR_KEY` or param `api_key=YOUR_KEY` in query or body.
   - **GET or POST**; for POST send params in **JSON body** (or form).
   - All responses are **JSON in the response body**.

3. **DAZN check (recommended: /check or /dazn)**  
   - **GET:** `https://your-domain.com/check?api_key=KEY&hit=email%3Apass&proxy=...`  
   - **POST:** Body `{"api_key":"KEY","hit":"email:pass","proxy":"ip:port:user:pass"}`  
   - Response: `{"success": true|false, "line": "...", "data": {...} or "error": "...", "response": "...", "time": "X.XXs"}`

4. **Other endpoints**  
   - **/** – Echo params (JSON).  
   - **/fetch** – TLS-fingerprinted GET to `url` (JSON).

See **README.md** for full endpoint list, examples, and proxy formats.

---

## 5. Proxy formats accepted

| Format | Example |
|--------|--------|
| `ip:port` | `1.2.3.4:8080` |
| `ip:port:user:pass` | `1.2.3.4:8080:myuser:mypass` |
| `user:pass@host:port` | `myuser:mypass@1.2.3.4:8080` |
| `http://host:port` | `http://1.2.3.4:8080` |
| `http://user:pass@host:port` | `http://user:pass@1.2.3.4:8080` |
| `https://...` | `https://user:pass@proxy.com:443` |
| `socks4://host:port` | `socks4://1.2.3.4:1080` |
| `socks5://user:pass@host:port` | `socks5://user:pass@1.2.3.4:1080` |

---

## 6. Security

- Set **FLASK_SECRET_KEY** in the environment in production (for session cookies).
- Change **admin00** / **admin00** in `app.py` (or load from env) before going live.
- Keep `api_keys.json` out of public access (it lives next to `app.py` on the server).
