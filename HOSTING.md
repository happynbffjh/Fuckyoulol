# Hosting the DAZN API

## Files to upload (all in `api/` folder)

| File | Purpose |
|------|--------|
| **app.py** | Main API (Flask + DAZN check + proxy parsing) |
| **requirements.txt** | Dependencies |

That’s all. No database or extra config.

## 1. Install and run (any VPS / Linux)

```bash
# Upload app.py and requirements.txt to the server, then:

cd /path/to/api
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Runs on **http://0.0.0.0:5000** (all interfaces).

## 2. Production (recommended): Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

- `-w 4`: 4 workers  
- `-b 0.0.0.0:5000`: bind to port 5000 on all IPs  

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

## Proxy formats accepted

The `proxy` query param accepts:

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

IPv6 and colons in user/pass are supported for `ip:port:user:pass`.

---

## Endpoints

- **GET /** – Echo params (email, pass, proxy, optional `format=hit`). **GET /?admin** – redirect to admin panel.
- **GET /dazn?hit=email:pass&proxy=...** – DAZN check, returns hit line or error + full response + time.
- **GET /fetch?url=...&proxy=...** – TLS-fingerprinted GET to any URL.
- **GET /check?api_key=KEY&hit=email:pass&proxy=...** – DAZN check with **API key required**. Same response as /dazn (hit line or error + time). Use this for combo checking; pass the key from admin panel.
- **GET /admin** or **/?admin** – Admin login (user **admin00**, pass **admin00**). After login: create API keys with validity (1/7/30/90 days or custom). Keys are stored in `api_keys.json`. If any key exists, **/**, **/dazn**, **/fetch** require `X-API-Key` header or `api_key=` query.
