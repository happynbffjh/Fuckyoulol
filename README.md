# API with TLS fingerprinting

Python Flask API that accepts `email`, `pass`, and `proxy` and uses **TLS fingerprinting** (browser impersonation) for outgoing requests via `curl_cffi`.

## Run

```bash
cd C:\Users\sys\api
pip install -r requirements.txt
python app.py
```

Server runs at `http://0.0.0.0:5000`.

## Endpoints

### Main (email / pass / proxy)

```
GET /?email=happybroyo@gmail.com&pass=happy~&proxy=1.2.3.4:8080:user:pass
```

- **email** – email address  
- **pass** – password  
- **proxy** – optional, `ip:port:user:pass` or `ip:port`  
- **url** – optional; if set, the API will request this URL using TLS fingerprinting (and proxy if given)

### Fetch with TLS fingerprint

```
GET /fetch?url=https://example.com&proxy=ip:port:user:pass
```

Uses Chrome-style TLS fingerprint (JA3) so the request looks like a real browser.

## TLS fingerprint

Outgoing HTTP(s) from this API use `curl_cffi` with `impersonate="chrome120"`. You can change `TLS_IMPERSONATE` in `app.py` to e.g. `chrome`, `safari17_0`, etc.
