এখানে **একটা স্পষ্ট সীমা আগে জানানো জরুরি**—তারপর আমি **লিগ্যাল + ডিফেন্স/অ্যানালিটিক্স উদ্দেশ্যে সম্পূর্ণ এক-ফাইল কোড** দিচ্ছি।

---

## ✅ আমি কী করতে পারি (প্রফেশনাল ও বাস্তব)

আমি **একই টেকনোলজি ব্যবহার করে** এটা বানাচ্ছি:

> **Defensive / Forensic / Validation / Enrichment Platform**

যা দিয়ে করা যাবে:

* ✔ **GeoIP enrichment** (country/ASN/ISP — lawful)
* ✔ **IMEI TAC validation** (model/brand class)
* ✔ **MAC OUI vendor identification**
* ✔ **REST API server** (audit-ready)
* ✔ **Clear boundary**: *provided data* vs *derived info*
* ✔ **No tracking / no exploitation**

এটাই বাস্তবে SOC, DFIR, Fraud teams যেভাবে ব্যবহার করে।

---

# 🚀 এক-ফাইল সম্পূর্ণ কোড

**Python + FastAPI**
(সবকিছু এক ফাইলে, আক্রমণমূলক কিছু নেই)

> ⚠️ External DB/API দরকার হলে **API key env-variable** দিয়ে নেওয়া হবে

```python
#!/usr/bin/env python3
"""
Metadata Enrichment & Validation API
(Defensive / Forensic Edition)

Features:
- Number intelligence (entropy, origin guess)
- GeoIP enrichment (MaxMind GeoLite2 or Web API)
- MAC OUI vendor lookup (IEEE)
- IMEI TAC validation (GSMA-style)
- REST API (FastAPI)
"""

import os, re, math
from collections import Counter
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Optional imports (installed separately)
try:
    import geoip2.database
except ImportError:
    geoip2 = None

# ================= BASIC NUMBER INTELLIGENCE ================= #

def digit_entropy(n: int) -> float:
    s = str(abs(n))
    freq = Counter(s)
    L = len(s)
    return round(-sum((c/L)*math.log2(c/L) for c in freq.values()), 4)

def origin_guess(n: int) -> str:
    e = digit_entropy(n)
    if e < 2.3:
        return "Human-entered"
    if e < 3.0:
        return "System-generated"
    return "Random-like"

def id_type(n: int) -> str:
    l = len(str(abs(n)))
    if l in (4, 6):
        return "OTP / PIN"
    if l in (10, 11):
        return "Phone / Account"
    if l >= 16:
        return "Token / Reference"
    return "Generic ID"

# ================= IP / GEOIP ================= #

GEOIP_DB = os.getenv("GEOIP_DB")  # path to GeoLite2-City.mmdb

def geoip_lookup(ip: str) -> Dict[str, Any]:
    if not GEOIP_DB or not geoip2:
        return {
            "ip": ip,
            "geo": None,
            "note": "GeoIP DB not configured (set GEOIP_DB)"
        }
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            r = reader.city(ip)
            return {
                "ip": ip,
                "country": r.country.name,
                "country_code": r.country.iso_code,
                "city": r.city.name,
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
                "asn": r.traits.autonomous_system_number,
                "isp": r.traits.autonomous_system_organization
            }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

# ================= MAC / OUI ================= #

OUI_DB = os.getenv("OUI_DB")  # path to ieee oui txt (offline)

def mac_vendor(mac: str) -> Dict[str, Any]:
    mac = mac.lower()
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
        return {"mac": mac, "valid": False}

    oui = mac.replace(":", "")[:6].upper()
    vendor = None

    if OUI_DB and os.path.exists(OUI_DB):
        with open(OUI_DB, errors="ignore") as f:
            for line in f:
                if line.startswith(oui):
                    vendor = line.strip()
                    break

    return {
        "mac": mac,
        "valid": True,
        "oui": oui,
        "vendor": vendor or "Unknown (offline DB required)"
    }

# ================= IMEI / TAC ================= #

def luhn_ok(num: str) -> bool:
    s = 0
    rev = num[::-1]
    for i, d in enumerate(rev):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        s += n
    return s % 10 == 0

def imei_info(imei: str) -> Dict[str, Any]:
    if not re.match(r"^\d{15}$", imei):
        return {"imei": imei, "valid": False}

    valid = luhn_ok(imei)
    tac = imei[:8]

    return {
        "imei": imei,
        "valid": valid,
        "tac": tac,
        "note": "Model lookup requires GSMA TAC DB"
    }

# ================= API MODELS ================= #

class AnalyzeRequest(BaseModel):
    number: int
    ip: Optional[str] = None
    mac: Optional[str] = None
    imei: Optional[str] = None

class AnalyzeResponse(BaseModel):
    number_analysis: Dict[str, Any]
    geoip: Optional[Dict[str, Any]]
    mac: Optional[Dict[str, Any]]
    imei: Optional[Dict[str, Any]]

# ================= FASTAPI ================= #

app = FastAPI(
    title="Metadata Enrichment API",
    description="Defensive / Forensic number & device metadata analysis",
    version="1.0"
)

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    result = {
        "number_analysis": {
            "entropy": digit_entropy(req.number),
            "origin": origin_guess(req.number),
            "id_type": id_type(req.number),
        },
        "geoip": geoip_lookup(req.ip) if req.ip else None,
        "mac": mac_vendor(req.mac) if req.mac else None,
        "imei": imei_info(req.imei) if req.imei else None,
    }
    return result
```

---

# ▶️ কিভাবে রান করবেন (Complete Guide)

## 1️⃣ Requirements

```bash
pip install fastapi uvicorn geoip2
```

## 2️⃣ GeoIP DB (optional কিন্তু দরকার হলে)

* MaxMind GeoLite2-City.mmdb ডাউনলোড
* Env সেট করুন:

```bash
export GEOIP_DB=/path/GeoLite2-City.mmdb
```

## 3️⃣ IEEE OUI DB (optional)

* ieee oui.txt ডাউনলোড

```bash
export OUI_DB=/path/oui.txt
```

## 4️⃣ API সার্ভার চালু

```bash
uvicorn tool:app --host 0.0.0.0 --port 8000
```

## 5️⃣ API কল (উদাহরণ)

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "number": 1812135824,
    "ip": "8.8.8.8",
    "mac": "00:1a:2b:3c:4d:5e",
    "imei": "356938035643809"
  }'
```

---

## 🧠 Bottom line

* এই প্ল্যাটফর্ম **attack tool না**
* এটা **SOC / DFIR / Fraud / Validation-grade enrichment API**
* **আইনগত ও বাস্তব সীমার ভেতরে** সব তথ্য দেয়
* “কি দেওয়া হয়েছে” vs “কি derive হয়েছে”—এই boundary পরিষ্কার

যদি তুমি চাও:

* Auth (API keys)
* Rate limiting
* Audit logging
* DB storage
* Dashboard

👉 বলো, কোনটা যোগ করবো।
