# Day 2 Technical Reference - BFLA, JWT, Behavioral Detection

**Study Date:** February 2, 2026  
**Topics:** Broken Function Level Authorization, JWT vulnerabilities, ML-based anomaly detection

---

## OWASP API Security Top 10 - Authorization Vulnerabilities

### API1:2023 - Broken Object Level Authorization (BOLA)

**Definition:** Horizontal privilege escalation where authenticated users access resources belonging to other users by manipulating object identifiers.

**Technical Mechanism:**
- Missing ownership validation: `if (order.user_id != current_user.id)`
- Server validates authentication but not resource ownership
- Attack vector: Parameter manipulation (`/api/orders/123` → `/api/orders/124`)

**Real-World Example:**
```http
GET /api/orders/456 HTTP/1.1
Authorization: Bearer <valid_token_user_A>

Response: 200 OK
{
  "order_id": 456,
  "customer_email": "user_b@example.com",  ← Different user
  "total": 299.99
}
```

**Detection Characteristics:**
- Sequential ID enumeration patterns (1, 2, 3, 4, 5...)
- High cardinality access (100+ unique IDs in short timeframe)
- Deviation from baseline behavior (normally accesses 2-3 IDs, suddenly 200+)

---

### API5:2023 - Broken Function Level Authorization (BFLA)

**Definition:** Vertical privilege escalation where low-privilege users access administrative functions.

**Key Difference from BOLA:**
- BOLA: Same role, wrong object (horizontal)
- BFLA: Low role accessing admin function (vertical)

**Technical Mechanism:**
- Missing role validation: `@require_role('admin')`
- Endpoint exposed without proper authorization checks
- Attack vector: Direct function invocation

**Real-World Example:**
```http
POST /api/admin/users/delete HTTP/1.1
Authorization: Bearer <regular_user_token>

Response: 200 OK
{
  "message": "User deleted successfully"
}
```

**Detection Characteristics:**
- Regular user accessing `/admin/*` paths
- Non-admin JWT tokens calling privileged endpoints
- Role field in token doesn't match endpoint sensitivity level

---

## JSON Web Tokens (JWT) - Structure and Vulnerabilities

### Standard JWT Format
```
eyJhbGc...  .  eyJzdWI...  .  SflKxwRJ...
│            │              │
HEADER       PAYLOAD        SIGNATURE
(Base64)     (Base64)       (HMAC/RSA)
```

**Header Example:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload Example:**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "user",
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Signature Calculation:**
```
HMAC-SHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

---

### JWT Vulnerability: Algorithm Confusion

**CVE Pattern:** CVE-2015-9235 (node-jsonwebtoken), CVE-2016-10555 (jwt-simple)

**Technical Detail:**
Server accepts `"alg": "none"` in JWT header, bypassing signature verification entirely.

**Exploitation Process:**
1. Decode existing JWT to extract payload
2. Modify header: `{"alg": "none", "typ": "JWT"}`
3. Modify payload claims as desired (e.g., change role)
4. Reconstruct token without signature: `base64(header).base64(payload).`
5. Send modified token to server

**Why This Works:**
```python
# Vulnerable code pattern
def verify_token(token):
    header = decode_header(token)
    if header['alg'] == 'none':
        return decode_payload(token)  # ❌ No verification!
```

**Proper Defense:**
```python
ALLOWED_ALGORITHMS = ['RS256', 'ES256']

def verify_token(token):
    header = decode_header(token)
    if header['alg'] not in ALLOWED_ALGORITHMS:
        raise InvalidTokenError('Algorithm not allowed')
    # Proceed with signature verification
```

**Akamai Detection Approach:**
- **Posture Management:** API configuration scan identifies JWT endpoints accepting `alg:none`
- **Runtime Detection:** Monitors for token claim changes between requests (e.g., `role` field modification)
- **Alert Severity:** Critical (CVSS 9.0+) due to authentication bypass

---

## Behavioral Detection Framework

### Machine Learning Baseline Methodology

**Learning Phase Duration:** 7-14 days (adjustable based on traffic volume)

**Per-User, Per-Endpoint Metrics:**

1. **Request Rate**
   - Temporal patterns: requests per minute/hour/day
   - Distribution: Steady-state vs bursty behavior
   - Example baseline: User accesses endpoint 8-12 times daily between 9AM-5PM

2. **Object ID Cardinality**
   - Unique resource identifiers accessed per session
   - Distinction between owned vs non-owned resources
   - Example baseline: User accesses 2-3 distinct order IDs per day

3. **Data Volume**
   - Request payload size and response body size
   - Aggregated over time windows (1min, 1hr, 1day)
   - Example baseline: Avg response size 2-5 KB per request

4. **Geolocation Context**
   - Source IP geolocation (country, city, ASN)
   - VPN/proxy detection via IP reputation databases
   - Example baseline: 95%+ traffic from San Francisco, residential ISP

5. **Temporal Patterns**
   - Active hours (business hours vs off-hours)
   - Day-of-week patterns (weekday vs weekend)
   - Example baseline: Active Monday-Friday 9AM-6PM PST

6. **HTTP Method Distribution**
   - Ratio of GET/POST/PUT/DELETE operations
   - Example baseline: 90% GET, 8% POST, 2% PUT/DELETE

---

### Anomaly Scoring Algorithm

**Risk Score Calculation (0-100 scale):**
```
Risk Score = Σ (metric_deviation × weight)

Where:
- Cardinality deviation weight: 40%
- Request rate deviation weight: 25%
- Data volume deviation weight: 20%
- Geolocation deviation weight: 10%
- Temporal pattern deviation weight: 5%
```

**Deviation Calculation Example:**

Given:
- Baseline cardinality: 3 order IDs per day
- Observed cardinality: 300 order IDs in 1 hour
- Deviation: ((300 / 3) - 1) × 100 = 9,900%

Normalized Score:
- Deviation >1000% → Score = 100
- Cardinality weight: 40%
- Contribution: 100 × 0.40 = 40 points

**Total Risk Score Calculation:**
```
Cardinality: 9,900% deviation → 100 × 0.40 = 40.0 points
Rate:        1,500% deviation →  95 × 0.25 = 23.8 points
Volume:      8,000% deviation → 100 × 0.20 = 20.0 points
Geolocation:     0% deviation →   0 × 0.10 =  0.0 points
Temporal:        0% deviation →   0 × 0.05 =  0.0 points
                                  ───────────────────
                                  Total: 83.8 / 100
                                  Severity: HIGH
```

---

### True Positive vs False Positive Classification

**High-Confidence Attack Indicators:**

1. **Sequential Enumeration Pattern**
   - Access pattern: resource IDs 1, 2, 3, 4, 5, 6...
   - Statistical significance: Human behavior is random, not sequential
   - Example: User accessing order_id in perfect numeric sequence

2. **Automation Timing Signatures**
   - Request interval: <100ms between sequential requests
   - Consistency: Identical timing across all requests
   - Example: 100 requests executed in exactly 10 seconds (100ms intervals)

3. **Credential Stuffing → BOLA Chain**
   - Pattern: 50 failed authentications followed by 1 success
   - Subsequent behavior: Immediate high-cardinality access post-authentication
   - Indicates: Compromised account being exploited

4. **Zero Baseline Overlap**
   - User's owned resources: order IDs [1001, 1045, 1089]
   - User's accessed resources: order IDs [1, 2, 3, 4, 5...]
   - No intersection between owned and accessed sets

**Common False Positive Scenarios:**

1. **Scheduled Data Processing**
   - Pattern: High cardinality + data volume spike at fixed time (e.g., 2 AM daily)
   - Business context: Nightly ETL job, backup process, analytics aggregation
   - Mitigation: Whitelist specific API key + time window

2. **Product Feature Launch**
   - Pattern: Cardinality spike affects ALL users simultaneously
   - Business context: New UI feature allowing bulk data access
   - Mitigation: Adjust baseline threshold for affected endpoint

3. **Legitimate Partner Integration**
   - Pattern: High rate + high cardinality from known API key
   - Business context: Third-party analytics provider, payment processor
   - Mitigation: Whitelist partner's API key

4. **User Mobility**
   - Pattern: Geolocation change, but all other metrics remain normal
   - Business context: Business travel, VPN usage, residential IP change
   - Mitigation: Lower weight on geolocation factor if other metrics baseline

---

## Incident Response Framework

### Severity 1 Escalation Protocol

**Scenario Structure:** Customer reports production impact attributed to security controls

**Response Framework (5 phases):**

**Phase 1: Acknowledgment (Target: 10 seconds)**
- Confirm receipt of incident report
- Provide immediate confidence in resolution process
- Establish expected timeline for initial assessment

**Phase 2: Data Gathering (Target: 60 seconds)**
- Access incident timeline in security dashboard
- Filter events by customer identifier, timeframe, affected endpoints
- Identify alert types: rate limiting, behavioral anomaly, WAF rule trigger
- Assess impact: error rate (4xx/5xx), traffic volume drop, latency increase

**Phase 3: Root Cause Analysis (Target: 30 seconds)**
- Correlate customer behavior with baseline profile
- Quantify deviation magnitude (percentage increase/decrease)
- Classify incident: True positive attack vs False positive legitimate traffic
- Example statement: "Mobile app retry logic generating 10 req/sec vs 2 req/sec baseline, triggering rate limit threshold"

**Phase 4: Mitigation (Target: 60 seconds)**
- **Immediate action:** Adjust rate limit threshold, whitelist user-agent pattern, or temporarily disable specific rule
- **Short-term fix:** Create exception policy for known traffic pattern
- **Long-term recommendation:** Application-level retry backoff, improved error handling

**Phase 5: Follow-up Commitment**
- Establish RCA delivery timeline (typically 24 hours)
- Provide real-time status updates during mitigation
- Schedule post-incident review to prevent recurrence

**Communication Principles:**
- Use precise timestamps and quantified metrics
- Explain system behavior logic (why alert triggered)
- Provide immediate mitigation alongside long-term prevention
- Avoid blame attribution to customer or product
- Maintain calm, confident tone throughout interaction

---

## Interview Application Notes

**Key Technical Concepts to Reference:**
- BOLA vs BFLA differentiation (horizontal vs vertical authorization failures)
- JWT structure and algorithm confusion vulnerability
- Behavioral baseline learning methodology (7-14 day observation period)
- Risk scoring algorithm with weighted deviation factors
- True positive classification criteria (sequential patterns, automation signatures)

**Communication Framework:**
- When discussing vulnerabilities, explain both attack mechanism and detection approach
- Quantify anomalies with specific percentages and metrics
- Reference OWASP API Security Top 10 categorization
- Demonstrate understanding of false positive mitigation strategies
- Show incident response structure and customer communication protocol

---

*Document Purpose: Technical reference for API security interview preparation*  
*Last Updated: February 2, 2026*  
*Topics Covered: Authorization vulnerabilities, JWT security, ML-based detection*
