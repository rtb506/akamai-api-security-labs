# Master Quick Reference Guide - Days 1-3 Consolidated

**Purpose:** Rapid review of all core concepts before Day 4  
**Read Time:** 10-15 minutes  
**Last Updated:** February 2, 2026

---

## TABLE OF CONTENTS

1. [OWASP API Top 10 - Vulnerabilities Covered](#owasp-api-top-10)
2. [Attack Techniques & Exploitation](#attack-techniques)
3. [Akamai Detection Framework](#akamai-detection)
4. [Platform Architecture](#platform-architecture)
5. [Competitive Positioning](#competitive-positioning)
6. [Remediation Patterns](#remediation-patterns)
7. [Interview Response Scripts](#interview-scripts)

---

## OWASP API TOP 10

### API1:2023 - Broken Object Level Authorization (BOLA)

**What:** Horizontal privilege escalation - authenticated user accesses another user's resources

**Attack Example:**
```http
GET /api/orders/123 HTTP/1.1          ← My order
Authorization: Bearer <my_token>

GET /api/orders/124 HTTP/1.1          ← Someone else's order
Authorization: Bearer <my_token>
Response: 200 OK                      ← BOLA vulnerability!
```

**Root Cause:** Missing ownership validation
```python
# Vulnerable
def get_order(order_id):
    return Order.query.get(order_id)  # No check if user owns this

# Secure
def get_order(order_id):
    order = Order.query.get(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return order
```

**Detection Signals:**
- Sequential ID enumeration (1, 2, 3, 4, 5...)
- High cardinality (100+ unique IDs vs baseline 2-3)
- Bot-speed timing (<100ms between requests)
- Zero overlap between owned and accessed resources

**Akamai Detection:**
- Baseline: User accesses 2-3 order IDs/day
- Attack: User accesses 200 IDs in 10 minutes
- Risk Score: 95/100 (10,000% cardinality deviation)
- Response: Block IP, revoke JWT, alert SOC

**Business Impact:** Data breach, GDPR violation, customer trust loss

---

### API3:2023 - Broken Object Property Level Authorization (Mass Assignment)

**What:** Hidden parameter injection to manipulate restricted fields

**Attack Example:**
```http
PUT /api/user/profile HTTP/1.1
Authorization: Bearer <user_token>

{
  "email": "new@email.com",
  "role": "admin",              ← Hidden field injection
  "is_admin": true,             ← Hidden field injection
  "credits": 99999              ← Hidden field injection
}

Response: 200 OK
{
  "role": "admin",              ← Privilege escalation successful
  "credits": 99999              ← Balance manipulation
}
```

**Root Cause:** Mass assignment (server binds ALL input fields)
```python
# Vulnerable
user.update(**request.get_json())  # Accepts ANY field

# Secure (DTO validation)
class ProfileUpdateDTO(BaseModel):
    email: str  # ONLY allowed field

validated = ProfileUpdateDTO(**request.get_json())
```

**Detection Signals:**
- Request contains 5 fields (vs baseline 1)
- Restricted keywords: "role", "is_admin", "credits"
- Privilege mismatch (JWT role:user, setting role:admin)
- Schema violation (extra parameters not in spec)

**Akamai Detection:**
- Posture scan flags: "Accepts fields beyond spec"
- Runtime detects: Parameter count anomaly + restricted keywords
- Risk Score: 95/100
- Response: Block request, revoke token, create Jira ticket

**Business Impact:** Privilege escalation, financial fraud, compliance breach

---

### API4:2023 - Unrestricted Resource Consumption

**What:** Missing/weak rate limiting allows abuse

**Attack Vectors:**

**1. IP Spoofing**
```http
POST /api/validate-coupon
X-Forwarded-For: 192.168.1.100  ← Spoofed IP

Next request:
X-Forwarded-For: 192.168.1.101  ← Different IP, counter resets
```

**2. Race Condition**
- Send 50 simultaneous requests in <100ms
- Server's atomic counter fails (TOCTOU vulnerability)
- Result: 50 requests processed, only 20 counted

**Root Cause:** 
- Trusting X-Forwarded-For without validation
- Non-atomic rate limit counter

**Detection Signals:**
- Sequential IPs (192.168.1.1-50)
- Identical User-Agent across all IPs
- Timestamp clustering (<100ms intervals)
- Hosting provider IPs (AWS/GCP, not residential)

**Akamai Detection:**
- Risk Score: 100/100 (volume + IP pattern + timing)
- Response: Edge rate limit (5 req/min), CAPTCHA, block IPs

**Business Impact:** Financial fraud (coupon abuse), credential stuffing, DoS

**Remediation:**
```python
# Per-JWT rate limiting (not per-IP)
@limiter.limit("10/minute", key_func=get_jwt_identity)

# Atomic counter (Redis)
current = redis.incr(f"rate_limit:{user_id}")
if current > 10:
    return 429
```

---

### API5:2023 - Broken Function Level Authorization (BFLA)

**What:** Vertical privilege escalation - low role accessing admin functions

**Attack Example:**
```http
POST /api/admin/delete-user HTTP/1.1
Authorization: Bearer <regular_user_token>

Response: 200 OK
{
  "message": "User deleted successfully"  ← Regular user performed admin action
}
```

**Root Cause:** Missing role validation
```python
# Vulnerable
@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    User.query.filter_by(id=request.json['user_id']).delete()

# Secure
@app.route('/admin/delete-user', methods=['POST'])
@require_role('admin')  # Decorator enforces role check
def delete_user():
    User.query.filter_by(id=request.json['user_id']).delete()
```

**Detection Signals:**
- Regular user accessing `/admin/*` paths
- JWT role doesn't match endpoint sensitivity
- User calling DELETE/PUT on protected resources

**Akamai Detection:**
- Alert: "Low-privilege user accessing admin function"
- Risk Score: 88/100
- Response: Block request, flag account for review

**BOLA vs BFLA Key Difference:**
- **BOLA:** Horizontal (same role, wrong object) - `GET /orders/123` → `/orders/124`
- **BFLA:** Vertical (low role, admin function) - Regular user calls `DELETE /admin/users`

---

## ATTACK TECHNIQUES

### JWT Vulnerabilities

**JWT Structure:**
```
eyJhbGc... . eyJzdWI... . SflKxwRJ...
│           │            │
HEADER      PAYLOAD      SIGNATURE
(Base64)    (Base64)     (HMAC/RSA)
```

**Header Example:**
```json
{"alg": "HS256", "typ": "JWT"}
```

**Payload Example:**
```json
{
  "sub": "user_id_123",
  "role": "user",
  "exp": 1516242622
}
```

**Signature:**
```
HMAC-SHA256(header + payload, secret_key)
```

---

**Attack: Algorithm None**

**Vulnerability:** Server accepts `"alg": "none"` (no signature verification)

**Exploitation:**
1. Decode JWT: `jwt.io`
2. Modify header: `{"alg": "none", "typ": "JWT"}`
3. Modify payload: `{"sub": "admin", "role": "admin"}`
4. Remove signature: `eyJhbGc...eyJzdWI...` (no third part, keep dots)
5. Send tampered token

**Why WAF Fails:** Token is valid Base64, no malicious strings

**Akamai Detection:**
- Posture scan: "JWT accepts alg:none" (config vulnerability)
- Runtime: Token claim changes (role:user → role:admin)
- Risk Score: 92/100

**Fix:**
```python
ALLOWED_ALGS = ['RS256', 'ES256']
if header['alg'] not in ALLOWED_ALGS:
    raise InvalidTokenError
```

---

### BOLA Exploitation Flow

**Recon Phase:**
1. Create 2 user accounts (User A, User B)
2. User A: Upload resource, note resource_id (e.g., video_id: 123)
3. User B: Upload resource, note resource_id (e.g., video_id: 124)

**Exploitation Phase:**
1. User B: Access own resource `GET /api/videos/124` → 200 OK (baseline)
2. User B: Access User A's resource `GET /api/videos/123` → 200 OK (BOLA!)
3. Enumerate: Try IDs 1, 2, 3, 4, 5... (automated enumeration)

**Proof:**
- Screenshot: 3 different users' resources accessed via sequential IDs
- Evidence: User B's token accessing User A's data

---

### Rate Limit Bypass Techniques

**Technique 1: IP Spoofing (X-Forwarded-For)**

**Attack:**
```bash
# Script to rotate IPs
for i in {1..100}; do
  curl -X POST https://api.example.com/validate \
    -H "X-Forwarded-For: 192.168.1.$i" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code": "DISCOUNT50"}'
done
```

**Detection:** Sequential IP pattern, identical User-Agent

---

**Technique 2: Race Condition (Burp Intruder)**

**Setup:**
- Burp Intruder: Resource Pool → Max concurrent: 50
- Payload: Single coupon code
- Timing: All requests in <100ms window

**Result:** Bypass atomic counter check (TOCTOU vulnerability)

**Detection:** Timestamp clustering, bot-speed timing

---

### Mass Assignment Exploitation

**Parameter Discovery (Burp Intruder):**

**Baseline Request:**
```json
{"email": "test@test.com"}
```
Response: 450 bytes

**Fuzz Request:**
```json
{"email": "test@test.com", "§PARAM§": true}
```

**Payload List:**
```
role, is_admin, admin, credits, balance, subscription,
verified, is_staff, permissions, account_type
```

**Analysis:**
- Response: 512 bytes → Field accepted (length changed)
- Response: 450 bytes → Field ignored (baseline length)

**Vulnerable Parameters:** `role`, `is_admin`, `credits`

---

## AKAMAI DETECTION

### Behavioral Detection Framework

**Phase 1: Baseline Learning (7-14 days)**

**6 Core Metrics Tracked (Per-User, Per-Endpoint):**

1. **Request Rate:** Calls per minute/hour/day
   - Example: User accesses `/orders` 10x/day, 9AM-5PM

2. **Object ID Cardinality:** # of unique resource IDs accessed
   - Example: User accesses 2-3 order IDs per session

3. **Data Volume:** Bytes transferred (request + response)
   - Example: Typical response 2-5 KB

4. **Geolocation:** Countries, cities, ASNs
   - Example: 95% traffic from San Francisco, residential ISP

5. **Time Patterns:** Active hours, day-of-week
   - Example: Monday-Friday 9AM-6PM PST

6. **HTTP Method Distribution:** GET/POST/PUT/DELETE ratio
   - Example: 90% GET, 8% POST, 2% PUT/DELETE

---

**Phase 2: Anomaly Scoring**

**Risk Score Formula:**
```
Risk = (Cardinality × 40%) + (Rate × 25%) + (Volume × 20%) + 
       (Geo × 10%) + (Time × 5%)
```

**Example Calculation:**

**Baseline:**
- Request rate: 10/day
- Cardinality: 3 unique IDs/day
- Data volume: 20 KB/day

**Attack:**
- Request rate: 150/hour (1,500% increase)
- Cardinality: 200 unique IDs/hour (10,000% increase)
- Data volume: 2 MB/hour (10,000% increase)

**Risk Calculation:**
```
Cardinality: 10,000% → Score 100 × 40% = 40 points
Rate:         1,500% → Score  95 × 25% = 23.75 points
Volume:      10,000% → Score 100 × 20% = 20 points
Geo:              0% → Score   0 × 10% = 0 points
Time:             0% → Score   0 × 5%  = 0 points
                                Total: 83.75/100
                                Severity: HIGH
```

---

### True Positive vs False Positive

**High-Confidence TRUE POSITIVE Indicators:**

✅ **Sequential ID Enumeration**
- Pattern: 1, 2, 3, 4, 5, 6, 7...
- Rationale: Humans don't access resources in perfect numeric sequence
- Confidence: 99%

✅ **Bot-Speed Timing**
- Pattern: 100 requests in exactly 10 seconds (100ms intervals)
- Rationale: Human behavior is irregular, not metronomic
- Confidence: 95%

✅ **Credential Stuffing → BOLA Chain**
- Pattern: 50 failed logins → 1 success → immediate high cardinality
- Rationale: Compromised account being exploited
- Confidence: 98%

✅ **Zero Baseline Overlap**
- Owned resources: [1001, 1045, 1089]
- Accessed resources: [1, 2, 3, 4, 5...]
- No intersection → Unauthorized access
- Confidence: 90%

---

**Common FALSE POSITIVE Scenarios:**

⚠️ **Scheduled Batch Job**
- Pattern: High cardinality + volume spike at 2 AM daily
- Business context: Nightly ETL, analytics aggregation
- Resolution: Whitelist API key + time window

⚠️ **Product Feature Launch**
- Pattern: ALL users spike cardinality simultaneously
- Business context: New UI feature (e.g., "View All Orders" page)
- Resolution: Adjust baseline for affected endpoint

⚠️ **Partner Integration**
- Pattern: High rate from known API key
- Business context: Third-party analytics, payment processor
- Resolution: Whitelist partner's API key

⚠️ **User Travel**
- Pattern: Geolocation change, other metrics normal
- Business context: Business trip, VPN usage
- Resolution: Lower geo weight if other metrics baseline

---

### Detection Decision Tree
```
ALERT TRIGGERED
    ↓
Known scheduled job? (Check API key, time window)
├─ YES → Whitelist → FALSE POSITIVE
└─ NO → Continue
    ↓
Sequential ID pattern? (1,2,3,4,5...)
├─ YES → TRUE POSITIVE (BOLA attack)
└─ NO → Continue
    ↓
Bot-speed timing? (<100ms intervals)
├─ YES → TRUE POSITIVE (Automation)
└─ NO → Continue
    ↓
Business justification? (Admin doing admin work)
├─ YES → FALSE POSITIVE (Legitimate)
└─ NO → Continue
    ↓
VPN + other anomalies?
├─ YES → TRUE POSITIVE (Compromised account)
└─ NO → FALSE POSITIVE (Privacy tool)
```

---

## PLATFORM ARCHITECTURE

### Two-Layer Defense Model

**Layer 1: App & API Protector (AAP) - "The Shield"**

**Deployment:** Inline at Akamai's global edge network
- **Scale:** 350,000+ servers across 135 countries
- **Coverage:** 30% of global internet traffic

**Capabilities:**
- **DDoS Mitigation:** Multi-Tbps absorption capacity
- **WAF:** OWASP Top 10, custom rules, signature-based
- **Bot Management:** Behavioral fingerprinting, CAPTCHA
- **Rate Limiting:** Per-IP, per-user, per-endpoint
- **Adaptive Security Engine:** Auto-tuning WAF rules

**Strengths:** Real-time blocking, volumetric attack defense
**Limitations:** Cannot detect logic abuse (BOLA, BFLA)

---

**Layer 2: API Security (Noname) - "The Radar"**

**Deployment:** Out-of-band (sideband analysis)
- **Latency Impact:** Zero (traffic mirroring, not inline)
- **Analysis:** Behavioral ML, not signature-based

**The 4 Pillars:**

**1. Discovery**
- Shadow APIs (undocumented endpoints)
- Zombie APIs (deprecated but active)
- Data classification (PII/PCI/PHI auto-tagging)

**2. Posture Management**
- Configuration auditing (API gateways, cloud)
- Vulnerability scanning (weak auth, missing encryption)
- Code-to-runtime mapping (links to GitHub repo/line number)

**3. Runtime Protection**
- Behavioral baselining (7-14 days)
- Anomaly detection (BOLA, BFLA, exfiltration)
- Risk scoring (0-100)

**4. Active Testing (Shift-Left)**
- CI/CD integration (Jenkins, GitHub Actions)
- Pre-production fuzzing (150+ attack simulations)
- Enforcement: Can fail builds if critical vulns detected

---

### The Native Connector

**What It Is:** Traffic mirroring bridge from edge to analytics

**How It Works:**
```
User Request → App & API Protector (Edge)
                    ↓
               Process & Block (if malicious)
                    ↓
               Forward to Origin
                    ↓ (simultaneous)
         Mirror copy to API Security engine
                    ↓
         Behavioral analysis (no latency impact)
                    ↓
         Anomaly detected? → Signal edge to block
```

**Value Proposition:**

For **existing Akamai CDN customers:**
- **Deployment:** Flip a switch in Akamai Control Center
- **Infrastructure:** Zero (leverages existing edge)
- **Time-to-Value:** Hours to days (vs weeks-months)
- **Friction:** Lowest in market (no collectors, no SPAN ports)

For **non-CDN customers:**
- Still need traffic mirroring (AWS VPC, Azure VTAP, OCI VTAP)
- Or API gateway plugins (Kong, Apigee, Mulesoft)
- Deployment: Weeks (comparable to competitors)

**Key Differentiator:** Existing Akamai infrastructure = moat

---

## COMPETITIVE POSITIONING

### Framework: Lead with Workflow, Not Features

**Bad Approach:** "We're better than Traceable"
**Good Approach:** "Here's the workflow difference..."

---

### Akamai vs Traceable AI

**Traceable Strengths:**
- Distributed tracing (eBPF deep visibility)
- Code-level context (function calls, stack traces)
- Developer-focused UX

**Akamai Differentiation:**

**1. Workflow Gap**
- **Traceable:** Detects attacks, requires WAF for blocking
- **Akamai:** Detects AND blocks natively at edge
- **Customer Impact:** One vendor vs two, no integration complexity

**2. Deployment Model**
- **Traceable:** eBPF agents (in-application)
- **Akamai:** Agentless (traffic mirroring)
- **Customer Impact:** Zero app stability risk, no resource overhead

**3. Time-to-Value (CDN Customers)**
- **Traceable:** Weeks (new infrastructure deployment)
- **Akamai:** Hours (Native Connector flip-a-switch)
- **Customer Impact:** Faster ROI, lower deployment risk

**Positioning Statement:**
> "Traceable provides exceptional code-level visibility through eBPF tracing. The workflow difference is that they focus on detection and require WAF integration for enforcement, whereas our unified platform combines App & API Protector's native edge blocking with API Security's behavioral analytics. For existing Akamai CDN customers, our Native Connector eliminates deployment complexity entirely—it's literally a configuration toggle. Additionally, our agentless architecture means zero application stability risk, no in-app dependencies, and no performance overhead from agents."

**When to Acknowledge Traceable:**
- Customer values deep code context (debugging, root cause)
- Development team prefers eBPF observability
- **Counter:** "Traceable excels at code visibility. If you need that level of detail, they're strong. Our customers typically prioritize operational simplicity and unified enforcement, which is where our platform shines."

---

### Akamai vs Salt Security

**Salt Strengths:**
- Pioneer in API behavioral AI (mature ML models)
- Established product, longer track record
- Strong analytics engine

**Akamai Differentiation:**

**1. Enforcement Layer**
- **Salt:** Analytics-only, requires separate WAF
- **Akamai:** Native edge blocking (App & API Protector)
- **Customer Impact:** One platform vs two vendors, no finger-pointing

**2. Deployment Friction (CDN Customers)**
- **Salt:** Traffic collectors, SPAN ports, cloud mirroring
- **Akamai:** Native Connector (flip switch)
- **Customer Impact:** Hours vs weeks time-to-value

**3. Vendor Consolidation**
- **Salt + WAF:** Two contracts, two vendors, integration tax
- **Akamai:** Single platform, unified dashboard
- **Customer Impact:** Simplified procurement, faster incident response

**Positioning Statement:**
> "Salt Security pioneered behavioral AI for APIs—they have mature ML models and strong detection capabilities. The architectural difference is that Salt focuses on analytics and requires integration with your existing WAF for blocking. Akamai owns both the edge enforcement layer (App & API Protector with 350,000 servers globally) and the deep analytics layer (API Security). When we detect a BOLA attack, we signal our own edge to block in milliseconds—no third-party integration required. For existing Akamai CDN customers, our Native Connector eliminates the collector deployment entirely."

**When to Acknowledge Salt:**
- Customer values proven ML models
- Already has strong WAF (Cloudflare, Imperva)
- **Counter:** "Salt's AI is excellent. The question is whether you want to manage two vendors—Salt for detection, another for blocking—or consolidate into a single platform. Our customers value the operational efficiency of unified enforcement."

---

### Key Competitive Talking Points

**DO:**
✅ Frame as "workflow differences" or "architectural trade-offs"
✅ Acknowledge competitor strengths ("Traceable's eBPF visibility is excellent...")
✅ Emphasize customer outcomes (faster TTV, lower risk, operational simplicity)
✅ Use conditional language ("For CDN customers, Native Connector offers...")
✅ Provide use case context (not blanket superiority claims)

**DON'T:**
❌ Say "We're better than X"
❌ Trash competitors ("Salt is outdated," "Traceable doesn't work")
❌ Make unverifiable claims ("We're the best in the market")
❌ Oversimplify ("They can't block, we can")
❌ Ignore competitor strengths (shows lack of research)

---

## REMEDIATION PATTERNS

### Immediate (0-24 hours)

**BOLA:**
- Block attacker IP at edge
- Revoke compromised JWT tokens
- Virtual patch: `if (object.owner != user) → 403`

**BFLA:**
- Block access to admin endpoints
- Review user permissions, revoke elevated access
- Virtual patch: `if (user.role != 'admin') → 403`

**Mass Assignment:**
- Block attacker account
- Virtual patch: Reject requests with restricted fields
- WAF rule: `if (body contains "role|is_admin|credits") → 403`

**Rate Limit Bypass:**
- Block attacker IPs
- Adjust rate limit threshold
- Implement CAPTCHA challenge

**JWT alg:none:**
- Block affected tokens
- Emergency config change: Reject `alg:none`

---

### Short-Term (1-7 days)

**BOLA:**
```python
def get_resource(resource_id):
    resource = Resource.query.get(resource_id)
    if resource.user_id != current_user.id:
        abort(403)
    return resource
```

**BFLA:**
```python
@app.route('/admin/delete', methods=['POST'])
@require_role('admin')  # Decorator enforces role
def delete_user():
    # admin-only logic
```

**Mass Assignment:**
```python
from pydantic import BaseModel

class UpdateDTO(BaseModel):
    email: str  # Only allowed field

validated = UpdateDTO(**request.get_json())
```

**Rate Limit Bypass:**
```python
# Per-JWT rate limiting (not per-IP)
@limiter.limit("10/minute", key_func=get_jwt_identity)

# Reject untrusted X-Forwarded-For
if request.remote_addr not in TRUSTED_PROXIES:
    # Ignore header, use request.remote_addr
```

**JWT Security:**
```python
ALLOWED_ALGORITHMS = ['RS256', 'ES256']

if header['alg'] not in ALLOWED_ALGORITHMS:
    raise InvalidTokenError
```

---

### Long-Term (1-4 weeks)

**BOLA:**
- Replace sequential IDs with UUIDs (prevent enumeration)
- CI/CD integration: Automated BOLA testing in staging
- API audit: Check all endpoints for ownership validation

**BFLA:**
- Implement comprehensive RBAC (Role-Based Access Control)
- Least privilege principle: Users get minimum required permissions
- Automated policy enforcement tests

**Mass Assignment:**
- Separate input/output models (DTO pattern)
- Schema validation in API gateway
- Code review: Flag `.update(**data)` patterns

**Rate Limiting:**
- Atomic counters (Redis INCR)
- Distributed rate limiting (across all nodes)
- Adaptive rate limiting (ML-based, per-user baselines)

**JWT:**
- Secret rotation policy (quarterly)
- Token expiration enforcement (short-lived tokens)
- Automated config scanning (detect weak JWT settings)

---

## INTERVIEW SCRIPTS

### 60-Second Pitches

**BOLA Explanation (for VP/CTO):**
> "BOLA—Broken Object Level Authorization—is when an authenticated user manipulates object IDs to access resources they don't own. For example, changing `/api/orders/123` to `/api/orders/124` to view someone else's order. Traditional WAFs can't detect this because every request is syntactically valid—proper authentication, valid JSON, returns 200 OK. Akamai detects it through behavioral baselining: if a user normally accesses 2-3 order IDs per day but suddenly accesses 200 in 10 minutes, that's a 10,000% deviation in cardinality. Our ML engine flags this as a high-confidence attack with a risk score of 95/100 and signals the edge to block."

---

**Behavioral Detection (for AppSec Engineer):**
> "We baseline per-user, per-endpoint behavior over 7-14 days, tracking six core metrics: request rate, object ID cardinality, data volume, geolocation, time patterns, and HTTP method distribution. Each metric gets a weighted contribution to the risk score—cardinality is 40% because it's the strongest BOLA indicator. When a user's behavior deviates significantly, we calculate a weighted risk score from 0 to 100. Scores above 90 are high-confidence attacks. The key difference from WAFs is we're detecting intent, not syntax. We show you the math—the exact baseline, the exact deviation, the specific metrics that triggered the alert."

---

**Why Akamai vs Traceable (60 seconds):**
> "Traceable excels at distributed tracing with eBPF—they provide deep code-level visibility that's valuable for debugging and root cause analysis. The workflow difference is that Traceable focuses on detection and requires WAF integration for enforcement. Akamai owns both layers: App & API Protector blocks at 350,000 edge servers globally, and API Security analyzes behavior out-of-band. When we detect an attack, we block it natively without third-party integration. Additionally, Traceable often deploys eBPF agents inside applications, which introduces stability risk and resource overhead. Our agentless architecture uses traffic mirroring—zero application impact. For existing Akamai CDN customers, our Native Connector is a configuration toggle with hours-to-days time-to-value, versus weeks for new infrastructure deployment."

---

**Why Akamai vs Salt (60 seconds):**
> "Salt Security pioneered API behavioral AI—they have mature machine learning models and strong detection capabilities. The architectural difference is that Salt is analytics-only and requires integration with your existing WAF for blocking. Akamai provides both the edge enforcement layer and the deep analytics layer as a unified platform. When we detect a BOLA attack, we signal our own edge to block in milliseconds. Salt would require your WAF to process that signal, introducing integration complexity and potential finger-pointing during incidents. For existing Akamai CDN customers, our Native Connector eliminates the need for traffic collectors or SPAN port configuration—it's literally a switch you flip in the control center. That's hours-to-days time-to-value versus Salt's weeks-to-months deployment for collector infrastructure."

---

**Native Connector (30 seconds):**
> "For existing Akamai CDN customers, the Native Connector mirrors edge traffic directly to the API Security analytics engine. You enable it with a configuration toggle in the Akamai Control Center—no on-premise collectors, no SPAN ports, no cloud packet mirroring setup. Your time-to-value goes from weeks or months down to hours or days. It's the lowest-friction API security deployment in the market because we're leveraging infrastructure you're already paying for. Competitors require complex sensor deployments; we eliminate that entirely."

---

### Sev1 Escalation Script (2-minute framework)

**Scenario:** Customer reports production impact

**Phase 1: Acknowledge (10 sec)**
> "I see the alerts in the dashboard. I'm on it immediately. Let me triage this for you."

**Phase 2: Gather Data (60 sec)**
> "I'm pulling the logs now... I see high request rate from your mobile User-Agent—your app is generating 10 requests per second. Let me check the pattern... The baseline for this endpoint is 2 requests per second. Your app's retry logic is triggering our rate limit threshold."

**Phase 3: Root Cause (30 sec)**
> "Here's what's happening: Your mobile app is retrying failed authentication requests 10 times per second. Your baseline is 2 per second. That's a 400% deviation. The system interpreted this as a credential stuffing attack and rate-limited the app's User-Agent to protect your infrastructure."

**Phase 4: Mitigation (60 sec)**
> "Here's what I'm doing right now:
> 
> **Immediate** (next 2 minutes): I'm raising the rate limit for your specific mobile User-Agent from 10 to 20 requests per second. This should restore service immediately.
> 
> **Short-term** (next 24 hours): I'll create a custom exception rule for your app pattern so this doesn't recur.
> 
> **Long-term recommendation**: Implement exponential backoff in your mobile app's retry logic—retry after 1 second, then 2 seconds, then 4 seconds. This prevents future rate limit triggers and improves user experience."

**Phase 5: Follow-Up**
> "I'm monitoring traffic in real-time. I'll stay on this call until we confirm normalization. I'll send you a detailed RCA within 24 hours with exact timestamps, the specific alert that triggered, and long-term hardening recommendations. My goal is to ensure this doesn't happen again."

**Key Principles:**
- Use precise timestamps ("spike started 13:45 UTC")
- Quantify deviations (400% increase)
- Explain system logic ("interpreted as credential stuffing")
- Provide immediate + long-term solutions
- Never blame customer or product
- Commit to follow-up with timeline

---

### Handling Technical Questions

**Q: "How do you prevent false positives?"**

**A:** 
> "We use a 7-14 day learning period in monitor-only mode—no blocking, just observation—to establish accurate baselines. During this phase, you tune sensitivity thresholds based on your business logic. For example, if your analytics team exports large reports daily, we whitelist their API key and time window. After tuning, our false positive rate is typically under 2%. We also provide full transparency—when an alert fires, we show you the exact baseline, the exact deviation, and which specific metrics triggered it. You're not trusting a black box; you're verifying behavioral math. If you see a false positive, you can whitelist that specific pattern in real-time."

---

**Q: "What's the latency impact?"**

**A:**
> "App & API Protector at the edge adds less than 1 millisecond of latency for inline processing—DDoS mitigation, WAF checks, bot detection. API Security operates entirely out-of-band using traffic mirroring, so it has zero latency impact. We're not in the critical path for user requests. The original request flows normally to your origin while we analyze a mirrored copy asynchronously. When we detect an anomaly, we signal the edge to adjust policies, but that doesn't slow down legitimate traffic."

---

**Q: "How does this compare to our existing WAF?"**

**A:**
> "Your existing WAF is excellent at catching syntax-based attacks—SQL injection, XSS, command injection—anything with a malicious signature. Where WAFs struggle is logic-based attacks like BOLA, where every request is syntactically valid but semantically malicious. Akamai doesn't replace your WAF; we augment it with behavioral analysis. Think of your WAF as catching known threats using signatures, and Akamai as catching unknown threats using behavioral math. Together, you get defense-in-depth: signature-based protection for traditional exploits and behavioral protection for logic abuse."

---

**Q: "Can you explain the Native Connector in more detail?"**

**A:**
> "The Native Connector is a traffic mirroring integration between Akamai's edge network and the API Security analytics engine. Here's the technical flow: When a user request hits our edge, App & API Protector processes it—checking for DDoS, WAF rules, bot detection. Simultaneously, we mirror a copy of that traffic to the API Security engine for behavioral analysis. This happens asynchronously, so there's no latency impact. The analytics engine builds baselines, detects anomalies, and calculates risk scores. If it identifies an attack, it signals back to the edge to update enforcement policies—block an IP, rate-limit a user, trigger a CAPTCHA. The value for existing CDN customers is that this mirroring happens automatically without deploying any new infrastructure. Competitors require you to set up SPAN ports, deploy traffic collectors, or configure cloud packet mirroring. We eliminate that complexity entirely."

---

## FINAL EXAM (Self-Test)

**Answer these without looking at notes (60 seconds each):**

1. **"Explain BOLA vs BFLA to a non-technical CFO"**
2. **"Walk me through your BOLA detection methodology"**
3. **"Why should we choose Akamai over Traceable?"**
4. **"Customer says: Too many alerts. What do you do?"**
5. **"What's the Native Connector and why does it matter?"**

**Pass Criteria:** All 5 answered smoothly in <60 seconds each

**If you pass:** ✅ Ready for Day 4
**If you fail any:** Review the specific section above, drill again

---

## STUDY STRATEGY

**10 Minutes Before Interview:**
1. Read "OWASP API Top 10" section (2 min)
2. Review "Akamai Detection" decision tree (2 min)
3. Scan "Competitive Positioning" statements (3 min)
4. Practice one 60-second pitch out loud (2 min)
5. Deep breath, walk in confident (1 min)

**Night Before Interview:**
1. Review all flashcards once (15 min)
2. Practice Sev1 escalation script out loud (5 min)
3. Read "Interview Scripts" section (10 min)
4. Sleep well (memory consolidation happens during sleep)

---

*Master Reference Document: All core concepts from Days 1-3*  
*Total Coverage: 5 vulnerabilities, 8+ attack techniques, 2 platform layers, 2 competitors*  
*Read Time: 15 minutes for full document, 5 minutes for targeted review*  
*Last Updated: February 2, 2026*

---

## QUICK METRICS REFERENCE

**Cumulative Progress (Days 1-3):**
- ✅ Vulnerabilities Exploited: 5 (BOLA, BFLA, JWT alg:none, Rate Limit Bypass, Mass Assignment)
- ✅ Professional Writeups: 5 (with Akamai detection stories)
- ✅ Flashcards Created: 35 (spaced repetition ready)
- ✅ GitHub Commits: 10+ (portfolio live)
- ✅ Technical References: 4 documents (13,400+ words)
- ✅ Competitive Positioning: 2 frameworks (Traceable, Salt)
- ✅ Platform Knowledge: Native Connector, AAP vs API Security, 4 Pillars

**Confidence Level: 8.5/10** ⭐⭐⭐⭐

**Readiness for Day 4: ✅ STRONG**

---

