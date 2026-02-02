# Akamai API Security Architecture - Day 1 Study Notes

**Date:** January 31, 2026  
**Focus:** Understanding the post-Noname acquisition unified platform

---

## 🏗️ The Two-Layer Architecture

### Layer 1: App & API Protector (AAP) - "The Shield"
**Deployment:** Inline at Akamai's global edge network  
**Function:** Real-time blocking and enforcement

**Capabilities:**
- **DDoS Mitigation:** Volumetric attack absorption (Tbps-scale capacity)
- **WAF (Signature-based):** Blocks known exploits (SQLi, XSS, RCE)
- **Rate Limiting:** Edge-level throttling (requests/sec per IP/user/endpoint)
- **Bot Management:** Behavioral fingerprinting, CAPTCHA challenges
- **Adaptive Security Engine:** Auto-tuning of WAF rules based on traffic patterns

**Limitation:** Cannot detect logic abuse (BOLA, BFLA) because:
- Requests are syntactically valid
- Authentication succeeds (valid JWT)
- No malicious payload strings
- Appears as legitimate API usage

---

### Layer 2: Akamai API Security (Noname) - "The Radar"
**Deployment:** Out-of-band (sideband analysis)  
**Function:** Deep behavioral analytics and discovery

**The 4 Pillars:**

#### 1. Discovery & Inventory
- **Shadow APIs:** Finds undocumented endpoints (developer shortcuts, test APIs)
- **Zombie APIs:** Identifies deprecated endpoints still receiving traffic
- **Data Classification:** Auto-tags APIs exposing PII/PCI/PHI
- **Method:** Traffic analysis (mirrors), code scanning (GitHub integration)

**Value:** Customers typically discover 30-40% more APIs than they knew existed

#### 2. Posture Management
- **Configuration Auditing:** Scans API gateways, cloud configs for misconfigurations
- **Compliance Mapping:** Maps findings to PCI DSS, OWASP API Top 10, NIST
- **Vulnerabilities:** Flags weak auth, missing encryption, verbose errors
- **Code-to-Runtime:** Links runtime risks back to GitHub repo/line number

#### 3. Runtime Protection (Behavioral Analytics)
**How it works:**
- **Baseline Learning:** 7-14 days per-user, per-endpoint profiling
- **Metrics Tracked:**
  - Request rate (calls/minute)
  - Object ID cardinality (unique resources accessed)
  - Data volume (bytes transferred)
  - Geolocation patterns
  - Time-of-day patterns

**Anomaly Detection:**
```
Example: BOLA Detection

Baseline:
  User: alice@company.com
  Endpoint: GET /orders/{id}
  Normal: Accesses 2-3 order_ids per day
  IDs: [1234, 5678, 9012] (her actual orders)

Attack Pattern:
  Same user suddenly accesses 500 distinct order_ids in 10 minutes
  IDs: Sequential enumeration (1, 2, 3, 4, 5...)
  
Risk Score: 95/100 → "High Cardinality Object Access - BOLA Suspected"
```

**Response Actions:**
- Alert to SIEM/SOC
- Signal AAP to block IP at edge
- Revoke JWT session token
- Rate-limit user to 5 req/min

#### 4. Active Testing (Shift-Left)
- **CI/CD Integration:** Jenkins, GitHub Actions, GitLab
- **Dynamic Testing:** Fuzzes APIs in staging (150+ attack simulations)
- **Coverage:** OWASP API Top 10 (BOLA, BFLA, Injection, etc.)
- **Enforcement:** Can fail builds if critical vulnerabilities detected

---

## 🔗 The Native Connector Innovation

**Problem (Pre-Acquisition):**
- Customers had to deploy on-premise traffic collectors (SPAN ports, agents)
- Complex setup, high deployment friction
- Weeks/months to Time-to-Value (TTV)

**Solution (Post-Acquisition):**
The **Native Connector** bridges Akamai Edge to API Security analytics:
```
Traffic Flow:
1. User request → Akamai Edge (AAP)
2. Edge processes request (blocks if malicious)
3. SIMULTANEOUSLY: Edge mirrors traffic copy to API Security engine
4. API Security analyzes behavior, builds baselines
5. If anomaly detected → Signals back to Edge for blocking
```

**Advantages:**
- **Zero deployment:** "Flip a switch" in Akamai Control Center
- **Zero latency:** Out-of-band mirroring (doesn't slow requests)
- **Global scale:** Leverages Akamai's 350,000+ servers
- **TTV:** Hours instead of months

---

## 🆚 Why Both Layers Are Required

| Threat Type | Traditional WAF (AAP Alone) | API Security + AAP |
|-------------|----------------------------|-------------------|
| SQL Injection | ✅ Blocks (signature match) | ✅ Blocks (signature match) |
| DDoS (volumetric) | ✅ Absorbs at edge | ✅ Absorbs at edge |
| **BOLA** (logic abuse) | ❌ Allows (looks valid) | ✅ Detects (behavioral anomaly) |
| **BFLA** (privilege escalation) | ❌ Allows (valid endpoint) | ✅ Detects (role violation) |
| **Data Exfiltration** (slow leak) | ❌ Misses (no spike) | ✅ Detects (volume over time) |
| **Shadow APIs** | ❌ Blind (no visibility) | ✅ Discovers (traffic analysis) |

**The Insight:**
- **WAFs protect against syntax errors** (malformed requests)
- **API Security protects against semantic errors** (malicious intent)

---

## 🎯 Akamai vs. Competitors

### vs. Salt Security
- **Salt Strength:** Pioneer in behavioral AI, strong analytics
- **Akamai Advantage:** 
  - Blocks at edge (Salt requires WAF integration)
  - Global scale (350K+ servers vs. cloud-only)
  - Native Connector (lower deployment friction)

### vs. Traceable AI
- **Traceable Strength:** Distributed tracing (eBPF), code-level visibility
- **Akamai Advantage:**
  - Agentless (Traceable often requires in-app agents → stability risk)
  - Zero latency impact (agents consume CPU/RAM)
  - Proven at scale (Akamai = 30% of internet traffic)

### vs. 42Crunch
- **42Crunch Strength:** Developer-focused, shift-left excellence
- **Akamai Advantage:**
  - Full lifecycle (42C weak on runtime detection)
  - Enterprise SOC integration (SIEM, ticketing)
  - Managed services available (Shadow Hunt)

---

## 🔑 Key Terminology for Interview

- **Native Connector:** Edge-to-analytics traffic bridge (Akamai differentiator)
- **Shadow APIs:** Undocumented endpoints developers deployed outside governance
- **Zombie APIs:** Deprecated endpoints still active (security debt)
- **Behavioral Baseline:** ML-driven "normal" profile per user/endpoint
- **High Cardinality Anomaly:** User accessing far more unique IDs than baseline (BOLA indicator)
- **Out-of-Band:** Traffic mirroring for analysis (vs. inline blocking)
- **Shift-Left:** Moving security testing earlier in SDLC (CI/CD integration)

---

## 📊 Detection Example: BOLA in crAPI

**Scenario:** User exploits shop orders endpoint

**AAP (WAF) View:**
```
Request: GET /workshop/api/shop/orders/3
Auth: Bearer eyJhbGc... (valid token)
Payload: None
Status: 200 OK
WAF Verdict: ✅ ALLOW (no signature match)
```

**API Security View:**
```
User: test@example.com
Baseline: Accesses 1-2 order_ids per session
Current Activity:
  - 15:00:00 - GET /orders/4 (own order)
  - 15:00:05 - GET /orders/3 (unauthorized)
  - 15:00:10 - GET /orders/2 (unauthorized)
  - 15:00:15 - GET /orders/1 (unauthorized)
  
Anomaly: 400% increase in cardinality (1→4 unique IDs)
Pattern: Sequential enumeration (4→3→2→1)
Risk Score: 85/100
Alert: "BOLA - Object Enumeration Detected"
Action: Block user's IP at edge, revoke JWT
```

---

## 💡 Customer Value Translation

**For VP/CISO:**
"Traditional firewalls stop hackers at the door. But what if an employee—or a compromised account—starts stealing data from the inside? That looks totally normal to a firewall. Akamai's behavioral AI learns what 'normal' looks like for every user and catches the abuse that signatures miss."

**For AppSec Engineer:**
"We baseline per-user behavior over 14 days. When User A suddenly accesses 100 distinct order IDs (vs. their baseline of 2/day), we flag it as potential BOLA enumeration. You control the sensitivity thresholds; we enforce the policy at the edge."

---

*Study Time: 2.5 hours (Block 1)*  
*Next: Hands-on BOLA exploitation to validate detection theory*
