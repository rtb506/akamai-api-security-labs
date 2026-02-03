# Technical Concepts Matrix - Days 2 & 3

**Purpose:** Quick-reference comparison table for key concepts  
**Study Date:** February 2, 2026

---

## Authorization Vulnerability Comparison

| Aspect | BOLA (API1:2023) | BFLA (API5:2023) |
|--------|------------------|------------------|
| **Full Name** | Broken Object Level Authorization | Broken Function Level Authorization |
| **Privilege Type** | Horizontal escalation | Vertical escalation |
| **Attack Vector** | Object ID manipulation | Function access without proper role |
| **Example** | `GET /api/orders/123` → `/api/orders/124` | Regular user calls `POST /api/admin/delete-user` |
| **Missing Control** | Ownership validation (`order.user_id == current_user.id`) | Role validation (`@require_role('admin')`) |
| **Detection Signal** | High cardinality, sequential IDs | Low role accessing privileged endpoints |

---

## Attack Technique Comparison

| Aspect | Rate Limit Bypass (API4:2023) | Mass Assignment (API3:2023) |
|--------|-------------------------------|------------------------------|
| **Primary Goal** | Resource exhaustion, brute force | Privilege escalation, data manipulation |
| **Technique #1** | IP spoofing via X-Forwarded-For | Hidden parameter injection |
| **Technique #2** | Race condition (TOCTOU) | Automated parameter fuzzing |
| **Why WAF Fails** | Valid syntax, proper auth | Valid JSON structure |
| **Detection Method** | Sequential IPs, bot-speed timing | Schema violation, restricted keywords |
| **Business Impact** | Financial fraud, DoS | Privilege escalation, compliance breach |

---

## JWT Vulnerability Classification

| Vulnerability Type | Technical Cause | Exploitation Method | Prevention |
|--------------------|-----------------|---------------------|------------|
| **Algorithm None** | Server accepts `alg:none` | Remove signature, forge claims | Reject `alg:none`, enforce algorithm whitelist |
| **Weak HMAC Secret** | Predictable secret key | Brute-force secret, sign valid tokens | 256-bit random secrets, rotation policy |
| **Algorithm Confusion** | HS256 accepted when expecting RS256 | Use public key as HMAC secret | Enforce algorithm per key type |
| **Claim Tampering** | No server-side validation | Modify role/permissions in payload | Server-side claim verification |

---

## Behavioral Detection Metrics

| Metric | Purpose | Baseline Example | Attack Example | Weight in Risk Score |
|--------|---------|------------------|----------------|----------------------|
| **Request Rate** | Identify automation | 10 req/day | 500 req/hour | 25% |
| **Object ID Cardinality** | Detect enumeration | 3 unique IDs/day | 300 unique IDs/hour | 40% |
| **Data Volume** | Flag exfiltration | 20 KB/day | 5 MB/hour | 20% |
| **Geolocation** | Anomalous access | San Francisco (residential ISP) | Russia (hosting provider) | 10% |
| **Temporal Pattern** | Unusual timing | 9AM-5PM weekdays | 3AM weekend | 5% |

---

## Akamai Platform Component Comparison

| Component | App & API Protector (AAP) | API Security (Noname) |
|-----------|---------------------------|------------------------|
| **Deployment** | Inline (edge network) | Out-of-band (sideband analysis) |
| **Primary Function** | Real-time blocking | Behavioral analysis, discovery |
| **Latency Impact** | Minimal (<1ms) | Zero (no inline processing) |
| **Attack Coverage** | DDoS, WAF, bot management, rate limiting | Logic abuse, shadow APIs, posture |
| **Detection Method** | Signature-based + basic behavioral | ML-based behavioral profiling |
| **Response Speed** | Milliseconds | Seconds to minutes (analysis → signal edge) |
| **Best For** | Volumetric attacks, known threats | Logic abuse, unknown APIs, complex attacks |

---

## Competitive Platform Analysis

| Evaluation Factor | Akamai | Traceable AI | Salt Security |
|-------------------|---------|--------------|---------------|
| **Detection** | Behavioral ML | eBPF distributed tracing | Behavioral AI |
| **Enforcement** | Native (AAP) | Requires WAF | Requires WAF |
| **Deployment** | Agentless (traffic mirror) | eBPF agents | Collectors, SPAN ports |
| **TTV (CDN customer)** | Hours-days | Weeks | Weeks-months |
| **Vendor Count** | 1 (unified) | 2 (Traceable + WAF) | 2 (Salt + WAF) |
| **App Impact** | Zero | Agent overhead | Minimal |
| **Key Strength** | Edge blocking + analytics | Code-level visibility | Mature ML models |
| **Key Limitation** | Less code context | Requires WAF integration | No native enforcement |

---

## Remediation Pattern Comparison

| Vulnerability | Immediate (0-24hr) | Short-term (1-7 days) | Long-term (1-4 weeks) |
|---------------|--------------------|-----------------------|------------------------|
| **Rate Limit Bypass** | Block attacker IP, adjust threshold | Per-JWT rate limiting, reject untrusted X-Forwarded-For | Atomic counters (Redis), CAPTCHA integration |
| **Mass Assignment** | Virtual patch (WAF rule) | Implement DTO validation | Separate input/output models, RBAC |
| **JWT alg:none** | Block affected tokens | Enforce algorithm whitelist | Automated config scanning, secret rotation |
| **BOLA** | Block attacker, revoke token | Add ownership checks | UUIDs instead of sequential IDs, API audit |
| **BFLA** | Block endpoint access | Implement role decorators | Comprehensive RBAC, least privilege |

---

## Detection Signal Classification

| Signal Type | True Positive Indicators | False Positive Indicators |
|-------------|--------------------------|---------------------------|
| **High Cardinality** | Sequential IDs (1,2,3...), bot-speed timing | Scheduled job, product launch affecting all users |
| **Rate Spike** | Identical User-Agent across IPs, hosting provider IPs | Partner integration, legitimate batch processing |
| **Geolocation Change** | Rapid location shift + other anomalies | Business travel, VPN usage (other metrics normal) |
| **Parameter Injection** | Restricted keywords (role, is_admin) + privilege mismatch | Admin user performing admin functions |
| **Data Volume Spike** | Regular user exporting massive data | Admin/analyst role performing report generation |

---

*Purpose: Quick-reference matrix for technical concept comparison*  
*Usage: Interview preparation, concept differentiation*  
*Last Updated: February 2, 2026*
