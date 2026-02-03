# Behavioral Detection Deep-Dive - Day 2 Study Notes

**Date:** February 1, 2026  
**Focus:** Understanding Akamai's ML-based anomaly detection

---

## 🧠 The Machine Learning Approach

### Phase 1: Baseline Learning (7-14 days)

**What the ML engine tracks PER USER, PER ENDPOINT:**

1. **Request Rate**
   - Calls per minute/hour/day
   - Pattern: Steady (9-5 worker) vs Bursty (batch jobs)
   - Example: User accesses /orders 10x/day, always between 9AM-5PM EST

2. **Object ID Cardinality**
   - Number of DISTINCT resource IDs accessed
   - Pattern: Low (user owns 3 orders) vs High (admin dashboard)
   - Example: Regular user accesses 2-5 unique order_ids per session
   - Admin user accesses 50-100 unique order_ids (legitimate)

3. **Data Volume**
   - Bytes transferred in requests/responses
   - Pattern: Consistent (viewing orders) vs Spike (export to CSV)
   - Example: Viewing single order = 2KB response
   - Bulk export = 5MB response (flagged if user never did this before)

4. **Geolocation**
   - Countries, cities, ASNs (Autonomous System Numbers)
   - Pattern: Consistent location vs Travel
   - Example: User always accesses from San Francisco
   - Sudden access from Russia = high-risk anomaly

5. **Time-of-Day Patterns**
   - Active hours (business hours vs off-hours)
   - Example: 9-5 user suddenly active at 3AM = suspicious

6. **HTTP Method Distribution**
   - Ratio of GET vs POST vs PUT vs DELETE
   - Example: Regular user = 95% GET, 5% POST
   - Attacker script = 80% POST (creating/modifying resources)

---

## 📊 Anomaly Scoring Algorithm

**Risk Score Calculation (0-100):**
```
Risk Score = Weighted sum of deviations:
- Cardinality deviation: 40% weight (most important for BOLA)
- Rate deviation: 25% weight
- Volume deviation: 20% weight
- Geo deviation: 10% weight
- Time pattern deviation: 5% weight
```

**Example Calculation:**

**Baseline:**
```
User: alice@company.com
Endpoint: GET /api/orders/{id}
Normal behavior (14-day baseline):
  - Request rate: 8-12/day
  - Cardinality: 2-3 unique order_ids per day
  - Data volume: 15-20 KB/day
  - Geolocation: San Francisco (always)
  - Active hours: 9AM-6PM PST (weekdays)
```

**Attack Pattern:**
```
Observed behavior (current):
  - Request rate: 150/hour (1800% increase)
  - Cardinality: 200 unique order_ids in 1 hour (10,000% increase)
  - Data volume: 2MB in 1 hour (10,000% increase)
  - Geolocation: San Francisco (consistent)
  - Active hours: 2PM PST (normal)
```

**Risk Calculation:**
```
Cardinality deviation: 10,000% → Score: 100 → Weight: 40% = 40 points
Rate deviation: 1800% → Score: 95 → Weight: 25% = 23.75 points
Volume deviation: 10,000% → Score: 100 → Weight: 20% = 20 points
Geo deviation: 0% → Score: 0 → Weight: 10% = 0 points
Time deviation: 0% → Score: 0 → Weight: 5% = 0 points

TOTAL RISK SCORE: 83.75 / 100 → HIGH SEVERITY
Alert: "Potential BOLA - Object Enumeration Detected"
```

---

## 🎯 True Positive vs False Positive Triage

**The Challenge:** Not every anomaly is an attack.

**Common False Positive Scenarios:**

1. **Legitimate Batch Jobs**
   - Example: Nightly ETL process exports all orders
   - Pattern: High cardinality + high volume + off-hours
   - Triage: Known scheduled job → Whitelist this specific user/time window

2. **New Feature Launch**
   - Example: New "Order History" page lets users scroll 100 orders
   - Pattern: Sudden spike in cardinality across ALL users
   - Triage: Product team confirms launch → Adjust baseline for this endpoint

3. **Partner Integration**
   - Example: Vendor's API key accesses 1000s of orders for analytics
   - Pattern: High rate + high cardinality + known API key
   - Triage: Business partnership confirmed → Whitelist API key

4. **User Travel**
   - Example: Sales rep accesses CRM from airport in Japan
   - Pattern: Geolocation anomaly (US → Japan) but normal cardinality
   - Triage: VPN or travel → Low risk if other metrics normal

**True Positive Indicators:**

1. **Sequential Enumeration**
   - Pattern: IDs accessed in exact order (1, 2, 3, 4, 5...)
   - Verdict: HIGH confidence attack (humans don't access sequentially)

2. **Timing: Too Fast**
   - Pattern: 100 requests in 10 seconds (automation, not human)
   - Verdict: HIGH confidence bot/script

3. **Failed Auth + Success**
   - Pattern: 50 failed auth attempts → 1 success → high cardinality access
   - Verdict: CRITICAL - credential stuffing → BOLA chaining

4. **Data Pattern: No Overlap**
   - Pattern: User's owned order_ids = [100, 200, 300]
   - User accessed: [1, 2, 3, 4, 5, 6...] (zero overlap with owned)
   - Verdict: HIGH confidence unauthorized access

---

## 🔀 Decision Tree: Alert Triage Workflow
```
ALERT TRIGGERED
       ↓
Known scheduled job?
   ├─ YES → Whitelist (adjust baseline) → FP
   └─ NO → Continue
       ↓
High cardinality access?
   ├─ YES → Investigate pattern
   │    ├─ Sequential IDs? → TP (BOLA)
   │    ├─ Too fast (bot speed)? → TP (Automation)
   │    └─ Random IDs + Business justification? → FP (Legit use)
   └─ NO → Continue
       ↓
Data volume spike?
   ├─ YES → Investigate intent
   │    ├─ User role = Admin/Analyst? → FP (Legit export)
   │    ├─ User role = Regular + Never exported before? → TP (Exfiltration)
   └─ NO → Continue
       ↓
Geolocation anomaly?
   ├─ YES → Check context
   │    ├─ VPN provider IP? → FP (Privacy tool)
   │    ├─ Known bad actor country + Other anomalies? → TP (Compromised)
   └─ NO → Reduce sensitivity → Monitor (Borderline)
```

---

## 🛡️ Akamai's Advantage: Context-Aware Detection

**What Akamai knows that WAFs don't:**

1. **User Identity** (from JWT/session)
   - Can correlate: "User A accessing User B's resources"
   - WAF only sees: "Valid token → Allow"

2. **Historical Behavior**
   - Can detect: "This user NEVER accessed 100 IDs before"
   - WAF only sees: "100 requests in 1 minute → Rate limit?"

3. **Resource Ownership**
   - Can infer: "User owns order_ids [10, 20, 30]"
   - Can detect: "User now accessing [1, 2, 3, 4...] (not owned)"
   - WAF: Blind to ownership concept

4. **Cross-Endpoint Patterns**
   - Can correlate: "User failed login 50x, then BOLA on /orders"
   - Shows: Attack chain (credential stuffing → data theft)
   - WAF: Treats each endpoint in isolation

---

## 💡 Customer Communication: "Explain Baselining to Skeptical CTO"

**Scenario:** CTO says "Machine learning sounds like a black box. How do I trust it?"

**Your Response:**

"Great question. Let me demystify it. Our ML engine is actually quite transparent—you control the sensitivity thresholds, and we show you exactly why an alert fired.

Here's how it works in practice:

For 7-14 days, we watch your APIs in 'learning mode'—no alerts, no blocks, just observation. We're building a profile for every user. For example, we learn that your average customer service rep accesses 10-15 customer records per day, always during business hours, always from your office IP range.

Then, if that same rep suddenly accesses 500 records in 10 minutes at 3AM from a VPN in Russia, **we don't just guess**—we show you the math:

- Baseline: 15 records/day
- Current: 500 records in 10 min
- Deviation: 20,000% increase
- Risk score: 92/100

You can tune the threshold. If you say 'Don't alert unless risk > 95', we won't. If you say 'Alert at 80', we will. **You're in control.**

And here's the key: We catch attacks that your WAF cannot, because we're not looking for bad code—we're looking for bad **behavior**. A hacker with stolen credentials looks totally normal to a WAF. To us, they look like someone doing 20x more than they usually do.

That's not a black box—that's behavioral math you can audit."

---

*Study time: 60 minutes (Block 1, Step 1.2)*  
*Next: Build the triage flowchart diagram*
