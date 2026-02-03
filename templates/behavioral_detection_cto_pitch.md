# Behavioral Detection Pitch - For Skeptical CTO/CISO

**Use Case:** Customer doubts ML, wants "proof" it's not a black box

---

## The Pitch (3 minutes)

"I understand the concern about 'machine learning magic'—and I appreciate the skepticism. Let me show you exactly how transparent this is.

**The Problem with Signatures:**
Your current WAF uses signatures. It looks for attack strings—SQL injection syntax, JavaScript in weird places, that kind of thing. That works great for **syntax attacks**. But 70% of API breaches today are **logic attacks**—authenticated users doing things they shouldn't. And those requests look 100% valid to a signature engine.

**Example:**
Your customer service rep logs in with their valid credentials. They have permission to access customer orders—that's their job. But instead of accessing 10 orders like they normally do, they access 10,000 orders in an hour and export them to a USB drive.

Every single request looks legit:
- Valid authentication token ✓
- Proper HTTP syntax ✓
- Authorized endpoint ✓
- Returns 200 OK ✓

Your WAF says: 'All good.' But clearly, something's wrong.

**How We Catch It:**

We don't look for bad code—we look for bad **behavior**. Here's the process:

**Phase 1: Learning (7-14 days, monitor-only mode)**
We observe every user's normal patterns:
- How many orders does this rep access per day? (Baseline: 8-12)
- What's their typical work hours? (Baseline: 9AM-5PM EST)
- Where do they access from? (Baseline: Office IP)

We're not blocking anything yet—just building their 'fingerprint.'

**Phase 2: Detection (real-time)**
The system runs a deviation calculation on every request:
```
Current activity: 500 orders in 1 hour
Baseline: 10 orders per day
Deviation: 5000%
Risk score: 95/100 (weighted by cardinality, rate, volume)
```

**YOU control the threshold.** You can say 'Don't alert unless risk > 90' or 'Alert at 75.' It's tunable.

**Phase 3: Evidence (full transparency)**
When an alert fires, we show you:
- The exact baseline numbers
- The exact current numbers  
- The math behind the risk score
- The user's historical activity graph

It's not a black box—it's auditable behavioral math.

**The Catch:**
You need to tolerate a 2-week learning period. During that time, we're silent. No alerts, no blocks—just learning. Some customers hate waiting 2 weeks. But the alternative is high false positives from Day 1, and that destroys trust in the system.

**The Outcome:**
After tuning, our false positive rate is typically under 2%. And we catch attacks your WAF will never see—because we're detecting **intent**, not just **syntax**.

**Your Decision:**
Do you want a system that catches only the attacks that announce themselves with bad syntax? Or do you want a system that catches the insider slowly bleeding your database dry?

Because one of those is what happened to [Competitor X] last quarter. And it looked totally normal to their WAF."

---

## Objection Handling

**Objection 1:** "2 weeks is too long to wait for protection."

**Response:**
"Fair point. But here's the reality: If we turn on blocking on Day 1, we'll be flagging your legitimate batch jobs, your partner integrations, your admin users—anything that doesn't fit a generic 'average user' profile. You'll spend the first 2 weeks drowning in false positives, disabling alerts, and eroding trust in the system.

The 2-week learning period isn't 'no protection'—you still have your WAF, your DDoS protection, your bot manager. We're learning the LOGIC layer. And after 2 weeks, we're catching attacks those other tools will never see.

Would you rather have loud, inaccurate alerts immediately? Or quiet, accurate alerts in 14 days?"

---

**Objection 2:** "What if my business changes during the learning period?"

**Response:**
"Great question. The baseline is **adaptive**—it doesn't lock in forever. If you launch a new feature that changes user behavior, the baseline recalibrates. We detect 'global' shifts (all users suddenly accessing 10x more) vs 'individual' anomalies (one user suddenly accessing 10x more).

If everyone's behavior changes, that's a feature launch. If one person's behavior changes, that's an investigation."

---

**Objection 3:** "How do I know you won't block my VIP customer who happens to use the app differently?"

**Response:**
"You can whitelist specific users, API keys, or IP ranges. If your CEO travels constantly and triggers geo-anomalies, we whitelist them. If your analytics partner accesses 100,000 records daily, we whitelist their API key.

The system is **permissive by design**—we alert first, you approve blocks. You're in control."

---

*Use this script in roleplay practice*  
*Target: 3-minute delivery, confident tone*  
*Practice out loud 2x before interview*
