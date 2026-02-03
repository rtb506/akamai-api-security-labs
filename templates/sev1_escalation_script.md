# Sev1 Escalation Roleplay Script

## Scenario
Customer: "Your product is blocking our mobile app! Production is down!"

## Your Response (5-step framework)

### 1. ACKNOWLEDGE (10 seconds)
"I see the alerts in the dashboard. I'm on it immediately. Let me triage this for you."

**Tone:** Calm, confident, no panic

---

### 2. GATHER DATA (60 seconds)
"I'm pulling the logs now... I see high request rate from your mobile user-agent. Let me check the pattern."

**Actions:**
- Open Incident Timeline in Akamai dashboard
- Filter by customer's app user-agent
- Check error rates (4xx vs 5xx)
- Identify blocked IPs/tokens

**What you're looking for:**
- Is it a real attack or false positive?
- What triggered the block? (Rate limit? Behavioral anomaly? WAF rule?)

---

### 3. ROOT CAUSE (30 seconds)
"Found it. Your mobile app is retrying failed authentication requests 10x per second. Your baseline is 2 retries per second. The system flagged this as a credential stuffing attack and rate-limited the app."

**Translation:** 
- Technical: "10 req/sec vs baseline 2 req/sec = 400% deviation"
- Business: "System thought it was bots, but it's your app's retry logic"

---

### 4. MITIGATION (60 seconds)
"Here's what I'm doing right now:

**Immediate (next 2 minutes):**
- Temporarily raising rate limit for your mobile user-agent
- Whitelisting your app's specific token pattern
- Traffic should normalize in <5 minutes

**Short-term (next 24 hours):**
- Create custom rule: 'Allow 20 req/sec for User-Agent: YourApp/1.0'
- Adjust behavioral baseline for this specific flow

**Long-term (next sprint):**
- Recommendation: Implement exponential backoff in your app (retry after 1s, 2s, 4s, 8s...)
- This prevents future blocks and improves user experience"

**Actions in console:**
- Navigate to rate limiting policies
- Create exception rule
- Apply immediately
- Monitor traffic graph for normalization

---

### 5. FOLLOW-UP (commitment)
"I'm monitoring this in real-time. I'll send you an RCA (Root Cause Analysis) within 24 hours with:
- Exact timeline of what happened
- Why the system triggered
- Long-term recommendations to prevent recurrence

I'll stay on this call until we confirm traffic is back to normal."

**Tone:** Partnership, not vendor

---

## Key Principles

**DO:**
✅ Stay calm (your calm = their calm)
✅ Use timestamps ("I see the spike started at 13:45 UTC")
✅ Explain the "why" (system did X because it saw Y)
✅ Give immediate + long-term solutions
✅ Set clear expectations (RCA in 24h)

**DON'T:**
❌ Blame the customer ("Your app is misconfigured")
❌ Blame the product ("The ML is too sensitive")
❌ Panic or show uncertainty
❌ Overpromise ("This will never happen again")
❌ Go silent (radio silence = lost trust)

---

## Practice Drill

**Timer: 3 minutes**

1. Acknowledge (10s)
2. Gather data (60s) - simulate dashboard clicks
3. Root cause (30s)
4. Mitigation (60s)
5. Follow-up (20s)

**Record yourself.** 
Listen back. 
Did you sound calm? Clear? Confident?

Repeat until you can do it smoothly under pressure.
