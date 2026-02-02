# Day 1 Quick Reference - Interview Cheat Sheet

**Use this for 60-second review before interview**

---

## 🔥 BOLA One-Liner
"Authenticated user manipulates object IDs to access resources they don't own. WAFs miss it because requests are syntactically valid. Akamai detects it via behavioral baselining—flagging high cardinality access patterns."

---

## 🏗️ Akamai Architecture (30-second explanation)
"Two layers: **App & API Protector** blocks at the edge (DDoS, WAF, bots). **API Security** analyzes behavior out-of-band (BOLA, shadow APIs, logic abuse). **Native Connector** bridges them—mirrors edge traffic to analytics with zero deployment friction."

---

## 🆚 vs. Competitors (Quick)
- **vs. Salt:** We block at edge, they don't. We have Native Connector, they require complex collectors.
- **vs. Traceable:** We're agentless (zero app impact), they often need in-app agents.
- **vs. 42Crunch:** We cover runtime, they're weak there. We're enterprise-scale SOC integration.

---

## 📊 BOLA Detection Flow
```
Baseline: User accesses 2 order_ids/day
Anomaly: User accesses 100 order_ids in 10 min (5000% increase)
Alert: "High Cardinality - Risk 95/100"
Action: Block IP at edge + Revoke JWT
```

---

## 🎤 Elevator Pitch (Bullets)
1. **Problem:** Most orgs run fragmented security stack (5 vendors, no integration)
2. **Edge Layer:** AAP blocks volumetric (350K servers, 135 countries)
3. **Analytics Layer:** API Security catches logic abuse via behavioral ML
4. **Integration:** Native Connector = one platform, hours to deploy
5. **Result:** Unified defense, one vendor, one contract

---

## 🔑 Key Terms (Memorize)
- **Native Connector:** Edge-to-analytics traffic bridge
- **Shadow API:** Undocumented endpoint (dev shortcut)
- **Zombie API:** Deprecated endpoint still active
- **High Cardinality:** Many unique IDs accessed (BOLA indicator)
- **Out-of-Band:** Analyzes traffic copy (zero latency)
- **Shift-Left:** Security testing in CI/CD (pre-production)

---

## 💡 Value Translation Examples

**For VP:**
"Traditional firewalls stop attacks at the door. Akamai also stops the insider who's slowly stealing data—which looks normal to a WAF."

**For AppSec:**
"We baseline per-user behavior over 14 days. When User A accesses 100 IDs vs. baseline of 2, we flag potential BOLA. You tune thresholds; we enforce at edge."

**For CISO:**
"One platform covering edge to code. Eliminates integration tax. Faster incident response (single timeline vs. correlating 5 tools)."

---

*Last Updated: January 31, 2026*  
*Confidence Level: Day 1 = 8/10*
