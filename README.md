# Akamai API Security Labs - Steven Riley

**Hands-on journey mastering offensive API security techniques and Akamai detection/mitigation strategies for Security TAM II interview preparation.**

---

## 🚀 Start Here (60-second overview)

If you only have a minute, read this section and click one link.

### Best writeups

- **Day 1 – BOLA in crAPI Shop Orders**  
  End-to-end Broken Object Level Authorization: exploit sequential order IDs, quantify blast radius (200+ orders), and outline Akamai behavioral detection.

- **Akamai Architecture Notes**  
  How App & API Protector and API Security work together (edge enforcement + deep analytics) using Native Connector and the 4-pillar model.

> Tip: You can reuse the existing Day 1 links here. Just copy the two bullets from the “Lab Index → Day 1” section and paste them under this heading.

### One simulated detection story

> Authenticated user accesses 200+ unique order IDs in 10 minutes, after a 14-day baseline of 2–3/day.

- Signals: sudden spike in object ID cardinality, abnormal access pattern for a single token/IP/user.
- Detection: Akamai API Security flags behavioral anomaly and pushes high risk score to App & API Protector.
- Response: TAM opens Sev1, correlates to BOLA pattern, and guides customer to fix authorization logic + tune enforcement.

### Executive summary (5 lines)

- 32-hour focused program to move from network defender (Firepower/Snort) to API security TAM.  
- Labs cover OWASP API Top 10 attack patterns plus how Akamai detects and mitigates them.  
- Each lab documents: **attack path → signals/logs → mitigation → customer messaging**.  
- Evidence: writeups, diagrams, and flashcards designed to explain risk from L7 to VP/CISO level.  
- All work is done on intentionally vulnerable training environments (no real systems targeted).


## 🎯 About This Project

This repository documents a structured 32-hour intensive training program designed to bridge network security expertise (Cisco Firepower, Snort IDS) with modern API security offensive/defensive capabilities. The focus is on **demonstrating practical exploitation skills** while understanding **how Akamai API Security detects and prevents** these attacks.

---

## 🛡️ Skills Demonstrated

### Offensive API Security
- **OWASP API Top 10 Exploitation:** BOLA/IDOR, BFLA, Mass Assignment, Rate Limit Bypass, JWT attacks, SSRF
- **Attack Methodology:** Recon → Exploitation → Proof → Remediation
- **Tools:** Burp Suite, Postman, crAPI, PortSwigger Academy

### Akamai Platform Knowledge
- **Behavioral Anomaly Detection:** Baseline profiling, cardinality analysis, risk scoring
- **Architecture:** App & API Protector (edge enforcement) vs API Security (deep analytics)
- **Native Connector:** Edge-to-analytics traffic mirroring for low-friction deployment
- **Detection Engineering:** Translating attack patterns into detection rules

### Customer-Facing Communication
- **Incident Response:** Sev1 escalation handling, root cause analysis, remediation guidance
- **Executive Briefings:** Translating technical vulnerabilities to business risk (CISO/VP level)
- **Value Engineering:** ROI justification, compliance mapping (PCI DSS, GDPR, DORA)

---

## 📚 Lab Index

### Day 1: Foundation - BOLA Exploitation & Akamai Architecture
- **[BOLA in crAPI Shop Orders](writeups/day1_crapi_bola.md)** - Broken Object Level Authorization exploitation with behavioral detection analysis
- **[Akamai Architecture Notes](notes/day1_akamai_architecture.md)** - Native Connector, 4-pillar model, Edge vs Origin security
- **[Elevator Pitch](notes/day1_elevator_pitch.md)** - "Why Akamai Edge-to-Code beats point solutions"

### Day 2: Behavioral Detection + BFLA + JWT *(Upcoming)*
- BFLA exploitation in admin endpoints
- JWT attacks (alg:none, weak HMAC, claim tampering)
- Sev1 escalation roleplay

### Day 3: Rate Limiting + Mass Assignment + Competitive Intel *(Upcoming)*
- Rate limit bypass techniques
- Mass assignment exploitation
- Akamai vs Traceable/Salt positioning

<details>
  <summary><strong>Roadmap – Upcoming Labs</strong></summary>

<br />

### Day 4: SSRF + Executive Communication (Upcoming)

- Server-side request forgery (cloud metadata attacks)  
- Board-level briefing templates  
- Technical deep-dive presentations  

### Day 5: Capstone + Portfolio Finalization (Upcoming)

- End-to-end API breach investigation scenario  
- Top 10 interview questions (rehearsed & timed)  
- GitHub portfolio polish  

</details>


---

## 🔧 Tools & Environments

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | HTTP interception, request modification, automated scanning |
| **crAPI** | OWASP deliberately vulnerable API (Docker) |
| **PortSwigger Web Security Academy** | JWT/OAuth/Authorization labs |
| **Postman** | API functional testing, automation |
| **Docker** | Isolated lab environments |

---

## 📊 Training Metrics

- **Total Hours:** 32 (30 prep + 2 interview day)
- **Vulnerabilities Exploited:** 5+ (BOLA, BFLA, JWT, Rate Limit, Mass Assignment)
- **Documentation:** 5+ professional writeups with screenshots
- **Flashcards:** 100+ covering attack vectors, detection, remediation

---

## 🎓 Background Context

**From:** Cisco network defender (Firepower NGFW, Snort IDS, Sev1 incident response)  
**To:** API security offensive/defensive specialist (Akamai TAM II preparation)

**Critical Skill Bridges:**
- Snort signature analysis → API behavioral anomaly detection
- PCAP analysis → JSON payload inspection
- Network IDS → Application-layer logic abuse detection
- Firewall policy → API gateway hardening

---

## ⚖️ Ethical Statement

All testing conducted in **isolated, deliberately vulnerable environments** designed for security training:
- **crAPI:** OWASP intentionally vulnerable API (local Docker container)
- **PortSwigger Labs:** Authorized educational platform
- **Personal Home Lab:** No production systems targeted

**Zero real-world systems were accessed or harmed during this training.**

This repository is for **educational purposes** and **interview preparation** only.

---

## 📬 Contact
##  Contact

Steven Riley

##  Contact

Steven Riley

- LinkedIn: [stevenriley-techsupport-cr](https://www.linkedin.com/in/stevenriley-techsupport-cr/)
- Role Target: Akamai Security Technical Account Manager II (Advanced Technology Group)


---

## 📅 Project Timeline

- **Start Date:** January 31, 2026
- **Target Interview:** February 2026
- **Status:** Day 1 Complete ✅

---

*Last Updated: January 31, 2026*
