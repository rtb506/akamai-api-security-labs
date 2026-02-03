# True Positive vs False Positive Triage Flowchart
```mermaid
graph TD
    A[Alert Triggered: High Cardinality Access] --> B{Known Scheduled Job?}
    B -->|YES| C[Whitelist - Adjust Baseline]
    B -->|NO| D{High Cardinality Confirmed?}
    
    D -->|YES| E{Access Pattern Analysis}
    D -->|NO| F{Data Volume Spike?}
    
    E --> E1{Sequential IDs?}
    E --> E2{Too Fast - Bot Speed?}
    E --> E3{Random IDs + Business Justification?}
    
    E1 -->|YES| TP1[TRUE POSITIVE: BOLA Enumeration]
    E2 -->|YES| TP2[TRUE POSITIVE: Automated Scraping]
    E3 -->|YES| FP1[FALSE POSITIVE: Legitimate Use]
    
    F -->|YES| G{User Role Check}
    F -->|NO| H{Geolocation Anomaly?}
    
    G --> G1{Admin/Analyst Role?}
    G --> G2{Regular User + Never Exported?}
    
    G1 -->|YES| FP2[FALSE POSITIVE: Authorized Export]
    G2 -->|YES| TP3[TRUE POSITIVE: Data Exfiltration]
    
    H -->|YES| I{Context Analysis}
    H -->|NO| J[Reduce Sensitivity - Monitor]
    
    I --> I1{VPN Provider IP?}
    I --> I2{Bad Actor Country + Other Anomalies?}
    
    I1 -->|YES| FP3[FALSE POSITIVE: Privacy Tool]
    I2 -->|YES| TP4[TRUE POSITIVE: Compromised Account]
    
    C --> END1[Action: Update Baseline]
    TP1 --> ACTION1[Action: Block IP + Revoke Token]
    TP2 --> ACTION2[Action: Rate Limit + CAPTCHA]
    TP3 --> ACTION3[Action: Block + Forensic Investigation]
    TP4 --> ACTION4[Action: Force Password Reset + Alert User]
    FP1 --> END2[Action: Whitelist Activity]
    FP2 --> END3[Action: Whitelist Role]
    FP3 --> END4[Action: No Action Required]
    J --> END5[Action: Continue Monitoring]
    
    style TP1 fill:#ff6b6b
    style TP2 fill:#ff6b6b
    style TP3 fill:#ff6b6b
    style TP4 fill:#ff6b6b
    style FP1 fill:#51cf66
    style FP2 fill:#51cf66
    style FP3 fill:#51cf66
```

**Key Decision Points:**

1. **Scheduled Job Check** (Easiest FP to eliminate)
2. **Pattern Analysis** (Sequential = High confidence TP)
3. **Speed Analysis** (Bot-speed = Automation)
4. **Role Verification** (Admin doing admin things = FP)
5. **Context** (VPN + Normal behavior = FP, VPN + Anomalies = TP)

---

*Created: February 1, 2026*  
*Use: Interview whiteboarding exercise*
