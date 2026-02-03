# BFLA Exploitation - crAPI Mechanic Endpoint

## Attack Chain
1. **Recon:** Discovered admin endpoint via directory fuzzing
2. **Exploit:** Regular user POST to admin-only function
3. **Proof:** Successfully added mechanic without admin role

## Vulnerability
- Missing role check: `if user.role != "admin": return 403`
- Endpoint accessible to any authenticated user

## Akamai Detection
- Alert: "Low-privilege user accessing admin function"
- Pattern: Regular user hitting `/admin/*` paths
- Risk score: 88/100
- While BFLA cannot be prevented purely at the edge, Akamai can surface anomalous role usage and access patterns that differ from established user baselines.

## Remediation
```python
@app.route('/api/mechanic/add', methods=['POST'])
@require_role('admin')  # Add this decorator
def add_mechanic():
    # existing code
```
