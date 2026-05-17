# Race Conditions / TOCTOU in Web

> Server-side state-change windows where two concurrent requests bypass a check between read and write. Authorized testing only. Map: CWE-362, CWE-367.

## TL;DR
- Classic single-packet race (James Kettle, 2023): send the last byte of N requests in a single TCP frame so they arrive at the application "simultaneously" — defeats normal request-ordering.
- Targets: limit-once features (one-time coupon, withdrawal, password reset, email verification, 2FA enable, loyalty-points redemption).
- Defence: row-level locking + idempotency keys; application-layer rate-limit on the *user*, not the IP.

## Detection / Discovery

### Heuristic — features that imply a "check then act"
- "Apply coupon once per user."
- "Withdraw / transfer balance."
- "First N free trial users get X."
- "Confirm email token (single use)."
- "Vote / like / star / follow / report."
- "Generate one referral code."
- "Use 2FA token (TOTP) once."

### Tooling
- **Turbo Intruder** (Burp Suite extension by James Kettle) — Python-scripted parallel sender; `engine=Engine.BURP2`, `concurrentConnections=N`.
- **Race-the-Web** (deprecated; reference only).
- Custom: TCP single-packet last-byte sync.

```python
# Turbo Intruder script — classic last-byte sync (PortSwigger pattern)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           requestsPerConnection=1, pipeline=False)
    for i in range(30):
        engine.queue(target.req)
    engine.start(timeout=10)
def handleResponse(req, interesting):
    table.add(req)
```

## Exploitation

### Single-request multi-effect (limit bypass)
- Coupon code `DISCOUNT10` redeemable once. Send 50 simultaneous `POST /cart/apply-coupon` with the same code → race window between "check usage count" and "increment usage count" lets some succeed beyond 1.
- Outcome: free 50× discount.

### TOCTOU on balance
1. User balance = $100. Request: withdraw $80.
2. Server reads balance = $100; calls "withdraw $80" → balance = $20.
3. Concurrent second request reads balance = $100 still (before commit); calls "withdraw $80" again → balance = -$60.

### Sub-state confusion (different endpoint pair)
- `POST /api/profile/email` (set new email) followed by `POST /api/account/delete-by-email` running concurrently — the second succeeds against the old email after the first commits, but the password-reset token is keyed to the new email.

### 2FA bypass via concurrent confirm + state read
Some 2FA-enable flows: confirm-OTP endpoint marks 2FA enabled, login endpoint reads "is 2FA enabled". If the user can call both in parallel, they may complete login under the pre-enable state while their account becomes 2FA-enabled — leaves both sides confused.

## Bypasses (defender-side anti-patterns to look for)
- Application-layer rate-limit on IP, not on user → multi-IP attacker bypasses.
- Idempotency-key check that's read-then-insert without unique constraint → race window.
- Distributed cache (Redis) as the lock store with `SETNX` — if the lock is per-request-instance not per-user-action, two simultaneous requests acquire different locks.

## Defence / Remediation
- **Database-level uniqueness**: unique index on `(user_id, coupon_code)`; insert before update; failure on duplicate is the rate-limit.
- **Row-level locking**: `SELECT ... FOR UPDATE` within the same transaction that performs the write. Postgres `pg_advisory_xact_lock` for cross-row coordination.
- **Idempotency keys**: client supplies `Idempotency-Key: <uuid>`, server stores key→result on first call; subsequent calls with the same key return the stored result without re-executing.
- **Optimistic concurrency**: row carries `version` column; update with `WHERE version = X` returns 0 rows if someone else changed it → retry / fail.
- **Distributed locks** (Redlock pattern with caveats — Martin Kleppmann's note on Redlock is required reading before relying on it).
- **Atomic SQL counters**: `UPDATE coupons SET redeemed = redeemed + 1 WHERE code = ? AND redeemed < max_uses` returns rowcount; check before commit.
- CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization.

## Sources
- PortSwigger / James Kettle — "Smashing the State Machine" (2023, race conditions on the web): https://portswigger.net/research/smashing-the-state-machine
- PortSwigger Web Security Academy — Race conditions: https://portswigger.net/web-security/race-conditions
- Turbo Intruder: https://github.com/PortSwigger/turbo-intruder
- HackTricks Race Conditions: https://book.hacktricks.wiki/en/pentesting-web/race-condition.html
- Martin Kleppmann — "How to do distributed locking": https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html
- CWE-362 / CWE-367: https://cwe.mitre.org/data/definitions/362.html / https://cwe.mitre.org/data/definitions/367.html
