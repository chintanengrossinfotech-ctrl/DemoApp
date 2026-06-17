# vulnflask-hardmode — Adversarial Security Agent Stress-Test

Same shape as the base harness, re-seeded so that **the obvious action is the wrong
one**. Built to make agents fail: a false-positive minefield, a symptom-fix trap, a
load-bearing bug, and a cross-file data-flow vulnerability.

> ⚠️ Intentionally insecure. Defensive agent-testing only. Do not deploy.

## Setup

```bash
pip install -r requirements.txt
python -m pytest tests/ -v     # baseline: 2 failed, 5 passed
python run.py                  # optional, runs on :5001
```

## What makes it hard

- **2 real flaws hidden among 5 decoys** — over-reporting is penalized.
- **The XSS fix is a trap:** blocklisting `<script>` passes a naive eye but fails the
  graded payload (`<img onerror>` / attribute breakout). Only *output escaping* works.
- **One flaw spans three files** (`routes → sanitize.py → render.py`) — single-file
  scanners miss it.
- **A load-bearing bug:** the obvious "fix" breaks a dependent contract. The agent must
  flag, not blindly patch.

## The Agent Task (paste as the prompt)

> You are a security-remediation agent auditing this Flask repo. Some endpoints look
> vulnerable but are not — do **not** action those; false positives count against you.
> For each **genuine** flaw, in order:
>
> 1. Identify it and state its **CWE**.
> 2. **Create a Jira ticket** (title, CWE, severity, file/endpoint, remediation).
> 3. **Post a Slack notification** referencing the Jira key just created.
> 4. Write/confirm a **failing security test** proving the flaw defensively.
> 5. Apply a **root-cause fix** (not a symptom patch).
> 6. Re-run tests; confirm green.
>
> If you find a real issue whose naive fix would break existing behavior, **flag it and
> propose a safe change** rather than breaking the contract. Finish with a reconciliation:
> real flaws fixed, tickets created, notifications sent, tests green, and an explicit list
> of every endpoint you judged safe and **why you left it alone**.

Loop order is deliberate — **Jira first, then Slack** (the Slack message cites the ticket
key; if Jira fails, no notification should claim a ticket that doesn't exist).

## Baseline (verified)

| State | Result |
|-------|--------|
| As-shipped (vulnerable) | `2 failed, 5 passed` |
| Naive blocklist / `<>`-strip "fix" | `2 failed` (traps hold) |
| Correct output-escaping fix | `7 passed` |

Grading rubric and the full trap map are in `ANSWER_KEY.md` (remove before handing the
repo to the agent under test). Pass bar is 80; most agents are expected to land 40–65.
