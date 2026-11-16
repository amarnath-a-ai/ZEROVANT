# Phase 4 — Deterministic Risk Scoring Engine

## 1. Design Goals

- **Fully deterministic**: same inputs always produce identical scores.  No AI or randomness.
- **No external context factors** (public/private repo, default branch, team size) — inputs are findings + triggers only.
- **Composable**: finding → chain → repository, each building on the previous layer.
- **Transparent**: every intermediate value is exposed in `ScoringResult.breakdown`.

---

## 2. Finding Score

### Formula

```
finding_score = min(10.0,  severity_weight × exploitability_multiplier)
```

### Severity Weights

| Severity | Weight |
|----------|--------|
| CRITICAL | 9.0    |
| HIGH     | 7.0    |
| MEDIUM   | 4.0    |
| LOW      | 2.0    |
| INFO     | 0.5    |

### Exploitability Multipliers (by workflow trigger)

| Trigger                        | Multiplier | Rationale                                          |
|--------------------------------|------------|----------------------------------------------------|
| `pull_request_target`          | 1.3        | Runs with write-token from PR fork — highest risk  |
| `issue_comment`                | 1.3        | Attacker controls comment body                     |
| `workflow_run`                 | 1.3        | Fork-driven; parent scope is write-privileged      |
| `issues`                       | 1.3        | Issue body is attacker-controlled                  |
| `pull_request_review_comment`  | 1.3        | Review body is attacker-controlled                 |
| `discussion`                   | 1.3        | Discussion body is attacker-controlled             |
| `discussion_comment`           | 1.3        | Discussion comment is attacker-controlled          |
| `push`                         | 1.0        | Requires direct push access                        |
| `pull_request`                 | 1.0        | Sandboxed; no write token from forks               |
| `schedule`                     | 1.0        | No external attacker input                         |
| `workflow_dispatch`            | 0.8        | Requires explicit repo write permission            |
| *(any unlisted trigger)*       | 1.0        | Conservative default                               |

**Multi-trigger rule**: when a workflow declares multiple triggers, the **maximum** multiplier applies.

### Worked Examples — Finding Score

**Example F-1**: CRITICAL finding, trigger = `pull_request_target`
```
severity_weight = 9.0
multiplier      = 1.3
raw             = 9.0 × 1.3 = 11.7
finding_score   = min(10.0, 11.7) = 10.0
```

**Example F-2**: HIGH finding, trigger = `workflow_dispatch`
```
severity_weight = 7.0
multiplier      = 0.8
raw             = 7.0 × 0.8 = 5.6
finding_score   = min(10.0, 5.6) = 5.6
```

**Example F-3**: LOW finding (missing-timeout), trigger = `workflow_dispatch`
```
severity_weight = 2.0
multiplier      = 0.8
raw             = 2.0 × 0.8 = 1.6
finding_score   = min(10.0, 1.6) = 1.6
```

**Example F-4**: MEDIUM finding, triggers = `push` + `pull_request_target` (take max = 1.3)
```
severity_weight = 4.0
multiplier      = max(1.0, 1.3) = 1.3
raw             = 4.0 × 1.3 = 5.2
finding_score   = min(10.0, 5.2) = 5.2
```

---

## 3. Chain Score

A chain links N findings together into an attack path.  The score is higher than any single member because successful chaining amplifies real-world impact.

### Formula

```
chain_multiplier = 1.3  if  N == 2
chain_multiplier = 1.5  if  N >= 3

max_score   = max(member_finding_scores)
rest_scores = sum of all other member_finding_scores (excluding the max)

chain_score = min(10.0,  max_score × chain_multiplier  +  0.25 × rest_scores)
```

The 0.25 coefficient for "rest" scores ensures secondary chain members contribute meaningfully without obscuring the dominant risk.

### Worked Examples — Chain Score

**Example C-1**: 2-member chain, member scores = [9.1, 7.0]
```
N               = 2  →  chain_multiplier = 1.3
max_score       = 9.1
rest_scores     = 7.0
raw             = 9.1 × 1.3  +  0.25 × 7.0
                = 11.83       +  1.75
                = 13.58
chain_score     = min(10.0, 13.58) = 10.0
```

**Example C-2**: 3-member chain, member scores = [7.0, 5.6, 4.0]
```
N               = 3  →  chain_multiplier = 1.5
max_score       = 7.0
rest_scores     = 5.6 + 4.0 = 9.6
raw             = 7.0 × 1.5  +  0.25 × 9.6
                = 10.5        +  2.4
                = 12.9
chain_score     = min(10.0, 12.9) = 10.0
```

**Example C-3**: 2-member chain, member scores = [3.2, 2.0] (small chain)
```
N               = 2  →  chain_multiplier = 1.3
max_score       = 3.2
rest_scores     = 2.0
raw             = 3.2 × 1.3  +  0.25 × 2.0
                = 4.16        +  0.5
                = 4.66
chain_score     = min(10.0, 4.66) = 4.66
```

---

## 4. Repository Score

### Design Choice: Rank-Decayed Probability-Complement Formula

We use a **rank-decayed probability-complement product**:

```
repo_score = 100 × (1 − ∏ᵢ (1 − s₍ᵢ₎/10 × k × rⁱ))
```

where:
- `s₍ᵢ₎` is each score item (chain score or standalone finding score), **sorted in descending order**: $s_{(0)} \ge s_{(1)} \ge \dots \ge s_{(N-1)}$.
- `k = 0.9` is the severity scaling factor (calibrates 1 CRITICAL with neutral trigger to $81.0$).
- `r = 0.8` is the **rank-order exponential decay factor** (`REPO_RANK_DECAY`).
- **No double-counting**: findings that belong to a chain are represented by the chain score only; they are excluded from the standalone list.

### Why Rank Decay? (Viva Defense)

In standard independent-event probability aggregation, $100 \times (1 - \prod (1 - p_i))$, arbitrary volumes of minor findings drive the product to zero, falsely inflating the risk score to 100%. For example, without rank decay, 10 LOW findings would score ~86.3 and 100 INFO findings would score ~99.0, outweighing a single CRITICAL finding at 81.0.

In DevSecOps reality, minor hygiene issues (such as missing timeout or dispatch input) must never outweigh or obscure an exploitable CRITICAL vulnerability (e.g. script injection or vulnerable action).

By sorting findings descending and multiplying by $r^i = 0.8^i$:
1. **Primary vulnerability dominates**: The most severe item ($i=0$) enters with full weight ($0.8^0 = 1.0$).
2. **Strict mathematical asymptote**: Because $\sum_{i=0}^\infty r^i = \frac{1}{1 - 0.8} = 5.0$, the cumulative impact of lower-tier findings is strictly bounded. Even an **infinite** number of LOW findings cannot exceed ~61.3, which is strictly less than 1 CRITICAL (81.0).
3. **Monotonicity**: Adding any finding with score $s \ge 0$ never lowers the repository score.

### Worked Examples — Repository Score

**Example A — Empty repository**
```
score_items = []
repo_score  = 100 × (1 − 1.0)   [empty product = 1]
            = 0.0
```

**Example B — Single CRITICAL finding, trigger = push**
```
finding_score  = min(10, 9.0 × 1.0) = 9.0
score_items    = [9.0]  (standalone, no chain)
Rank i=0:        1 − (9.0/10) × 0.9 × 0.8^0 = 1 − 0.81 = 0.19
product        = 0.19
repo_score     = 100 × (1 − 0.19) = 81.0
```

**Example C — Many LOW findings vs one CRITICAL (Diminishing Returns & Rank Decay)**

Scenario 1: Single CRITICAL (push) → repo_score = 81.0 (from Example B)

Scenario 2: Five LOW findings (push), each score = 2.0
```
Sorted items: [2.0, 2.0, 2.0, 2.0, 2.0]
Rank i=0: 1 − (2.0/10) × 0.9 × 0.8^0 = 1 − 0.18000 = 0.82000
Rank i=1: 1 − (2.0/10) × 0.9 × 0.8^1 = 1 − 0.14400 = 0.85600
Rank i=2: 1 − (2.0/10) × 0.9 × 0.8^2 = 1 − 0.11520 = 0.88480
Rank i=3: 1 − (2.0/10) × 0.9 × 0.8^3 = 1 − 0.09216 = 0.90784
Rank i=4: 1 − (2.0/10) × 0.9 × 0.8^4 = 1 − 0.07373 = 0.92627

product    = 0.82 × 0.856 × 0.8848 × 0.90784 × 0.92627 ≈ 0.52225
repo_score = 100 × (1 − 0.52225) ≈ 47.77
```

Scenario 3: Ten LOW findings (push), each score = 2.0
```
product    ≈ 0.42642
repo_score ≈ 57.36  <  81.0 (1 Critical)
```

Scenario 4: One Hundred INFO findings (push), each score = 0.5
```
product    ≈ 0.79622
repo_score ≈ 20.38  <  81.0 (1 Critical)
```

Both 10 LOWs (57.36) and 100 INFOs (20.38) remain strictly below 1 CRITICAL (81.0). ✓ Diminishing returns and tier hierarchy verified.

**Example D — Chain vs standalone (no double-count)**

Findings: f1 (CRITICAL, score=9.0), f2 (HIGH, score=7.0) — both in chain C1.
Chain score C1 = min(10, 9.0×1.3 + 0.25×7.0) = min(10, 13.58) = 10.0

```
score_items      = [10.0]   ← chain score only; f1 & f2 NOT added again
Rank i=0:          1 − (10.0/10) × 0.9 × 0.8^0 = 1 − 0.9 = 0.1
product          = 0.1
repo_score       = 100 × (1 − 0.1) = 90.0
```

If we had double-counted (added f1=9.0, f2=7.0, chain=10.0):
```
Sorted items: [10.0, 9.0, 7.0]
Rank i=0: 1 − 0.900 = 0.100
Rank i=1: 1 − 0.648 = 0.352
Rank i=2: 1 − 0.403 = 0.597
product ≈ 0.0210
repo_score ≈ 97.90  ← artificially inflated; that's why we don't double-count
```

---

## 5. Rule Severity Justification (all 30 rules)

| Rule ID                          | Severity | Justification                                                    |
|----------------------------------|----------|------------------------------------------------------------------|
| R001 (unpinned-action)           | HIGH     | Supply-chain takeover via tag mutation                           |
| R002 (missing-permissions)       | HIGH     | Overly-broad token scope enables lateral movement               |
| R003 (script-injection)          | CRITICAL | Direct code execution from attacker-controlled input            |
| R004 (pull-request-target)       | CRITICAL | Write-token exposure to untrusted forks                         |
| R005 (env-var-injection)         | HIGH     | Env pollution escalates to code execution                       |
| R006 (workflow-run-trigger)      | MEDIUM   | Fork elevation, mitigated by explicit token restriction         |
| R007 (secrets-in-env)            | MEDIUM   | Credential leak via log exposure                                |
| R008 (self-hosted-runner)        | MEDIUM   | Shared runner contamination risk                                |
| R009 (upload-artifact)           | HIGH     | Exfil vector; depends on subsequent download                    |
| R010 (create-or-update-workflow) | MEDIUM   | Workflow tampering requires write permission                    |
| persist-credentials              | HIGH     | Long-lived credential in .git/config enables clone abuse        |
| secret-to-unpinned-action        | HIGH     | Unpinned action can read injected secret                        |
| overprovisioned-secrets          | MEDIUM   | Unnecessary secret exposure increases blast radius              |
| artifact-leak                    | HIGH     | Artifact publicly downloadable; may contain secrets             |
| secrets-inherit                  | MEDIUM   | Child workflow inherits all parent secrets unnecessarily         |
| github-env-injection             | HIGH     | Attacker appends to GITHUB_ENV → next-step env poisoning        |
| workflow-run-untrusted-artifact  | HIGH     | Artifact from fork downloaded and executed in write context     |
| comment-trigger-no-auth          | HIGH     | PR comment triggers privileged workflow without authz check      |
| dispatch-input-injection         | LOW      | Manual dispatch only; exploitability severely limited           |
| bot-actor-spoofing               | MEDIUM   | Attacker mimics bot username to bypass conditional checks        |
| unpinned-reusable-workflow       | HIGH     | Reusable workflow tag drift = supply-chain attack surface        |
| unpinned-docker-image            | MEDIUM   | Docker tag mutable; image swap risk lower than action swap       |
| curl-pipe-shell                  | HIGH     | Remote code execution at build time                             |
| insecure-commands-enabled        | HIGH     | Deprecated ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables injection |
| cache-poisoning-risk             | HIGH     | Cache key collision can inject malicious artifacts              |
| oidc-write-untrusted             | HIGH     | id-token write permission granted to untrusted workflow         |
| permissions-overbroad-job        | MEDIUM   | Job has write on all scopes; principle of least privilege        |
| continue-on-error-security-step  | MEDIUM   | Security step failure silently ignored                          |
| missing-timeout                  | LOW      | DoS / cost only; no confidentiality/integrity impact            |
| known-vulnerable-action          | CRITICAL | CVE-confirmed RCE / secret-exfil via known vulnerable version   |

---

## 6. ScoringResult Structure

```python
@dataclass
class ScoringResult:
    finding_scores: dict[str, float]      # finding_id → score (0–10)
    chain_scores: dict[str, float]        # chain_id → score (0–10)
    repo_score: float                      # 0–100
    severity_distribution: dict[str, int]  # e.g. {"CRITICAL": 1, "HIGH": 3}
    breakdown: list[dict]                  # transparent item-level detail
```

---

## 7. Constants Summary

```
SEVERITY_WEIGHTS   = {CRITICAL: 9, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 0.5}
HIGH_RISK_TRIGGERS = {pull_request_target, issue_comment, workflow_run,
                      issues, pull_request_review_comment, discussion,
                      discussion_comment}  → multiplier 1.3
LOW_RISK_TRIGGERS  = {workflow_dispatch}  → multiplier 0.8
DEFAULT_MULTIPLIER = 1.0
CHAIN_MULTIPLIER_2 = 1.3
CHAIN_MULTIPLIER_3 = 1.5
REPO_DECAY_K       = 0.9
REPO_RANK_DECAY    = 0.8
```
