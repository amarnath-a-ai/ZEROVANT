# ZEROVANT Explainability User Study Protocol
## Empirical Evaluation of Remediation Explanations vs. Raw SAST Findings

---

### 1. Executive Summary & Study Purpose
This study protocol evaluates the empirical effectiveness of **ZEROVANT's Structured Explainability Engine** (What, Why, How, unified YAML fix diff) compared to traditional **Raw SAST Tool Output** (e.g., standard single-line rule warnings such as *"template-injection: untrusted expression in run script"*).

The primary hypothesis ($H_1$) states:
> *Providing structured multi-part explanations and unified YAML remediation diffs significantly reduces developer time-to-remediate, improves fix correctness, and increases vulnerability comprehension compared to standard raw static analysis warnings.*

---

### 2. Participant Cohort & Sampling Strategy
- **Sample Size ($n$):** 4 to 5 participants.
- **Participant Profile:** Final-year Computer Science & Engineering students, graduate researchers, or junior DevOps/cloud security engineers with prior knowledge of Git, YAML, and basic CI/CD concepts.
- **Ethics & Consent:** All participants provide voluntary informed consent. Results are anonymized under identifiers `P01` through `P05`. No identifying telemetry or personal data is collected.

---

### 3. Study Design & Counterbalancing
A **within-subjects counterbalanced (Latin Square / ABBA)** experimental design is employed to eliminate task-order and learning biases:

- **Condition A (Baseline SAST):** Participant receives raw finding output (rule ID, file name, line number, single-line error description as produced by conventional linters/Zizmor).
- **Condition B (ZEROVANT Explainable):** Participant receives ZEROVANT's full 4-tier explainability report:
  1. *What happened*: Executive summary of the vulnerability.
  2. *Why it matters*: Root cause analysis and attack-chain blast radius.
  3. *How to fix*: Hardening guidance and principle of least privilege.
  4. *YAML Remediation*: Unified syntactic diff showing exact code replacements.

#### Counterbalanced Group Assignment:
| Participant ID | Group Order | Task 1 | Task 2 | Task 3 | Task 4 |
|:---|:---|:---|:---|:---|:---|
| `P01` | Group 1 | Condition A (Baseline) | Condition B (ZEROVANT) | Condition A (Baseline) | Condition B (ZEROVANT) |
| `P02` | Group 2 | Condition B (ZEROVANT) | Condition A (Baseline) | Condition B (ZEROVANT) | Condition A (Baseline) |
| `P03` | Group 1 | Condition A (Baseline) | Condition B (ZEROVANT) | Condition A (Baseline) | Condition B (ZEROVANT) |
| `P04` | Group 2 | Condition B (ZEROVANT) | Condition A (Baseline) | Condition B (ZEROVANT) | Condition A (Baseline) |
| `P05` | Group 1 | Condition A (Baseline) | Condition B (ZEROVANT) | Condition A (Baseline) | Condition B (ZEROVANT) |

---

### 4. Tasks & Objective Evaluation Rubric

#### Task 1: Script Injection Remediation (`R004`)
- **Workflow Context:** GitHub Actions workflow triggers on `issues: [opened]` and executes `run: echo "Processing ${{ github.event.issue.title }}"`.
- **Condition A Prompt:** `Warning R004 [line 12]: script-injection detected. Untrusted context github.event.issue.title interpolated in run block.`
- **Condition B Prompt:** Full ZEROVANT structured remediation card with unified diff moving the expression to intermediate environment variable `env: ISSUE_TITLE: ${{ github.event.issue.title }}`.
- **Comprehension Questions (1 pt each):**
  1. *Q1.1:* What character sequence allows an attacker to break out of the shell command? (Answer: Double quotes, backticks, `$()`, or newline).
  2. *Q1.2:* Why does moving the expression to an `env:` key prevent injection? (Answer: Environment variables are passed via the execve syscall process table, avoiding shell lexical parsing).
- **Correctness Rubric:** 1.0 = Fix uses `env:` mapping or safe action; 0.5 = Partial quoting without env variable; 0.0 = Vulnerability remains or syntax invalid.

#### Task 2: Pwn-Request Attack-Chain Remediation (`pwn-request`)
- **Workflow Context:** Workflow triggers on `pull_request_target` with write permissions and checks out `ref: ${{ github.event.pull_request.head.sha }}` before executing `npm test`.
- **Condition A Prompt:** `Warning: pull_request_target checkout of PR head detected with write-all permissions.`
- **Condition B Prompt:** ZEROVANT Attack-Chain Remediation detailing the two-stage privilege escalation path and unified diff switching to `pull_request` or restricting permissions to `contents: read`.
- **Comprehension Questions (1 pt each):**
  1. *Q2.1:* In a fork PR, whose repository secrets are accessible under `pull_request_target`? (Answer: The target/base repository secrets, NOT the fork).
  2. *Q2.2:* Which specific configuration change neutralizes the danger while keeping automated CI testing? (Answer: Switch trigger to `pull_request` OR execute untrusted code in an unprivileged isolated workflow).
- **Correctness Rubric:** 1.0 = Safely eliminates untrusted code checkout under privileged token; 0.0 = Leaves token exposed to fork code.

#### Task 3: Missing Environment Protection & Blast Radius (`R008` / `deploy-blast-radius`)
- **Workflow Context:** Production AWS deployment step executing on `push` to `main` without `environment: production` guard.
- **Condition A Prompt:** `Warning R008: Deployment job lacks environment protection rule.`
- **Condition B Prompt:** ZEROVANT remediation specifying GitHub Environment protections (manual approvals, branch protection, OIDC role scoping).
- **Comprehension Questions (1 pt each):**
  1. *Q3.1:* How does configuring `environment: production` restrict unauthorized deployment? (Answer: Enforces required reviewers, deployment branch policies, or environment-scoped secrets).
- **Correctness Rubric:** 1.0 = Added `environment:` block with approval guidance; 0.0 = Omitted.

#### Task 4: Credential Persistence & OIDC Federation (`persist-credentials` / `R007`)
- **Workflow Context:** Workflow uses `actions/checkout@v4` without `persist-credentials: false` followed by static `AWS_ACCESS_KEY_ID` usage.
- **Condition A Prompt:** `Warning: persist-credentials default true. Static cloud credentials detected.`
- **Condition B Prompt:** ZEROVANT diff setting `persist-credentials: false` and migrating to OIDC `aws-actions/configure-aws-credentials` with `role-to-assume`.
- **Comprehension Questions (1 pt each):**
  1. *Q4.1:* Where does `actions/checkout` persist the repository `GITHUB_TOKEN` by default? (Answer: In local `.git/config` on runner disk).
  2. *Q4.2:* What is the security advantage of OIDC short-lived tokens over static AWS access keys? (Answer: Short lifespan, cryptographic JWT claims, no long-lived secrets stored in repository settings).
- **Correctness Rubric:** 1.0 = `persist-credentials: false` added and OIDC explained; 0.0 = Incomplete.

---

### 5. Quantitative & Qualitative Metrics
For each task and participant, record:
1. **Time-to-Remediate ($T_{\text{rem}}$, seconds):** Time elapsed from reading the finding to completing the YAML fix.
2. **Fix Correctness ($C_{\text{fix}}$, 0.0 to 1.0):** Evaluated against rubric.
3. **Comprehension Score ($S_{\text{comp}}$, 0 to 2 points):** Sum of correct comprehension question answers.
4. **Subjective Likert Scale (1 = Strongly Disagree, 5 = Strongly Agree):**
   - *Clarity Rating:* "The tool clearly conveyed what the vulnerability is."
   - *Actionability Rating:* "The guidance made it effortless to write the correct fix."
   - *Confidence Rating:* "I am confident this fix will not break CI operations."

---

### 6. Threats to Validity & Limitations ($n=4\text{--}5$)
1. **Sample Size Constraint:** With $n=4\text{--}5$, this evaluation constitutes a **pilot exploratory study**. Statistical tests (e.g., paired t-test or Wilcoxon signed-rank test) suffer from reduced statistical power ($\beta$) and higher risk of Type II errors.
2. **Participant Background Variance:** Even with counterbalancing, individual differences in familiarity with GitHub Actions syntax can induce variance.
3. **Synthetic Task Simplicity:** Isolated benchmark tasks do not represent complex multi-thousand-line proprietary enterprise pipelines.
4. **Academic Justification:** In final-year capstone evaluations, a rigor-first within-subjects pilot study with objective answer rubrics provides defensible empirical grounding and establishes a reproducible methodology for larger future cohorts.

---

### 7. Study Results & Participant Observations
`[TO BE FILLED AFTER STUDY]`

*(This section will be populated with empirical outcomes upon execution of the study sessions using `analyse_study.py`).*
