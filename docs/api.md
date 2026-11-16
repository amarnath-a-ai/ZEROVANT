# REST API Specification

**CI/CD Pipeline Security Auditor for Misconfiguration Detection and Explainable Supply-Chain Risk Remediation**  
*Document Version:* 1.0.0  
*Base URL:* `/api`  
*Default Port:* 5000  

---

## 1. Architectural Overview & Security Controls

The CI/CD Pipeline Security Auditor REST API provides automated endpoints for static security analysis, rule catalogue inspection, attack-chain correlation retrieval, historical risk progression tracking, and comparative differential analysis.

### 1.1 Content Negotiation
- **Request Payloads:** All endpoints accepting bodies require `Content-Type: application/json`. Non-JSON payloads are rejected with HTTP 415 `UNSUPPORTED_MEDIA_TYPE`.
- **Response Payloads:** Responses are serialized as UTF-8 encoded `application/json`.

### 1.2 Mandatory Security Headers
Every HTTP response emitted by the application factory (`app/__init__.py`) enforces hardened security headers:
| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'` | Prevents unauthorized cross-origin resource execution. |
| `X-Content-Type-Options` | `nosniff` | Disables MIME type sniffing attacks. |
| `X-Frame-Options` | `DENY` | Prevents framing and clickjacking attacks. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referer leakage to cross-origin destinations. |

### 1.3 Rate Limiting
- **Mechanism:** In-memory, thread-safe sliding-window rate limiter per client IP address.
- **Default Limit:** 60 requests per minute (`RATELIMIT_PER_MINUTE = 60`, `RATELIMIT_WINDOW_SECONDS = 60`).
- **Client IP Resolution:** Derived from `X-Forwarded-For` (first entry) or `request.remote_addr`.
- **Exceeded Threshold Response:** HTTP 429 `RATE_LIMIT_EXCEEDED` accompanied by standard `Retry-After: <seconds>` response header.

### 1.4 Request Size Limits
- **Maximum Request Body:** 2 MB (`MAX_CONTENT_LENGTH = 2 * 1024 * 1024`). Exceeding bodies are terminated with HTTP 413 `PAYLOAD_TOO_LARGE`.
- **Maximum YAML Content:** 1 MB (`MAX_YAML_SIZE = 1 * 1024 * 1024`). Exceeding strings in `yaml` payload return HTTP 413 `PAYLOAD_TOO_LARGE`.

### 1.5 Server-Side Request Forgery (SSRF) Protection
Remote ingestion (`repo_url`) enforces strict network boundary validation:
- **Allowed Scheme:** Strictly `https://`. Unencrypted `http://` is forbidden.
- **Allowed Host:** Strictly `github.com`. Third-party hosts (`gitlab.com`, `evil.com`), private RFC 1918 IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`, `localhost`), and cloud metadata IP (`169.254.169.254`) are rejected with HTTP 400 `INVALID_URL`.
- **Forbidden Constructs:** Embedded credentials (`https://user:pass@github.com/...`), non-standard ports (ports other than 443), and path traversal (`..` or `%2e%2e`) are rejected immediately.
- **Local Filesystem Isolation:** Local path ingestion (`local_path`) is disabled by default in web API mode (`ALLOW_LOCAL_PATH = False`) to prevent Local File Inclusion (LFI).

### 1.6 Log Privacy & Data Redaction
- Request logging automatically redacts tokens from headers (`Authorization`, `X-GitHub-Token`, `token`, `Cookie`) and query parameters (`token`, `key`, `secret`, `auth`, `password`).
- Request logging records metadata summaries (`keys`, `content_length`, `yaml_bytes`) but **never writes raw YAML content** or source tokens to system logs.

---

## 2. Standard Error Envelope & Error Code Registry

All client and server errors return a consistent JSON envelope:

```json
{
  "error": {
    "code": "ERROR_CODE_CONSTANT",
    "message": "Human-readable explanation of the error."
  }
}
```

### 2.1 Error Code Reference
| HTTP Status | Error Code | Description |
|---|---|---|
| **400** | `BAD_REQUEST` | Malformed JSON or invalid query parameter formats. |
| **400** | `MISSING_SOURCE` | Neither `repo_url` nor `yaml` was provided. |
| **400** | `MULTIPLE_SOURCES` | Both `repo_url` and `yaml` were provided simultaneously. |
| **400** | `EMPTY_YAML` | The `yaml` field was empty or consisted solely of whitespace. |
| **400** | `INVALID_URL` | The `repo_url` was invalid, non-HTTPS, or violated SSRF constraints. |
| **400** | `INVALID_YAML` | The `yaml` parameter was not a valid string. |
| **400** | `LOCAL_PATH_DISABLED` | Attempted `local_path` scan while disabled in web API mode. |
| **400** | `MISSING_COMPARISON_TARGETS` | Query parameters `a` or `b` omitted in scan comparison. |
| **400** | `CROSS_REPO_COMPARISON_NOT_ALLOWED` | Scans `a` and `b` do not belong to the same repository. |
| **404** | `NOT_FOUND` | The requested scan, repository, or endpoint route was not found. |
| **413** | `PAYLOAD_TOO_LARGE` | HTTP request body exceeded 2MB or YAML exceeded 1MB. |
| **415** | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type` is not `application/json`. |
| **422** | `UNPROCESSABLE_ENTITY` | Syntactically invalid YAML that cannot be parsed into an AST. |
| **429** | `RATE_LIMIT_EXCEEDED` | Client IP exceeded request allowance within the sliding window. |
| **500** | `STORAGE_ERROR` | Database transaction error during record persistence. |
| **500** | `INTERNAL_SERVER_ERROR` | Unhandled exception encountered during execution. |
| **502** | `UPSTREAM_NOT_FOUND` | Target GitHub repository does not exist (upstream 404). |
| **502** | `UPSTREAM_ERROR` | GitHub API rate limit exceeded or upstream network timeout. |

---

## 3. API Endpoints

### 3.1 Service Health & Metadata

#### `GET /health` or `GET /api/health`
Monitors API availability and returns current service status.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "app": "cicd-auditor",
  "version": "1.0.0"
}
```

---

### 3.2 Catalogue Endpoints

#### `GET /api/rules`
Retrieves static security rule definitions with optional category and tier filtering.

**Query Parameters:**
- `category` *(string, optional)*: Filter by rule category (e.g. `credentials`, `permissions`, `runner`, `triggers`, `actions`).
- `tier` *(string, optional)*: Filter by rule tier (`core` for 25 base rules, `extension` for 5 advanced rules).

**Response `200 OK`:**
```json
{
  "rules": [
    {
      "id": "R001",
      "name": "unpinned-action",
      "title": "Third-party action not pinned to a full-length commit SHA",
      "description": "Third-party action not pinned to a full-length commit SHA. Floating tags can be mutated by adversaries.",
      "severity": "MEDIUM",
      "category": "actions",
      "tier": "core",
      "tags": ["supply-chain", "pinning", "cwe-829"]
    }
  ],
  "total": 30
}
```

---

#### `GET /api/chains`
Retrieves all 10 correlated attack chain definitions, including prerequisites, scopes, and narrative templates.

**Response `200 OK`:**
```json
{
  "chains": [
    {
      "chain_type": "pwn-request",
      "name": "Pwn Request: PR Target Script Injection to Secret Exfiltration",
      "required_rules": ["R003", "R004"],
      "secondary_rules": ["R002", "R006"],
      "scope": "cross_job",
      "trigger_label": "pull_request_target",
      "privilege_label": "write-all / secrets",
      "impact_label": "Arbitrary code execution with write privileges",
      "narrative_template": "Workflow triggered on untrusted pull_request_target checks out untrusted PR head..."
    }
  ],
  "total": 10
}
```

---

#### `GET /api/stats`
Retrieves holistic dashboard summary statistics across all recorded scans and repositories.

**Response `200 OK`:**
```json
{
  "total_repos": 14,
  "total_scans": 42,
  "total_findings": 128,
  "critical_count": 12,
  "high_count": 35,
  "severity_counts": {
    "CRITICAL": 12,
    "HIGH": 35,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 6
  },
  "category_counts": {
    "actions": 40,
    "permissions": 32,
    "credentials": 28,
    "injection": 18,
    "runner": 10
  },
  "tier_counts": {
    "core": 110,
    "extension": 18
  },
  "average_repo_score": 54.32,
  "recent_scans": [
    {
      "id": "scan-7a1b2c3d4e5f",
      "repo_id": "repo-1a2b3c4d5e6f",
      "repo_name": "octocat/hello-world",
      "scanned_at": "2026-11-17 01:30:00",
      "repo_score": 78.4,
      "risk_level": "HIGH",
      "finding_count": 4,
      "chain_count": 1,
      "source_type": "github_repo"
    }
  ]
}
```

---

### 3.3 Scan Execution & Inspection

#### `POST /api/scan`
Triggers a static audit scan synchronously. Evaluates all workflows against 30 detection rules, correlates 10 attack chains, calculates deterministic risk scores, generates unified diff fixes, and persists results transactionally in SQLite.

**Request Headers:**
`Content-Type: application/json`

**Request Body (GitHub Ingestion):**
```json
{
  "repo_url": "https://github.com/octocat/hello-world",
  "ref": "main"
}
```

**Request Body (Inline YAML Ingestion):**
```json
{
  "yaml": "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n"
}
```

**Response `201 Created`:**
```json
{
  "scan_id": "scan-e4d3c2b1a0f9",
  "status": "completed",
  "message": "Scan completed successfully."
}
```

**Error Responses:**
- `400 Bad Request` (`MISSING_SOURCE`, `MULTIPLE_SOURCES`, `EMPTY_YAML`, `INVALID_URL`)
- `413 Payload Too Large` (`PAYLOAD_TOO_LARGE`)
- `415 Unsupported Media Type` (`UNSUPPORTED_MEDIA_TYPE`)
- `422 Unprocessable Entity` (`UNPROCESSABLE_ENTITY` - YAML parse syntax error)
- `502 Bad Gateway` (`UPSTREAM_NOT_FOUND`, `UPSTREAM_ERROR`)

---

#### `GET /api/scans/<scan_id>`
Retrieves complete scan details, including findings sorted by severity and line number, attack chains, and unified diff remediations.

**Response `200 OK`:**
```json
{
  "id": "scan-e4d3c2b1a0f9",
  "repo_id": "repo-9a8b7c6d5e4f",
  "repo_name": "octocat/hello-world",
  "repo_url": "https://github.com/octocat/hello-world",
  "commit_sha": null,
  "ref": "main",
  "scanned_at": "2026-11-17 01:30:15",
  "repo_score": 75.8,
  "risk_level": "HIGH",
  "finding_count": 2,
  "chain_count": 1,
  "source_type": "github_repo",
  "severity_distribution": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "id": "find-112233445566",
      "scan_id": "scan-e4d3c2b1a0f9",
      "rule_id": "R004",
      "title": "Script Injection via untrusted context interpolation",
      "severity": "HIGH",
      "file_path": ".github/workflows/ci.yml",
      "job_id": "build",
      "step_id": null,
      "line_number": 12,
      "evidence": "run: echo ${{ github.event.issue.title }}",
      "tags": ["injection", "cwe-78"],
      "base_score": 7.5,
      "fingerprint": "a1b2c3d4e5f6g7h8",
      "explanation": {
        "what": "Step directly interpolates github.event.issue.title into inline shell script.",
        "why": "Adversaries can craft issue titles containing shell metacharacters to execute arbitrary bash commands.",
        "how": "Pass the context via an environment variable and reference $TITLE safely.",
        "fix_diff": "--- .github/workflows/ci.yml\n+++ .github/workflows/ci.yml\n@@ -11,2 +11,4 @@\n-      - run: echo ${{ github.event.issue.title }}\n+      - env:\n+          TITLE: ${{ github.event.issue.title }}\n+        run: echo \"$TITLE\"\n",
        "source": "template"
      }
    }
  ],
  "chains": [
    {
      "id": "chain-998877665544",
      "scan_id": "scan-e4d3c2b1a0f9",
      "chain_type": "pwn-request",
      "finding_ids": ["find-112233445566", "find-223344556677"],
      "composite_score": 88.5,
      "narrative": "Untrusted pull_request_target trigger combined with script injection leads to code execution with repository write token."
    }
  ]
}
```

---

### 3.4 Repository Management, History & Differential Analysis

#### `GET /api/repos`
Lists registered repositories with scan counts, latest scan timestamps, and current risk ratings.

**Query Parameters:**
- `limit` *(integer, optional, default: 50, max: 100)*: Number of repositories to return.
- `offset` *(integer, optional, default: 0)*: Pagination offset.

**Response `200 OK`:**
```json
{
  "repos": [
    {
      "id": "repo-9a8b7c6d5e4f",
      "name": "octocat/hello-world",
      "url": "https://github.com/octocat/hello-world",
      "created_at": "2026-11-17 01:00:00",
      "scan_count": 3,
      "latest_scan_at": "2026-11-17 01:30:15",
      "latest_score": 42.1,
      "latest_risk_level": "MEDIUM"
    }
  ],
  "total": 1
}
```

---

#### `GET /api/repos/<repo_id>/history`
Retrieves chronological scan progression for a specific repository ordered from oldest to newest.

**Query Parameters:**
- `limit` *(integer, optional, default: 50, max: 100)*: Maximum scan records to return.

**Response `200 OK`:**
```json
{
  "repo_id": "repo-9a8b7c6d5e4f",
  "repo_name": "octocat/hello-world",
  "repo_url": "https://github.com/octocat/hello-world",
  "history": [
    {
      "scan_id": "scan-1",
      "repo_id": "repo-9a8b7c6d5e4f",
      "commit_sha": null,
      "ref": "main",
      "scanned_at": "2026-11-17 01:10:00",
      "repo_score": 85.0,
      "risk_level": "CRITICAL",
      "finding_count": 5,
      "chain_count": 2,
      "source_type": "github_repo",
      "severity_distribution": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 0, "INFO": 0}
    },
    {
      "scan_id": "scan-2",
      "repo_id": "repo-9a8b7c6d5e4f",
      "commit_sha": null,
      "ref": "main",
      "scanned_at": "2026-11-17 01:25:00",
      "repo_score": 35.0,
      "risk_level": "MEDIUM",
      "finding_count": 1,
      "chain_count": 0,
      "source_type": "github_repo",
      "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}
    }
  ],
  "total": 2
}
```

---

#### `GET /api/repos/<repo_id>/compare?a=<baseline_scan_id>&b=<target_scan_id>`
Performs differential analysis between two scans belonging to the repository using stable semantic fingerprints.

**Query Parameters:**
- `a` *(string, required)*: Baseline (older) scan ID.
- `b` *(string, required)*: Target (newer) scan ID.

**Validation Rules:**
- Both parameters `a` and `b` must be provided (`400 MISSING_COMPARISON_TARGETS`).
- Repository `<repo_id>` must exist (`404 NOT_FOUND`).
- Both scans `a` and `b` must exist in storage (`404 NOT_FOUND`).
- Both scans `a` and `b` must have `repo_id == <repo_id>`. Cross-repository comparison is rejected (`400 CROSS_REPO_COMPARISON_NOT_ALLOWED`).

**Response `200 OK`:**
```json
{
  "previous_scan": {
    "id": "scan-1",
    "scanned_at": "2026-11-17 01:10:00",
    "repo_score": 85.0,
    "risk_level": "CRITICAL"
  },
  "current_scan": {
    "id": "scan-2",
    "scanned_at": "2026-11-17 01:25:00",
    "repo_score": 35.0,
    "risk_level": "MEDIUM"
  },
  "previous_score": 85.0,
  "current_score": 35.0,
  "score_delta": -50.0,
  "new_count": 0,
  "fixed_count": 4,
  "persisting_count": 1,
  "new_findings": [],
  "fixed_findings": [
    {
      "rule_id": "R004",
      "title": "Script Injection via untrusted context interpolation",
      "severity": "HIGH",
      "file_path": ".github/workflows/ci.yml",
      "fingerprint": "a1b2c3d4e5f6g7h8"
    }
  ],
  "persisting_findings": [
    {
      "rule_id": "R001",
      "title": "Third-party action not pinned to a full-length commit SHA",
      "severity": "MEDIUM",
      "file_path": ".github/workflows/ci.yml",
      "fingerprint": "e9f8d7c6b5a41234"
    }
  ],
  "new_chains_count": 0,
  "fixed_chains_count": 2,
  "persisting_chains_count": 0
}
```

---

## 4. Verification and Security Validation

The REST API implementation is covered by automated unit and integration tests:
- **Test suite file:** `tests/test_api.py` (20 dedicated test cases)
- **Coverage:**
  - Route availability, root landing metadata, and health responses.
  - Mandatory security headers on all responses.
  - Rule and attack-chain catalogue inspection with query filters (`?category=`, `?tier=`).
  - Dashboard stats computation and aggregation.
  - Ingestion validation (single source, YAML size caps, HTTP body caps).
  - Malformed YAML handling with HTTP 422.
  - In-memory rate limiting with 429 response and `Retry-After` header.
  - SSRF protections across cloud metadata, private subnets, loopbacks, non-HTTPS protocols, non-GitHub domains, and embedded credentials.
  - Request logging redaction of authorization headers, query tokens, and raw YAML bodies.
  - Complete end-to-end integration workflow (`scan -> retrieve -> list repos -> history -> compare`).
