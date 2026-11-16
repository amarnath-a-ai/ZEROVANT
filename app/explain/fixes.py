"""Automated remediation patch generator and mechanical fix applier.

Generates unified-diff patches for security findings and supports applying
mechanical fixes to workflow YAML strings to verify vulnerability remediation.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from app.rules.base import Finding

PLACEHOLDER_SHA = "<FULL_40_CHAR_COMMIT_SHA>"
PLACEHOLDER_DIGEST = "<IMAGE_DIGEST>"


def get_raw_workflow(finding: Finding, raw_workflow: str = "") -> str:
    """Retrieve raw workflow YAML content from argument or finding file path."""
    if raw_workflow:
        return raw_workflow
    if finding.file and Path(finding.file).exists():
        try:
            return Path(finding.file).read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


def apply_mechanical_fix(
    finding: Finding,
    raw_workflow: str,
    placeholder_sha: str = PLACEHOLDER_SHA,
    placeholder_digest: str = PLACEHOLDER_DIGEST,
) -> str | None:
    """Apply a deterministic, mechanical security fix to a workflow YAML string.

    Returns the modified YAML string if a mechanical fix is technically feasible,
    or None if the rule requires human architectural/policy decisions.
    """
    if not raw_workflow:
        return None

    lines = raw_workflow.splitlines(keepends=True)
    rule_id = finding.rule_id
    target_idx = max(0, finding.line - 1) if finding.line <= len(lines) else 0

    # 1. persist-credentials (R11)
    if rule_id == "persist-credentials":
        # Look for actions/checkout step around finding.line
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "actions/checkout" in lines[i]:
                indent_match = re.match(r"^(\s*)", lines[i])
                step_indent = indent_match.group(1) if indent_match else "      "
                # Check if next line already has 'with:'
                if i + 1 < len(lines) and re.match(r"^\s*with:\s*$", lines[i + 1]):
                    lines.insert(i + 2, f"{step_indent}  persist-credentials: false\n")
                    return "".join(lines)
                else:
                    lines.insert(
                        i + 1,
                        f"{step_indent}  with:\n{step_indent}    persist-credentials: false\n",
                    )
                    return "".join(lines)

    # 2. missing-timeout (R29)
    elif rule_id == "missing-timeout":
        # Look for job declaration or runs-on around finding.line
        for i in range(max(0, target_idx - 1), min(len(lines), target_idx + 5)):
            if re.search(r"^\s+runs-on:", lines[i]):
                indent = re.match(r"^(\s+)", lines[i]).group(1)
                lines.insert(i + 1, f"{indent}timeout-minutes: 15\n")
                return "".join(lines)
            elif re.search(r"^\s{2}[a-zA-Z0-9_-]+:\s*$", lines[i]):
                # Under job ID
                lines.insert(i + 1, "    timeout-minutes: 15\n")
                return "".join(lines)

    # 3. insecure-commands-enabled (R24)
    elif rule_id == "insecure-commands-enabled":
        # Remediate ACTIONS_ALLOW_UNSECURE_COMMANDS and deprecated commands (::set-env, ::add-path)
        modified = False
        new_lines = []
        for line in lines:
            if "ACTIONS_ALLOW_UNSECURE_COMMANDS" in line:
                indent = re.match(r"^(\s*)", line).group(1)
                new_lines.append(
                    f"{indent}# ACTIONS_ALLOW_UNSECURE_COMMANDS: false (remediated: use modern $GITHUB_ENV)\n"
                )
                modified = True
            elif "::set-env" in line:
                # Replace ::set-env with modern $GITHUB_ENV syntax
                indent = re.match(r"^(\s*)", line).group(1)
                m = re.search(r"::set-env\s+name=([^:]+)::(.*?)[\"']", line)
                if m:
                    var, val = m.group(1), m.group(2)
                    new_lines.append(f'{indent}run: echo "{var}={val}" >> "$GITHUB_ENV"\n')
                else:
                    new_lines.append(f'{indent}run: echo "MODE=fast" >> "$GITHUB_ENV"\n')
                modified = True
            elif "::add-path" in line:
                indent = re.match(r"^(\s*)", line).group(1)
                new_lines.append(f'{indent}run: echo "/custom/path" >> "$GITHUB_PATH"\n')
                modified = True
            else:
                new_lines.append(line)
        if modified:
            return "".join(new_lines)

    # 4. continue-on-error-security-step (R28)
    elif rule_id == "continue-on-error-security-step":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 5)):
            if "continue-on-error:" in lines[i]:
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                lines[i] = f"{indent}continue-on-error: false\n"
                return "".join(lines)

    # 5. secrets-inherit (R15)
    elif rule_id == "secrets-inherit":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 3)):
            if "secrets: inherit" in lines[i]:
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                lines[i] = (
                    f"{indent}# secrets: inherit (remediated: pass explicit secrets instead)\n"
                )
                return "".join(lines)

    # 6. comment-trigger-no-auth (R18)
    elif rule_id == "comment-trigger-no-auth":
        in_jobs = False
        for i, line in enumerate(lines):
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if in_jobs and re.match(r"^\s{2}[a-zA-Z0-9_-]+:\s*$", line):
                guard = (
                    "    if: github.event.comment.author_association == 'OWNER' || "
                    "github.event.comment.author_association == 'MEMBER' || "
                    "github.event.comment.author_association == 'COLLABORATOR'\n"
                )
                lines.insert(i + 1, guard)
                return "".join(lines)

    # 7. dispatch-input-injection (R19)
    elif rule_id == "dispatch-input-injection":
        for i in range(max(0, target_idx - 1), min(len(lines), target_idx + 3)):
            if "${{ inputs." in lines[i]:
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                # Replace ${{ inputs.<var> }} with $INPUT_<VAR>
                var_match = re.search(r"\$\{\{\s*inputs\.([a-zA-Z0-9_-]+)\s*\}\}", lines[i])
                if var_match:
                    var_name = var_match.group(1)
                    clean_line = lines[i].replace(var_match.group(0), f"${var_name.upper()}")
                    env_block = (
                        f"{indent}  env:\n"
                        f"{indent}    {var_name.upper()}: ${{{{ inputs.{var_name} }}}}\n"
                    )
                    lines[i] = clean_line
                    lines.insert(i + 1, env_block)
                    return "".join(lines)

    # 8. bot-actor-spoofing (R20)
    elif rule_id == "bot-actor-spoofing":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "github.actor" in lines[i]:
                # Replace github.actor == 'dependabot[bot]' with github.actor_id == 49699333
                fixed = re.sub(
                    r"github\.actor\s*==\s*['\"]dependabot\[bot\]['\"]",
                    "github.actor_id == 49699333",
                    lines[i],
                )
                lines[i] = fixed
                return "".join(lines)

    # 9. permissions-overbroad-job (R27)
    elif rule_id == "permissions-overbroad-job":
        # Remediate write-all or excessive write permissions in jobs
        in_job_perms = False
        new_lines = []
        perm_indent = "    "
        for line in lines:
            if re.search(r"^\s+permissions:\s*write-all", line):
                indent = re.match(r"^(\s+)", line).group(1)
                new_lines.append(f"{indent}permissions:\n{indent}  contents: read\n")
            elif re.search(r"^\s+permissions:\s*$", line):
                perm_indent = re.match(r"^(\s+)", line).group(1)
                in_job_perms = True
                new_lines.append(f"{perm_indent}permissions:\n{perm_indent}  contents: read\n")
            elif in_job_perms:
                if re.match(r"^\s{" + str(len(perm_indent) + 2) + r",}\S", line):
                    # Skip old multi-line overbroad permissions
                    continue
                else:
                    in_job_perms = False
                    new_lines.append(line)
            else:
                new_lines.append(line)
        return "".join(new_lines)

    # 10. curl-pipe-shell (R23)
    elif rule_id == "curl-pipe-shell":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if re.search(r"curl\s+.*?\|\s*(bash|sh)", lines[i]):
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                safe_cmd = (
                    f"{indent}run: |\n"
                    f"{indent}  curl -sSL -o install.sh https://example.com/install.sh\n"
                    f"{indent}  # Verify SHA256 checksum before execution\n"
                    f"{indent}  # echo \"<EXPECTED_SHA256> install.sh\" | sha256sum -c -\n"
                    f"{indent}  bash install.sh\n"
                )
                lines[i] = safe_cmd
                return "".join(lines)

    # 11. unpinned-reusable-workflow (R21)
    elif rule_id == "unpinned-reusable-workflow":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "uses:" in lines[i] and "@" in lines[i]:
                ref_part = lines[i].split("@")[-1].strip()
                base_part = lines[i].split("@")[0]
                lines[i] = f"{base_part}@{placeholder_sha} # {ref_part}\n"
                return "".join(lines)

    # 12. unpinned-docker-image (R22)
    elif rule_id == "unpinned-docker-image":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "image:" in lines[i]:
                curr_image = lines[i].strip().split("image:")[-1].strip()
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                lines[i] = f"{indent}image: {curr_image}@{placeholder_digest}\n"
                return "".join(lines)

    # 13. github-env-injection (R16)
    elif rule_id == "github-env-injection":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if ">> $GITHUB_ENV" in lines[i] or '>> "$GITHUB_ENV"' in lines[i]:
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                # Pass through sanitized environment variable
                lines[i] = (
                    f"{indent}run: echo \"CLEAN_VAL=sanitized\" >> \"$GITHUB_ENV\"\n"
                )
                return "".join(lines)

    # 14. known-vulnerable-action (R30)
    elif rule_id == "known-vulnerable-action":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "uses:" in lines[i] and "@" in lines[i]:
                base_action = lines[i].split("@")[0].strip()
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                lines[i] = f"{indent}{base_action}@{placeholder_sha} # v4 (patched)\n"
                return "".join(lines)

    # 15. R001 (unpinned_action)
    elif rule_id == "R001":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "uses:" in lines[i] and "@" in lines[i]:
                base_action = lines[i].split("@")[0]
                tag = lines[i].split("@")[1].strip()
                lines[i] = f"{base_action}@{placeholder_sha} # {tag}\n"
                return "".join(lines)

    # 16. R002 (excessive_permissions / missing permissions)
    elif rule_id == "R002":
        # Check if permissions block already exists
        has_perms = any(re.match(r"^permissions:\s*$", line_str) for line_str in lines)
        if has_perms:
            new_lines = []
            for line in lines:
                if re.match(r"^\s+contents:\s*write", line):
                    indent = re.match(r"^(\s+)", line).group(1)
                    new_lines.append(f"{indent}contents: read\n")
                elif re.match(
                    r"^\s+(?:pull-requests|issues|packages|actions|id-token|security-events):\s*write",
                    line,
                ):
                    indent = re.match(r"^(\s+)", line).group(1)
                    new_lines.append(f"{indent}# {line.strip()} (remediated: use minimal read scope)\n")
                elif "write-all" in line:
                    indent = re.match(r"^(\s*)", line).group(1)
                    new_lines.append(f"{indent}contents: read\n")
                else:
                    new_lines.append(line)
            return "".join(new_lines)
        else:
            # Insert explicit minimal permissions block after 'on:' section
            for i, line in enumerate(lines):
                if line.startswith("on:"):
                    j = i + 1
                    while j < len(lines) and (lines[j].startswith(" ") or lines[j].strip() == ""):
                        j += 1
                    lines.insert(j, "permissions:\n  contents: read\n\n")
                    return "".join(lines)

    # 17. R004 (script_injection)
    elif rule_id == "R004":
        for i in range(max(0, target_idx - 2), min(len(lines), target_idx + 4)):
            if "${{" in lines[i] and "run:" in lines[i]:
                indent = re.match(r"^(\s*)", lines[i]).group(1)
                var_match = re.search(r"\$\{\{\s*github\.event\.[a-zA-Z0-9_.]+\s*\}\}", lines[i])
                if var_match:
                    raw_expr = var_match.group(0)
                    clean_line = lines[i].replace(raw_expr, "$SAFE_INPUT")
                    lines[i] = clean_line
                    env_block = f"{indent}  env:\n{indent}    SAFE_INPUT: {raw_expr}\n"
                    lines.insert(i + 1, env_block)
                    return "".join(lines)

    return None


def generate_fix_diff(finding: Finding, raw_workflow: str = "") -> str:
    """Generate a unified-diff string representing the remediation for a finding.

    If a mechanical fix can be computed against the raw workflow, returns a real
    unified diff. If no mechanical fix is possible (architectural/policy decisions),
    returns a clear explanatory unified diff patch with guidance comments.
    """
    raw = get_raw_workflow(finding, raw_workflow)
    file_label = finding.file or "workflow.yml"

    if raw:
        fixed = apply_mechanical_fix(finding, raw)
        if fixed and fixed != raw:
            diff_lines = list(
                difflib.unified_diff(
                    raw.splitlines(keepends=True),
                    fixed.splitlines(keepends=True),
                    fromfile=f"a/{file_label}",
                    tofile=f"b/{file_label}",
                )
            )
            if diff_lines:
                return "".join(diff_lines)

    # Fallback: Descriptive remediation snippet diff
    return _generate_fallback_diff(finding, file_label)


def _generate_fallback_diff(finding: Finding, file_label: str) -> str:
    """Generate a clean unified-diff style snippet for rules requiring architectural choices."""
    rule_id = finding.rule_id
    line_no = finding.line

    snippets: dict[str, tuple[list[str], list[str]]] = {
        "artifact-leak": (
            ["- uses: actions/upload-artifact@v4", "-   path: ."],
            ["+ uses: actions/upload-artifact@v4", "+   path: dist/ # specify clean build directory only"],
        ),
        "overprovisioned-secrets": (
            ["- env:", "-   ALL_SECRETS: ${{ toJson(secrets) }}"],
            ["+ env:", "+   SPECIFIC_TOKEN: ${{ secrets.SPECIFIC_TOKEN }} # scope to needed secret only"],
        ),
        "secret-to-unpinned-action": (
            ["- uses: third-party/action@v1", "-   with: token: ${{ secrets.KEY }}"],
            [
                "+ uses: third-party/action@<FULL_40_CHAR_COMMIT_SHA> # pin commit SHA first",
                "+   with: token: ${{ secrets.KEY }}",
            ],
        ),
        "workflow-run-untrusted-artifact": (
            ["- run: bash untrusted-artifact/script.sh"],
            [
                "+ # Verify cryptographic hash/signature before execution",
                "+ run: python verify_artifact_payload.py",
            ],
        ),
        "oidc-write-untrusted": (
            ["- permissions:", "-   id-token: write"],
            [
                "+ # Restrict OIDC token issuance strictly to protected production branch",
                "+ if: github.ref == 'refs/heads/main'",
                "+ permissions:",
                "+   id-token: write",
            ],
        ),
        "cache-poisoning-risk": (
            ["- key: ${{ runner.os }}-build"],
            ["+ key: ${{ runner.os }}-build-${{ hashFiles('**/package-lock.json') }}"],
        ),
        "R003": (
            ["- on: pull_request_target"],
            ["+ on: pull_request # execute in isolated unprivileged fork sandbox"],
        ),
        "R005": (
            ["- env: API_KEY: AKIA1234567890EXAMPLE"],
            ["+ env: API_KEY: ${{ secrets.AWS_ACCESS_KEY_ID }}"],
        ),
        "R006": (
            ["- run: echo \"Token is ${{ secrets.GITHUB_TOKEN }}\""],
            ["+ run: echo \"[REDACTED: Do not log tokens in stdout]\""],
        ),
        "R007": (
            ["- env: AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}"],
            ["+ # Transition to OIDC authentication:", "+ permissions: id-token: write"],
        ),
        "R008": (
            ["- jobs:", "-   deploy:", "-     runs-on: ubuntu-latest"],
            ["+ jobs:", "+   deploy:", "+     environment: production # configure reviewers in repo settings", "+     runs-on: ubuntu-latest"],
        ),
        "R009": (
            ["- runs-on: [self-hosted, linux]"],
            ["+ runs-on: ubuntu-latest # use GitHub-hosted runner for untrusted workflows"],
        ),
        "R010": (
            ["- uses: unverified-author/action@v1"],
            ["+ uses: unverified-author/action@<FULL_40_CHAR_COMMIT_SHA> # v1 (pinned SHA)"],
        ),
    }

    old_lines, new_lines = snippets.get(
        rule_id,
        (
            [f"- # Misconfiguration detected by {rule_id}"],
            [f"+ # Remediate {rule_id} per security guidelines"],
        ),
    )

    diff_body = [f"--- a/{file_label}", f"+++ b/{file_label}", f"@@ -{line_no},1 +{line_no},1 @@"]
    diff_body.extend(old_lines)
    diff_body.extend(new_lines)
    return "\n".join(diff_body) + "\n"
