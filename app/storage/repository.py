"""Repository interface for scan persistence and querying."""

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.config import Config
from app.storage.db import get_db_connection, init_db, transaction
from app.storage.errors import RecordNotFoundError


def synthetic_repo_identity(source_type: str, target: str) -> tuple[str, str | None]:
    """Generate deterministic synthetic repository name and URL for non-GitHub sources.

    - pasted_yaml: synthetic name 'pasted-yaml:<sha256(content)[:12]>', URL 'pasted://inline'
    - local_directory: synthetic name 'local:<dir_name>', URL 'file://<path>'
    - github_repo: returns (target, target_url)
    """
    if source_type == "pasted_yaml":
        content_hash = hashlib.sha256(target.encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"pasted-yaml:{content_hash}", "pasted://inline"
    if source_type == "local_directory":
        norm_name = Path(target).name or "local-dir"
        return f"local:{norm_name}", f"file://{target}"
    return target, None


class ScanRepository:
    """Manages transactional persistence for scans, findings, chains, and explanations."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        conn: sqlite3.Connection | None = None,
    ):
        self._conn = conn
        self.db_path = (
            str(db_path) if db_path is not None else (Config.DATABASE_PATH if conn is None else ":memory:")
        )
        if self._conn is None:
            if self.db_path == ":memory:":
                self._conn = get_db_connection(":memory:")
                schema_file = Path(__file__).resolve().parent / "schema.sql"
                self._conn.executescript(schema_file.read_text(encoding="utf-8"))
                self._conn.commit()
            else:
                init_db(self.db_path)

    def _connect(self) -> sqlite3.Connection:
        """Obtain a database connection."""
        if self._conn is not None:
            return self._conn
        return get_db_connection(self.db_path)

    def _close_if_ephemeral(self, conn: sqlite3.Connection) -> None:
        """Close connection if it was opened ephemerally."""
        if self._conn is None:
            conn.close()

    def get_or_create_repo(self, name: str, url: str | None = None) -> str:
        """Retrieve existing repository ID by name, or insert and return a new one."""
        conn = self._connect()
        try:
            with transaction(conn):
                row = conn.execute("SELECT id FROM repos WHERE name = ?;", (name,)).fetchone()
                if row:
                    return str(row["id"])

                repo_id = f"repo-{uuid.uuid4().hex[:12]}"
                conn.execute(
                    "INSERT INTO repos (id, name, url) VALUES (?, ?, ?);",
                    (repo_id, name, url),
                )
                return repo_id
        finally:
            self._close_if_ephemeral(conn)

    def get_repo(self, repo_id: str) -> dict[str, Any] | None:
        """Retrieve repository record by ID."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM repos WHERE id = ?;", (repo_id,)).fetchone()
            return dict(row) if row else None
        finally:
            self._close_if_ephemeral(conn)

    def get_repo_by_name(self, name: str) -> dict[str, Any] | None:
        """Retrieve repository record by name."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM repos WHERE name = ?;", (name,)).fetchone()
            return dict(row) if row else None
        finally:
            self._close_if_ephemeral(conn)

    def list_repos(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """List registered repositories with summary statistics and scan counts."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT r.id, r.name, r.url, r.created_at,
                       COUNT(s.id) AS scan_count,
                       MAX(s.scanned_at) AS latest_scan_at,
                       (SELECT repo_score FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, rowid DESC LIMIT 1) AS latest_score,
                       (SELECT risk_level FROM scans WHERE repo_id = r.id ORDER BY scanned_at DESC, rowid DESC LIMIT 1) AS latest_risk_level
                FROM repos r
                LEFT JOIN scans s ON r.id = s.repo_id
                GROUP BY r.id
                ORDER BY (latest_scan_at IS NULL), latest_scan_at DESC, r.created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            self._close_if_ephemeral(conn)

    def save_scan(self, repo_id: str, scan_data: dict[str, Any]) -> str:
        """Persist a completed scan and all its child entities in a single atomic transaction.

        If any error occurs during saving scan metadata, findings, chains, or explanations,
        the entire transaction rolls back completely and a StorageError is raised.
        """
        conn = self._connect()
        try:
            with transaction(conn):
                # Verify repository exists
                repo_check = conn.execute(
                    "SELECT id FROM repos WHERE id = ?;", (repo_id,)
                ).fetchone()
                if not repo_check:
                    raise RecordNotFoundError(f"Repository with ID '{repo_id}' not found.")

                scan_id = scan_data.get("id") or f"scan-{uuid.uuid4().hex[:12]}"
                repo_score = float(scan_data.get("repo_score", 0.0))

                # Determine risk level deterministically if not supplied
                risk_level = scan_data.get("risk_level")
                if not risk_level:
                    if repo_score >= 75.0:
                        risk_level = "CRITICAL"
                    elif repo_score >= 50.0:
                        risk_level = "HIGH"
                    elif repo_score >= 25.0:
                        risk_level = "MEDIUM"
                    else:
                        risk_level = "LOW"

                findings = scan_data.get("findings", [])
                chains = scan_data.get("chains", [])
                explanations = scan_data.get("explanations", {})
                workflows = scan_data.get("workflows", [])

                finding_count = int(scan_data.get("finding_count", len(findings)))
                chain_count = int(scan_data.get("chain_count", len(chains)))
                source_type = str(scan_data.get("source_type", "local"))

                # Severity distribution
                sev_dist = scan_data.get("severity_distribution")
                if not sev_dist:
                    sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                    for f in findings:
                        sev = getattr(f, "severity", None) or (
                            f.get("severity") if isinstance(f, dict) else "LOW"
                        )
                        sev_str = sev.value if hasattr(sev, "value") else str(sev)
                        sev_dist[sev_str] = sev_dist.get(sev_str, 0) + 1

                severity_dist_json = json.dumps(sev_dist)

                # 1. Insert scan record
                conn.execute(
                    """
                    INSERT INTO scans (
                        id, repo_id, commit_sha, ref, repo_score, risk_level,
                        finding_count, chain_count, source_type, severity_dist_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        scan_id,
                        repo_id,
                        scan_data.get("commit_sha"),
                        scan_data.get("ref"),
                        repo_score,
                        risk_level,
                        finding_count,
                        chain_count,
                        source_type,
                        severity_dist_json,
                    ),
                )

                # Index explanations by finding_id for fast lookup
                explanations_by_finding: dict[str, Any] = {}
                if isinstance(explanations, dict):
                    explanations_by_finding = explanations
                elif isinstance(explanations, list):
                    for exp in explanations:
                        fid = getattr(exp, "finding_id", None) or (
                            exp.get("finding_id") if isinstance(exp, dict) else None
                        )
                        if fid:
                            explanations_by_finding[fid] = exp

                # 2. Insert findings
                seen_f_ids = set()
                db_id_by_fid: dict[str, str] = {}

                for f in findings:
                    if isinstance(f, dict):
                        raw_f_id = f.get("id") or f"find-{uuid.uuid4().hex[:12]}"
                        rule_id = str(f.get("rule_id", ""))
                        title = str(f.get("title", rule_id))
                        sev = f.get("severity", "LOW")
                        severity = sev.value if hasattr(sev, "value") else str(sev)
                        file_path = str(f.get("file_path") or f.get("file") or "")
                        job_id = f.get("job_id") or f.get("job")
                        step_id = f.get("step_id") or f.get("step")
                        line_number = int(f.get("line_number", f.get("line", 1)))
                        evidence = str(f.get("evidence", ""))
                        tags = f.get("tags", [])
                        base_score = float(f.get("base_score", 0.0))
                        fingerprint = f.get("fingerprint")
                    else:
                        raw_f_id = getattr(f, "id", None) or f"find-{uuid.uuid4().hex[:12]}"
                        rule_id = str(getattr(f, "rule_id", ""))
                        title = str(getattr(f, "title", rule_id))
                        sev = getattr(f, "severity", "LOW")
                        severity = sev.value if hasattr(sev, "value") else str(sev)
                        file_path = str(getattr(f, "file", None) or getattr(f, "file_path", ""))
                        job_id = getattr(f, "job", None) or getattr(f, "job_id", None)
                        step_id = getattr(f, "step", None) or getattr(f, "step_id", None)
                        line_number = int(getattr(f, "line", 1))
                        evidence = str(getattr(f, "evidence", ""))
                        tags = getattr(f, "tags", [])
                        base_score = float(getattr(f, "base_score", 0.0))
                        fingerprint = getattr(f, "fingerprint", None)

                    # Disambiguate if duplicate ID within the same scan
                    f_id = raw_f_id
                    ctr = 1
                    while f_id in seen_f_ids:
                        ctr += 1
                        f_id = f"{raw_f_id}-{ctr}"
                    seen_f_ids.add(f_id)

                    # Global unique database ID scoped by scan_id
                    db_finding_id = f"{scan_id}:{f_id}"
                    db_id_by_fid[raw_f_id] = db_finding_id
                    db_id_by_fid[f_id] = db_finding_id

                    if not fingerprint:
                        if hasattr(f, "compute_fingerprint"):
                            fingerprint = f.compute_fingerprint()
                        else:
                            step_val = step_id or ""
                            sig = f"{rule_id}:{file_path}:{job_id or ''}:{step_val}:{evidence}"
                            fingerprint = hashlib.sha256(sig.encode("utf-8", errors="replace")).hexdigest()[:16]

                    tags_json = json.dumps(tags)

                    # Attached explanation if present
                    exp_obj = explanations_by_finding.get(raw_f_id) or explanations_by_finding.get(f_id)
                    exp_json = None
                    if exp_obj:
                        exp_dict = {
                            "what": getattr(exp_obj, "what", None) or (
                                exp_obj.get("what") if isinstance(exp_obj, dict) else ""
                            ),
                            "why": getattr(exp_obj, "why", None) or (
                                exp_obj.get("why") if isinstance(exp_obj, dict) else ""
                            ),
                            "how": getattr(exp_obj, "how", None) or (
                                exp_obj.get("how") if isinstance(exp_obj, dict) else ""
                            ),
                            "fix_diff": getattr(exp_obj, "fix_diff", None) or (
                                exp_obj.get("fix_diff") if isinstance(exp_obj, dict) else ""
                            ),
                            "source": getattr(exp_obj, "source", None) or (
                                exp_obj.get("source") if isinstance(exp_obj, dict) else "template"
                            ),
                        }
                        exp_json = json.dumps(exp_dict)

                    conn.execute(
                        """
                        INSERT INTO findings (
                            id, scan_id, rule_id, title, severity, file_path, job_id, step_id,
                            line_number, evidence, tags_json, base_score, fingerprint, explanation_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            db_finding_id,
                            scan_id,
                            rule_id,
                            title,
                            severity,
                            file_path,
                            job_id,
                            step_id,
                            line_number,
                            evidence,
                            tags_json,
                            base_score,
                            fingerprint,
                            exp_json,
                        ),
                    )

                # 3. Insert explanations table
                for fid, exp in explanations_by_finding.items():
                    exp_id = f"expl-{uuid.uuid4().hex[:12]}"
                    target_finding_db_id = db_id_by_fid.get(fid)
                    if not target_finding_db_id:
                        continue

                    what = getattr(exp, "what", "") or (
                        exp.get("what", "") if isinstance(exp, dict) else ""
                    )
                    why = getattr(exp, "why", "") or (
                        exp.get("why", "") if isinstance(exp, dict) else ""
                    )
                    how = getattr(exp, "how", "") or (
                        exp.get("how", "") if isinstance(exp, dict) else ""
                    )
                    fix_diff = getattr(exp, "fix_diff", "") or (
                        exp.get("fix_diff", "") if isinstance(exp, dict) else ""
                    )
                    source = getattr(exp, "source", "template") or (
                        exp.get("source", "template") if isinstance(exp, dict) else "template"
                    )

                    conn.execute(
                        """
                        INSERT INTO explanations (
                            id, scan_id, finding_id, what, why, how, fix_diff, source
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (exp_id, scan_id, target_finding_db_id, what, why, how, fix_diff, source),
                    )

                # 4. Insert chains
                seen_c_ids = set()
                for c in chains:
                    if isinstance(c, dict):
                        raw_c_id = c.get("id") or f"chain-{uuid.uuid4().hex[:12]}"
                        ctype = c.get("chain_type", "UNKNOWN")
                        chain_type = ctype.value if hasattr(ctype, "value") else str(ctype)
                        finding_ids = c.get("finding_ids", [])
                        job_id = c.get("job_id")
                        nodes = c.get("nodes", [])
                        edges = c.get("edges", [])
                        graph = c.get("graph_json") or c.get("graph") or {"nodes": nodes, "edges": edges}
                        narrative = str(c.get("narrative", ""))
                        chain_score = float(c.get("chain_score", 0.0))
                    else:
                        raw_c_id = getattr(c, "id", None) or f"chain-{uuid.uuid4().hex[:12]}"
                        ctype = getattr(c, "chain_type", "UNKNOWN")
                        chain_type = ctype.value if hasattr(ctype, "value") else str(ctype)
                        finding_ids = getattr(c, "finding_ids", [])
                        job_id = getattr(c, "job_id", None)
                        nodes = getattr(c, "nodes", [])
                        edges = getattr(c, "edges", [])
                        graph = getattr(c, "graph", None) or {"nodes": nodes, "edges": edges}
                        narrative = str(getattr(c, "narrative", ""))
                        chain_score = float(getattr(c, "chain_score", 0.0))

                    c_id = raw_c_id
                    ctr = 1
                    while c_id in seen_c_ids:
                        ctr += 1
                        c_id = f"{raw_c_id}-{ctr}"
                    seen_c_ids.add(c_id)
                    db_chain_id = f"{scan_id}:{c_id}"

                    graph_json = json.dumps(graph) if not isinstance(graph, str) else graph

                    conn.execute(
                        """
                        INSERT INTO chains (
                            id, scan_id, chain_type, finding_ids_json, job_id,
                            nodes_json, edges_json, graph_json, narrative, chain_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            db_chain_id,
                            scan_id,
                            chain_type,
                            json.dumps(finding_ids),
                            job_id,
                            json.dumps(nodes),
                            json.dumps(edges),
                            graph_json,
                            narrative,
                            chain_score,
                        ),
                    )

                # 5. Insert optional workflows catalog
                for wf in workflows:
                    wf_id = getattr(wf, "id", None) or (
                        wf.get("id") if isinstance(wf, dict) else f"wf-{uuid.uuid4().hex[:12]}"
                    )
                    file_path = getattr(wf, "file_path", "") or (
                        wf.get("file_path", "") if isinstance(wf, dict) else ""
                    )
                    wf_name = getattr(wf, "name", "") or (
                        wf.get("name", "") if isinstance(wf, dict) else ""
                    )
                    triggers = getattr(wf, "triggers", {}) or (
                        wf.get("triggers", {}) if isinstance(wf, dict) else {}
                    )
                    raw = getattr(wf, "raw_content", "") or (
                        wf.get("raw_content", "") if isinstance(wf, dict) else ""
                    )
                    line_count = (
                        len(raw.splitlines())
                        if raw
                        else (wf.get("line_count", 0) if isinstance(wf, dict) else 0)
                    )

                    conn.execute(
                        """
                        INSERT INTO workflows (
                            id, scan_id, file_path, name, triggers_json, line_count
                        ) VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (wf_id, scan_id, file_path, wf_name, json.dumps(triggers), line_count),
                    )

                return scan_id
        finally:
            self._close_if_ephemeral(conn)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve complete scan record including findings, chains, and explanations."""
        conn = self._connect()
        try:
            scan_row = conn.execute(
                """
                SELECT s.*, r.name as repo_name, r.url as repo_url
                FROM scans s
                JOIN repos r ON s.repo_id = r.id
                WHERE s.id = ?;
                """,
                (scan_id,),
            ).fetchone()

            if not scan_row:
                return None

            # Retrieve explanations
            expl_rows = conn.execute(
                "SELECT * FROM explanations WHERE scan_id = ?;", (scan_id,)
            ).fetchall()
            explanations_by_finding: dict[str, dict[str, Any]] = {}
            for er in expl_rows:
                clean_fid = er["finding_id"].split(":", 1)[1] if ":" in er["finding_id"] else er["finding_id"]
                explanations_by_finding[clean_fid] = {
                    "id": er["id"],
                    "finding_id": clean_fid,
                    "what": er["what"],
                    "why": er["why"],
                    "how": er["how"],
                    "fix_diff": er["fix_diff"],
                    "source": er["source"],
                }

            # Retrieve findings
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number ASC, id ASC;",
                (scan_id,),
            ).fetchall()
            findings = []
            for fr in finding_rows:
                f_dict = dict(fr)
                clean_id = fr["id"].split(":", 1)[1] if ":" in fr["id"] else fr["id"]
                f_dict["id"] = clean_id
                f_dict["tags"] = json.loads(fr["tags_json"]) if fr["tags_json"] else []
                f_dict["explanation"] = (
                    json.loads(fr["explanation_json"])
                    if fr["explanation_json"]
                    else explanations_by_finding.get(clean_id)
                )
                findings.append(f_dict)

            # Retrieve chains
            chain_rows = conn.execute(
                "SELECT * FROM chains WHERE scan_id = ? ORDER BY chain_score DESC, id ASC;",
                (scan_id,),
            ).fetchall()
            chains = []
            for cr in chain_rows:
                c_dict = dict(cr)
                clean_cid = cr["id"].split(":", 1)[1] if ":" in cr["id"] else cr["id"]
                c_dict["id"] = clean_cid
                c_dict["finding_ids"] = (
                    json.loads(cr["finding_ids_json"]) if cr["finding_ids_json"] else []
                )
                c_dict["nodes"] = json.loads(cr["nodes_json"]) if cr["nodes_json"] else []
                c_dict["edges"] = json.loads(cr["edges_json"]) if cr["edges_json"] else []
                c_dict["graph"] = (
                    json.loads(cr["graph_json"])
                    if cr["graph_json"]
                    else {"nodes": c_dict["nodes"], "edges": c_dict["edges"]}
                )
                chains.append(c_dict)

            sev_dist = (
                json.loads(scan_row["severity_dist_json"])
                if scan_row["severity_dist_json"]
                else {}
            )

            return {
                "id": scan_row["id"],
                "repo_id": scan_row["repo_id"],
                "repo_name": scan_row["repo_name"],
                "repo_url": scan_row["repo_url"],
                "commit_sha": scan_row["commit_sha"],
                "ref": scan_row["ref"],
                "scanned_at": scan_row["scanned_at"],
                "repo_score": scan_row["repo_score"],
                "risk_level": scan_row["risk_level"],
                "finding_count": scan_row["finding_count"],
                "chain_count": scan_row["chain_count"],
                "source_type": scan_row["source_type"],
                "severity_distribution": sev_dist,
                "findings": findings,
                "chains": chains,
                "explanations": explanations_by_finding,
            }
        finally:
            self._close_if_ephemeral(conn)

    def list_scans(
        self,
        repo_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List historical scans ordered by recency."""
        conn = self._connect()
        try:
            if repo_id:
                rows = conn.execute(
                    """
                    SELECT s.*, r.name as repo_name, r.url as repo_url
                    FROM scans s
                    JOIN repos r ON s.repo_id = r.id
                    WHERE s.repo_id = ?
                    ORDER BY s.scanned_at DESC, s.rowid DESC
                    LIMIT ? OFFSET ?;
                    """,
                    (repo_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT s.*, r.name as repo_name, r.url as repo_url
                    FROM scans s
                    JOIN repos r ON s.repo_id = r.id
                    ORDER BY s.scanned_at DESC, s.rowid DESC
                    LIMIT ? OFFSET ?;
                    """,
                    (limit, offset),
                ).fetchall()

            results = []
            for r in rows:
                row_dict = dict(r)
                row_dict["severity_distribution"] = (
                    json.loads(r["severity_dist_json"]) if r["severity_dist_json"] else {}
                )
                results.append(row_dict)
            return results
        finally:
            self._close_if_ephemeral(conn)

    def get_history(self, repo_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve scan history for a repository ordered chronologically (oldest to newest)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT id, repo_id, commit_sha, ref, scanned_at, repo_score, risk_level,
                       finding_count, chain_count, source_type, severity_dist_json
                FROM scans
                WHERE repo_id = ?
                ORDER BY scanned_at ASC, rowid ASC
                LIMIT ?;
                """,
                (repo_id, limit),
            ).fetchall()

            history = []
            for r in rows:
                sev_dist = (
                    json.loads(r["severity_dist_json"]) if r["severity_dist_json"] else {}
                )
                history.append(
                    {
                        "scan_id": r["id"],
                        "repo_id": r["repo_id"],
                        "commit_sha": r["commit_sha"],
                        "ref": r["ref"],
                        "scanned_at": r["scanned_at"],
                        "repo_score": r["repo_score"],
                        "risk_level": r["risk_level"],
                        "finding_count": r["finding_count"],
                        "chain_count": r["chain_count"],
                        "source_type": r["source_type"],
                        "severity_distribution": sev_dist,
                    }
                )
            return history
        finally:
            self._close_if_ephemeral(conn)

    def compare_scans(self, scan_a_id: str, scan_b_id: str) -> dict[str, Any]:
        """Compare two scans (scan_a: baseline/older, scan_b: target/newer).

        Returns:
            dict containing:
            - previous_scan & current_scan metadata
            - previous_score, current_score, score_delta
            - new, fixed, and persisting findings (and counts)
            - new, fixed, and persisting chains (and counts)
        """
        scan_a = self.get_scan(scan_a_id)
        if not scan_a:
            raise RecordNotFoundError(f"Baseline scan '{scan_a_id}' not found.")
        scan_b = self.get_scan(scan_b_id)
        if not scan_b:
            raise RecordNotFoundError(f"Target scan '{scan_b_id}' not found.")

        # Findings comparison by fingerprint
        a_findings_by_fp: dict[str, list[dict[str, Any]]] = {}
        for f in scan_a["findings"]:
            a_findings_by_fp.setdefault(f["fingerprint"], []).append(f)

        b_findings_by_fp: dict[str, list[dict[str, Any]]] = {}
        for f in scan_b["findings"]:
            b_findings_by_fp.setdefault(f["fingerprint"], []).append(f)

        all_fps = set(a_findings_by_fp.keys()) | set(b_findings_by_fp.keys())

        new_findings: list[dict[str, Any]] = []
        fixed_findings: list[dict[str, Any]] = []
        persisting_findings: list[dict[str, Any]] = []

        for fp in all_fps:
            a_list = a_findings_by_fp.get(fp, [])
            b_list = b_findings_by_fp.get(fp, [])
            n_a = len(a_list)
            n_b = len(b_list)

            if n_a > 0 and n_b > 0:
                common_count = min(n_a, n_b)
                persisting_findings.extend(b_list[:common_count])
                if n_b > n_a:
                    new_findings.extend(b_list[common_count:])
                elif n_a > n_b:
                    fixed_findings.extend(a_list[common_count:])
            elif n_b > 0:
                new_findings.extend(b_list)
            else:
                fixed_findings.extend(a_list)

        # Chains comparison by chain_type
        a_chains_by_type: dict[str, dict[str, Any]] = {
            c["chain_type"]: c for c in scan_a["chains"]
        }
        b_chains_by_type: dict[str, dict[str, Any]] = {
            c["chain_type"]: c for c in scan_b["chains"]
        }

        all_ctypes = set(a_chains_by_type.keys()) | set(b_chains_by_type.keys())
        new_chains: list[dict[str, Any]] = []
        fixed_chains: list[dict[str, Any]] = []
        persisting_chains: list[dict[str, Any]] = []

        for ct in all_ctypes:
            in_a = ct in a_chains_by_type
            in_b = ct in b_chains_by_type
            if in_a and in_b:
                persisting_chains.append(b_chains_by_type[ct])
            elif in_b:
                new_chains.append(b_chains_by_type[ct])
            else:
                fixed_chains.append(a_chains_by_type[ct])

        previous_score = float(scan_a["repo_score"])
        current_score = float(scan_b["repo_score"])
        score_delta = round(current_score - previous_score, 2)

        return {
            "previous_scan": {
                "id": scan_a["id"],
                "scanned_at": scan_a["scanned_at"],
                "commit_sha": scan_a["commit_sha"],
                "ref": scan_a["ref"],
                "repo_score": previous_score,
                "risk_level": scan_a["risk_level"],
            },
            "current_scan": {
                "id": scan_b["id"],
                "scanned_at": scan_b["scanned_at"],
                "commit_sha": scan_b["commit_sha"],
                "ref": scan_b["ref"],
                "repo_score": current_score,
                "risk_level": scan_b["risk_level"],
            },
            "previous_score": previous_score,
            "current_score": current_score,
            "score_delta": score_delta,
            "new_findings": new_findings,
            "fixed_findings": fixed_findings,
            "persisting_findings": persisting_findings,
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "persisting_count": len(persisting_findings),
            # Direct aliases
            "new": new_findings,
            "fixed": fixed_findings,
            "persisting": persisting_findings,
            "new_chains": new_chains,
            "fixed_chains": fixed_chains,
            "persisting_chains": persisting_chains,
            "new_chains_count": len(new_chains),
            "fixed_chains_count": len(fixed_chains),
            "persisting_chains_count": len(persisting_chains),
        }

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Compute holistic dashboard statistics from stored database records.

        Returns aggregated counts for repos, scans, findings (by severity and rule category/tier),
        average risk scores, and recent scan activity.
        """
        conn = self._connect()
        try:
            total_repos = conn.execute("SELECT COUNT(*) FROM repos;").fetchone()[0]
            total_scans = conn.execute("SELECT COUNT(*) FROM scans;").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings;").fetchone()[0]

            # Severity distribution across all findings
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity;"
            ).fetchall()
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            for row in sev_rows:
                s_key = str(row["severity"]).upper()
                severity_counts[s_key] = row["cnt"]

            # Derive category and tier counts from rule catalogue at read time
            from app.rules import default_registry

            rule_counts_rows = conn.execute(
                "SELECT rule_id, COUNT(*) as cnt FROM findings GROUP BY rule_id;"
            ).fetchall()

            category_counts: dict[str, int] = {}
            tier_counts: dict[str, int] = {"core": 0, "extension": 0}

            for row in rule_counts_rows:
                rid = row["rule_id"]
                cnt = row["cnt"]
                rule_inst = default_registry.get_rule(rid)
                cat = getattr(rule_inst, "category", "Other") if rule_inst else "Other"
                tier = getattr(rule_inst, "tier", "core") if rule_inst else "core"

                category_counts[cat] = category_counts.get(cat, 0) + cnt
                tier_counts[tier] = tier_counts.get(tier, 0) + cnt

            # Average score
            avg_row = conn.execute("SELECT AVG(repo_score) FROM scans;").fetchone()[0]
            avg_score = round(float(avg_row), 2) if avg_row is not None else 0.0

            # Recent activity
            recent_rows = conn.execute(
                """
                SELECT s.id, s.repo_id, r.name as repo_name, s.scanned_at,
                       s.repo_score, s.risk_level, s.finding_count, s.chain_count,
                       s.source_type
                FROM scans s
                JOIN repos r ON s.repo_id = r.id
                ORDER BY s.scanned_at DESC, s.rowid DESC
                LIMIT 5;
                """
            ).fetchall()
            recent_scans = [dict(r) for r in recent_rows]

            return {
                "total_repos": total_repos,
                "total_scans": total_scans,
                "total_findings": total_findings,
                "critical_count": severity_counts.get("CRITICAL", 0),
                "high_count": severity_counts.get("HIGH", 0),
                "severity_counts": severity_counts,
                "category_counts": category_counts,
                "tier_counts": tier_counts,
                "average_repo_score": avg_score,
                "recent_scans": recent_scans,
            }
        finally:
            self._close_if_ephemeral(conn)
