"""
MD (Molecular Dynamics) Job Intelligence Layer
Monitors MD pipeline: setup -> simulation -> analysis -> results
Detects: stalled simulations, unstable trajectories, analysis failures
"""
import os
import time
import json
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger("sentinel.md")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://biodockify_user:biodockify_secure_pass@biodockify-postgres:5432/biodockify",
).replace("postgresql+asyncpg://", "postgresql://")

MD_STALLED_HOURS = 8
MD_FAILED_THRESHOLD = 5
MD_QUEUE_BACKLOG = 20

MD_STAGES = [
    "setup", "minimization", "equilibration", "production", "analysis", "complete",
]

MD_FAILURE_PATTERNS = [
    "simulation crashed",
    "energy explosion",
    "nan detected",
    "atom position",
    "constraint error",
    "openmm",
    "gromacs",
    "trajectory corrupted",
    "timeout",
    "memory",
    "disk full",
    "gpu error",
]


class MDJobMonitor:
    """Domain-aware monitor for MD simulations."""

    def __init__(self):
        self._db_url = DB_URL

    def _get_conn(self):
        if not psycopg2:
            return None
        return psycopg2.connect(self._db_url, cursor_factory=RealDictCursor, connect_timeout=5)

    def get_stalled_simulations(self) -> List[Dict]:
        """Find MD jobs stuck in same stage too long."""
        try:
            conn = self._get_conn()
            if not conn:
                return []
            cur = conn.cursor()
            cur.execute("""
                SELECT id, job_id, status, created_at, updated_at,
                       error_message,
                       EXTRACT(EPOCH FROM (NOW() - updated_at)) / 3600 as hours_stalled
                FROM jobs
                WHERE status IN ('RUNNING', 'PROVISIONING')
                  AND (parameters::text LIKE '%md%' OR parameters::text LIKE '%simulation%')
                  AND updated_at < NOW() - INTERVAL '%s hours'
                ORDER BY updated_at ASC
                LIMIT 10
            """, (MD_STALLED_HOURS,))
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"MD stalled query failed: {e}")
            return []

    def get_failed_simulations(self, hours: int = 6) -> List[Dict]:
        """Get recently failed MD jobs."""
        try:
            conn = self._get_conn()
            if not conn:
                return []
            cur = conn.cursor()
            cur.execute("""
                SELECT id, job_id, status, error_message, updated_at,
                       parameters
                FROM jobs
                WHERE status = 'FAILED'
                  AND (parameters::text LIKE '%md%' OR parameters::text LIKE '%simulation%')
                  AND updated_at > NOW() - INTERVAL '%s hours'
                ORDER BY updated_at DESC
                LIMIT 20
            """, (hours,))
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"MD failed query failed: {e}")
            return []

    def get_queue_depth(self) -> int:
        try:
            conn = self._get_conn()
            if not conn:
                return 0
            cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(*) as cnt FROM jobs
                WHERE status = 'QUEUED'
                  AND (parameters::text LIKE '%md%' OR parameters::text LIKE '%simulation%')
            """)
            row = cur.fetchone()
            cur.close()
            conn.close()
            return row["cnt"] if row else 0
        except Exception as e:
            logger.warning(f"MD queue query failed: {e}")
            return 0

    def classify_failure(self, error_message: str) -> Tuple[str, float]:
        """Classify MD failure by error pattern."""
        if not error_message:
            return "UNKNOWN_FAILURE", 0.4

        msg = error_message.lower()

        if "nan" in msg or "energy explosion" in msg:
            return "UNSTABLE_TRAJECTORY", 0.9
        if "constraint" in msg or "atom position" in msg:
            return "CONSTRAINT_VIOLATION", 0.85
        if "openmm" in msg or "gromacs" in msg:
            return "ENGINE_ERROR", 0.8
        if "trajectory" in msg or "corrupted" in msg:
            return "TRAJECTORY_CORRUPTED", 0.85
        if "gpu" in msg:
            return "GPU_ERROR", 0.9
        if "timeout" in msg:
            return "TIMEOUT", 0.7
        if "memory" in msg:
            return "OOM_SIMULATION", 0.9
        if "disk" in msg:
            return "DISK_FULL_SIMULATION", 0.95

        return "UNKNOWN_FAILURE", 0.4

    def build_report(self, event_type: str, jobs: List[Dict], extra: Dict = None) -> Optional[Dict]:
        now = int(time.time())

        signals = [event_type]
        confidence = extra.get("confidence", 0.7) if extra else 0.7

        recent_errors = []
        for j in jobs[:5]:
            err = j.get("error_message", "")
            if err:
                recent_errors.append(err[:100])

        return {
            "event_id": hashlib.sha256(f"{event_type}:md:{now // 60}".encode()).hexdigest()[:16],
            "event_type": event_type,
            "service": "biodockify-md-worker",
            "severity": "high" if len(jobs) > 2 else "medium",
            "summary": {
                "status": "md_issue",
                "affected_jobs": len(jobs),
                "job_type": "md_simulation",
            },
            "system_state": {},
            "container_state": {"status": "running", "exit_code": None, "exit_reason": ""},
            "recent_logs": recent_errors[:20],
            "signals": signals,
            "confidence": confidence,
            "timestamp": now,
            "job_context": {
                "job_type": "md_simulation",
                "affected_count": len(jobs),
                **(extra or {}),
            },
        }

    def check(self) -> List[Dict]:
        """Run full MD check. Returns list of reports to send."""
        reports = []

        stalled = self.get_stalled_simulations()
        if stalled:
            report = self.build_report("JOB_STALLED", stalled, {
                "hours_stalled": round(stalled[0].get("hours_stalled", 0), 1),
                "confidence": 0.85,
            })
            if report:
                reports.append(report)
                logger.warning(f"[MD] {len(stalled)} stalled simulations")

        failed = self.get_failed_simulations(hours=6)
        if len(failed) >= MD_FAILED_THRESHOLD:
            failure_types = {}
            for j in failed:
                ftype, _ = self.classify_failure(j.get("error_message", ""))
                failure_types[ftype] = failure_types.get(ftype, 0) + 1

            dominant = max(failure_types, key=failure_types.get) if failure_types else "UNKNOWN"
            report = self.build_report("JOB_FAILED", failed, {
                "failure_count": len(failed),
                "failure_type": dominant,
                "failure_breakdown": failure_types,
                "confidence": 0.9,
            })
            if report:
                reports.append(report)
                logger.warning(f"[MD] {len(failed)} failed simulations, dominant: {dominant}")

        queue_depth = self.get_queue_depth()
        if queue_depth > MD_QUEUE_BACKLOG:
            report = self.build_report("QUEUE_BACKLOG", [], {
                "queue_depth": queue_depth,
                "confidence": 0.9,
            })
            if report:
                reports.append(report)
                logger.warning(f"[MD] Queue backlog: {queue_depth}")

        return reports