"""
Docking Job Intelligence Layer
Monitors docking pipeline: ligand prep -> protein prep -> vina -> ranking
Detects: stalled jobs, failed conversions, scoring failures, queue backlog
"""
import os
import time
import json
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger("sentinel.docking")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://biodockify_user:biodockify_secure_pass@biodockify-postgres:5432/biodockify",
).replace("postgresql+asyncpg://", "postgresql://")

DOCKING_STALLED_HOURS = 4
DOCKING_FAILED_THRESHOLD = 10
DOCKING_QUEUE_BACKLOG = 50

DOCKING_STAGES = [
    "ligand_prep", "protein_prep", "docking", "ranking", "complete",
]

DOCKING_FAILURE_PATTERNS = [
    "conversion failed",
    "pdbqt conversion",
    "vina failed",
    "receptor preparation",
    "ligand preparation",
    "grid box",
    "exhaustiveness",
    "timeout",
    "memory error",
]


class DockingJobMonitor:
    """Domain-aware monitor for docking jobs."""

    def __init__(self):
        self._db_url = DB_URL

    def _get_conn(self):
        if not psycopg2:
            return None
        return psycopg2.connect(self._db_url, cursor_factory=RealDictCursor, connect_timeout=5)

    def get_stalled_jobs(self) -> List[Dict]:
        """Find jobs stuck in same stage too long."""
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
                WHERE status IN ('RUNNING', 'PROVISIONING', 'QUEUED')
                  AND updated_at < NOW() - INTERVAL '%s hours'
                ORDER BY updated_at ASC
                LIMIT 20
            """, (DOCKING_STALLED_HOURS,))
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Docking stalled query failed: {e}")
            return []

    def get_failed_jobs(self, hours: int = 1) -> List[Dict]:
        """Get recently failed docking jobs with error classification."""
        try:
            conn = self._get_conn()
            if not conn:
                return []
            cur = conn.cursor()
            cur.execute("""
                SELECT id, job_id, status, error_message, updated_at
                FROM jobs
                WHERE status = 'FAILED'
                  AND updated_at > NOW() - INTERVAL '%s hours'
                ORDER BY updated_at DESC
                LIMIT 50
            """, (hours,))
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Docking failed query failed: {e}")
            return []

    def get_queue_depth(self) -> int:
        try:
            conn = self._get_conn()
            if not conn:
                return 0
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM jobs WHERE status = 'QUEUED'")
            row = cur.fetchone()
            cur.close()
            conn.close()
            return row["cnt"] if row else 0
        except Exception as e:
            logger.warning(f"Queue depth query failed: {e}")
            return 0

    def get_stage_distribution(self) -> Dict[str, int]:
        """Get count of jobs per stage."""
        try:
            conn = self._get_conn()
            if not conn:
                return {}
            cur = conn.cursor()
            cur.execute("""
                SELECT status, COUNT(*) as cnt
                FROM jobs
                WHERE created_at > NOW() - INTERVAL '24 hours'
                GROUP BY status
            """)
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return {r["status"]: r["cnt"] for r in rows}
        except Exception as e:
            logger.warning(f"Stage distribution query failed: {e}")
            return {}

    def classify_failure(self, error_message: str) -> Tuple[str, float]:
        """Classify docking failure by error pattern."""
        if not error_message:
            return "UNKNOWN_FAILURE", 0.4

        msg = error_message.lower()

        for pattern in DOCKING_FAILURE_PATTERNS:
            if pattern in msg:
                if "conversion" in pattern or "pdbqt" in pattern:
                    return "CONVERSION_FAILED", 0.8
                if "vina" in pattern:
                    return "VINA_EXECUTION_FAILED", 0.9
                if "receptor" in pattern or "ligand" in pattern:
                    return "PREPARATION_FAILED", 0.8
                if "timeout" in pattern:
                    return "TIMEOUT", 0.7
                if "memory" in pattern:
                    return "OOM_DOCKING", 0.9

        return "UNKNOWN_FAILURE", 0.4

    def build_report(self, event_type: str, jobs: List[Dict], extra: Dict = None) -> Optional[Dict]:
        """Build diagnostic report for docking issue."""
        now = int(time.time())

        signals = [event_type]
        confidence = extra.get("confidence", 0.7) if extra else 0.7

        recent_errors = []
        for j in jobs[:5]:
            err = j.get("error_message", "")
            if err:
                recent_errors.append(err[:100])

        return {
            "event_id": hashlib.sha256(f"{event_type}:docking:{now // 60}".encode()).hexdigest()[:16],
            "event_type": event_type,
            "service": "biodockify-docking-worker",
            "severity": "high" if len(jobs) > 3 else "medium",
            "summary": {
                "status": "docking_issue",
                "affected_jobs": len(jobs),
                "job_type": "docking",
            },
            "system_state": {},
            "container_state": {"status": "running", "exit_code": None, "exit_reason": ""},
            "recent_logs": recent_errors[:20],
            "signals": signals,
            "confidence": confidence,
            "timestamp": now,
            "job_context": {
                "job_type": "docking",
                "affected_count": len(jobs),
                "stage_distribution": self.get_stage_distribution(),
                **(extra or {}),
            },
        }

    def check(self) -> List[Dict]:
        """Run full docking check. Returns list of reports to send."""
        reports = []

        stalled = self.get_stalled_jobs()
        if stalled:
            report = self.build_report("JOB_STALLED", stalled, {
                "hours_stalled": round(stalled[0].get("hours_stalled", 0), 1),
                "confidence": 0.85,
            })
            if report:
                reports.append(report)
                logger.warning(f"[DOCKING] {len(stalled)} stalled jobs")

        failed = self.get_failed_jobs(hours=1)
        if len(failed) >= DOCKING_FAILED_THRESHOLD:
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
                logger.warning(f"[DOCKING] {len(failed)} failed jobs, dominant: {dominant}")

        queue_depth = self.get_queue_depth()
        if queue_depth > DOCKING_QUEUE_BACKLOG:
            report = self.build_report("QUEUE_BACKLOG", [], {
                "queue_depth": queue_depth,
                "confidence": 0.9,
            })
            if report:
                reports.append(report)
                logger.warning(f"[DOCKING] Queue backlog: {queue_depth}")

        return reports