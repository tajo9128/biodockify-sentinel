"""
Sentinel - Production Observer & Diagnostic Reporter

ROLE: Detect real system issues, build structured diagnostic reports,
      and send them to OpenClaw for safe execution.

HARD RULES:
  - NEVER execute any action (no restart, no fix)
  - NEVER send raw logs without filtering
  - NEVER spam duplicate events
  - NEVER send incomplete or malformed reports
  - NEVER trigger on single transient failure
  - If uncertain -> DO NOT emit event

EVENT GENERATION:
  Only emit if:
  - At least 2 signals correlate, OR
  - A critical signal persists for 3 consecutive checks

EVENT TYPES (strict):
  OOM_CRASH, RESTART_LOOP, API_DOWN, CADDY_502, DISK_FULL,
  JOB_STALLED, JOB_FAILED, QUEUE_BACKLOG

CONFIDENCE THRESHOLD:
  - 0.9 -> strong correlation
  - 0.7 -> moderate evidence
  - below 0.6 -> DO NOT emit

DEDUPLICATION:
  - Same event_type + service within 5 minutes -> skip

TEMPORAL VALIDATION:
  - Issue must persist for at least 2-3 checks
  - Ignore short spikes
"""
import os
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import docker
except ImportError:
    import subprocess
    subprocess.run(["pip", "install", "docker"], check=True)
    import docker

try:
    import psutil
except ImportError:
    import subprocess
    subprocess.run(["pip", "install", "psutil"], check=True)
    import psutil

try:
    import requests
except ImportError:
    import subprocess
    subprocess.run(["pip", "install", "requests"], check=True)
    import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENTINEL] %(levelname)s %(message)s"
)
logger = logging.getLogger("sentinel")

SIGNAL_HIGH_MEMORY = "HIGH_MEMORY"
SIGNAL_HIGH_CPU = "HIGH_CPU"
SIGNAL_RESTART_LOOP = "RESTART_LOOP"
SIGNAL_DISK_FULL = "DISK_FULL"
SIGNAL_API_DOWN = "API_DOWN"
SIGNAL_ERROR_LOG = "ERROR_LOG_DETECTED"
SIGNAL_OOM_LOG = "OOM_DETECTED"
SIGNAL_502_LOG = "GATEWAY_502"
SIGNAL_JOB_STALLED = "JOB_STALLED"
SIGNAL_JOB_FAILED = "JOB_FAILED"
SIGNAL_QUEUE_BACKLOG = "QUEUE_BACKLOG"

THRESHOLD_MEMORY_PCT = 85.0
THRESHOLD_CPU_PCT = 90.0
THRESHOLD_DISK_PCT = 90.0
THRESHOLD_RESTART_COUNT = 3
THRESHOLD_STALLED_HOURS = 4
THRESHOLD_QUEUE_BACKLOG = 50

MIN_SIGNALS_FOR_EVENT = 2
MIN_CONFIDENCE_TO_EMIT = 0.6
PERSISTENCE_CHECKS_REQUIRED = 2

EVENT_TYPES = [
    "OOM_CRASH", "RESTART_LOOP", "API_DOWN", "CADDY_502", "DISK_FULL",
    "JOB_STALLED", "JOB_FAILED", "QUEUE_BACKLOG",
]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

LOG_FILTER_KEYWORDS = [
    "error", "exception", "fatal", "oom", "killed", "failed",
    "502", "bad gateway", "stalled", "timeout", "deadlock",
]
LOG_MAX_LINES = 20
LOG_TAIL_SIZE = 100

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://biodockify_user:biodockify_secure_pass@biodockify-postgres:5432/biodockify",
)


class SentinelConfig:
    OPENCLAW_URL = os.getenv("OPENCLAW_URL", "http://biodockify-openclaw:8001")
    CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "120"))
    COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))
    MONITORED_SERVICES = [
        s.strip()
        for s in os.getenv(
            "MONITORED_SERVICES",
            "biodockify-api,biodockify-docking-worker,biodockify-ranking-worker,biodockify-md-worker,caddy-reverse",
        ).split(",")
        if s.strip()
    ]
    AUTO_HEAL = os.getenv("AUTO_HEAL", "true").lower() == "true"
    PERSISTENCE_WINDOW = int(os.getenv("PERSISTENCE_WINDOW", "3"))
    JOB_MONITORING = os.getenv("JOB_MONITORING", "true").lower() == "true"


class DiagnosticReport:
    def __init__(self, data: Dict):
        self.data = data
        self._validate()

    def _validate(self):
        required = ["event_id", "event_type", "service", "severity", "timestamp"]
        for f in required:
            if f not in self.data:
                raise ValueError(f"Missing required field: {f}")
        if self.data["event_type"] not in EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {self.data['event_type']}")
        if self.data["severity"] not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {self.data['severity']}")

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)

    def to_dict(self) -> Dict:
        return self.data.copy()


class PersistenceTracker:
    def __init__(self):
        self._history: Dict[str, List[Dict]] = {}

    def record(self, service: str, signals: List[str], event_type: str):
        key = f"{service}:{event_type}"
        entry = {"signals": signals, "timestamp": time.time()}
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(entry)
        self._history[key] = self._history[key][-10:]

    def get_persistence_count(self, service: str, event_type: str) -> int:
        key = f"{service}:{event_type}"
        if key not in self._history:
            return 0
        return len(self._history[key])

    def clear(self, service: str, event_type: str):
        key = f"{service}:{event_type}"
        if key in self._history:
            del self._history[key]


class FailureMemory:
    """Track failure patterns per service for escalation."""

    def __init__(self):
        self._history: Dict[str, List[Dict]] = {}

    def record(self, service: str, event_type: str):
        key = f"{service}:{event_type}"
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(time.time())
        self._history[key] = self._history[key][-20:]

    def get_count(self, service: str, event_type: str, window_hours: int = 24) -> int:
        key = f"{service}:{event_type}"
        if key not in self._history:
            return 0
        cutoff = time.time() - (window_hours * 3600)
        return len([t for t in self._history[key] if t > cutoff])

    def should_escalate(self, service: str, event_type: str) -> bool:
        return self.get_count(service, event_type, window_hours=1) >= 3


class JobMonitor:
    """Monitor docking and MD jobs using separate intelligence layers."""

    def __init__(self):
        self._docking = None
        self._md = None
        try:
            from sentinel.docking import DockingJobMonitor
            self._docking = DockingJobMonitor()
        except Exception as e:
            logger.warning(f"Docking monitor unavailable: {e}")
        try:
            from sentinel.md import MDJobMonitor
            self._md = MDJobMonitor()
        except Exception as e:
            logger.warning(f"MD monitor unavailable: {e}")

    def check_docking(self) -> List[Dict]:
        if self._docking:
            return self._docking.check()
        return []

    def check_md(self) -> List[Dict]:
        if self._md:
            return self._md.check()
        return []


class Sentinel:
    """Production Observer - detects, classifies, reports. NO execution."""

    def __init__(self, config: SentinelConfig = None):
        self.config = config or SentinelConfig()
        self.docker_client = docker.from_env()
        self.last_events: Dict[str, float] = {}
        self.persistence = PersistenceTracker()
        self.failure_memory = FailureMemory()
        self.job_monitor = JobMonitor() if self.config.JOB_MONITORING else None
        self.stats = {
            "checks": 0,
            "events_detected": 0,
            "events_emitted": 0,
            "events_skipped_cooldown": 0,
            "events_skipped_confidence": 0,
            "events_skipped_persistence": 0,
            "jobs_checked": 0,
            "job_events": 0,
            "send_success": 0,
            "send_failed": 0,
        }

    def check_service(self, service_name: str) -> Optional[Dict]:
        self.stats["checks"] += 1

        try:
            container = self.docker_client.containers.get(service_name)
        except docker.errors.NotFound:
            return self._build_raw_state(service_name, None, signals=[SIGNAL_API_DOWN])
        except Exception as e:
            logger.error(f"Error checking {service_name}: {e}")
            return None

        attrs = container.attrs
        state = attrs.get("State", {})

        container_state = {
            "status": state.get("Status", "unknown"),
            "exit_code": state.get("ExitCode"),
            "exit_reason": state.get("Error", ""),
            "restart_count": attrs.get("RestartCount", 0),
        }

        system_state = self._get_system_metrics()

        raw_logs = ""
        try:
            raw_logs = container.logs(
                tail=LOG_TAIL_SIZE, stderr=True, stdout=True
            ).decode("utf-8", errors="ignore")
        except Exception:
            pass

        filtered_logs = self._filter_logs(raw_logs)

        signals = self._detect_signals(container_state, system_state, filtered_logs)

        return {
            "service": service_name,
            "container_state": container_state,
            "system_state": system_state,
            "filtered_logs": filtered_logs,
            "signals": signals,
            "uptime": self._calculate_uptime(attrs),
        }

    def check_jobs(self):
        """Check docking + MD jobs using separate intelligence layers."""
        if not self.job_monitor:
            return

        self.stats["jobs_checked"] += 1

        docking_reports = self.job_monitor.check_docking()
        for report_data in docking_reports:
            self._send_job_report(report_data, layer="docking")

        md_reports = self.job_monitor.check_md()
        for report_data in md_reports:
            self._send_job_report(report_data, layer="md")

    def _send_job_report(self, report_data: Dict, layer: str = "unknown"):
        """Send a job report from docking/MD layers."""
        try:
            report = DiagnosticReport(report_data)
            if self.send_report(report):
                self.stats["job_events"] += 1
                self.stats["events_emitted"] += 1
                logger.info(
                    f"[EMIT-{layer.upper()}] {report_data.get('event_type')} "
                    f"service={report_data.get('service')} "
                    f"jobs={report_data.get('job_context', {}).get('affected_count', '?')}"
                )
        except Exception as e:
            logger.error(f"{layer} report send failed: {e}")



    def _get_system_metrics(self) -> Dict:
        try:
            return {
                "memory_pct": round(psutil.virtual_memory().percent, 1),
                "cpu_pct": round(psutil.cpu_percent(interval=0.5), 1),
                "disk_pct": round(psutil.disk_usage("/").percent, 1),
            }
        except Exception:
            return {"memory_pct": 0, "cpu_pct": 0, "disk_pct": 0}

    def _filter_logs(self, raw_logs: str) -> List[str]:
        if not raw_logs:
            return []
        lines = raw_logs.split("\n")
        filtered = [
            line.strip()
            for line in lines
            if any(k in line.lower() for k in LOG_FILTER_KEYWORDS)
        ]
        return [l for l in filtered if l][-LOG_MAX_LINES:]

    def _detect_signals(self, container_state: Dict, system_state: Dict, filtered_logs: List[str]) -> List[str]:
        signals = []
        log_text = " ".join(filtered_logs).lower()

        if system_state.get("memory_pct", 0) > THRESHOLD_MEMORY_PCT:
            signals.append(SIGNAL_HIGH_MEMORY)
        if system_state.get("cpu_pct", 0) > THRESHOLD_CPU_PCT:
            signals.append(SIGNAL_HIGH_CPU)
        if system_state.get("disk_pct", 0) > THRESHOLD_DISK_PCT:
            signals.append(SIGNAL_DISK_FULL)
        if container_state.get("restart_count", 0) >= THRESHOLD_RESTART_COUNT:
            signals.append(SIGNAL_RESTART_LOOP)
        if container_state.get("status") == "restarting":
            signals.append(SIGNAL_RESTART_LOOP)
        if container_state.get("exit_code") == 137:
            signals.append(SIGNAL_OOM_LOG)
        if filtered_logs:
            signals.append(SIGNAL_ERROR_LOG)
        if "oom" in log_text or "killed" in log_text:
            signals.append(SIGNAL_OOM_LOG)
        if "502" in log_text or "bad gateway" in log_text:
            signals.append(SIGNAL_502_LOG)
        if container_state.get("exit_code") == 1:
            signals.append(SIGNAL_API_DOWN)

        return list(set(signals))

    def _classify_event(self, signals: List[str], system_state: Dict, filtered_logs: List[str]) -> Tuple[str, str]:
        log_text = " ".join(filtered_logs).lower()

        if SIGNAL_OOM_LOG in signals or (SIGNAL_HIGH_MEMORY in signals and "oom" in log_text):
            return "OOM_CRASH", "critical"
        if SIGNAL_RESTART_LOOP in signals:
            return "RESTART_LOOP", "high"
        if SIGNAL_502_LOG in signals:
            return "CADDY_502", "high"
        if SIGNAL_DISK_FULL in signals:
            return "DISK_FULL", "critical"
        if SIGNAL_API_DOWN in signals:
            return "API_DOWN", "high"

        return "", "medium"

    def _calculate_confidence(self, event_type: str, signals: List[str], filtered_logs: List[str]) -> float:
        if not event_type:
            return 0.0

        score = 0.4
        signal_count = len(signals)

        if signal_count >= 3:
            score += 0.4
        elif signal_count >= 2:
            score += 0.3
        elif signal_count == 1:
            score += 0.1

        log_text = " ".join(filtered_logs).lower()
        if event_type == "OOM_CRASH" and ("oom" in log_text or "killed" in log_text):
            score += 0.2
        if event_type == "CADDY_502" and "502" in log_text:
            score += 0.2
        if event_type == "RESTART_LOOP" and SIGNAL_RESTART_LOOP in signals:
            score += 0.2

        return min(round(score, 2), 1.0)

    def should_emit(self, service: str, event_type: str, confidence: float, signals: List[str]) -> Tuple[bool, str]:
        if not event_type:
            return False, "no_event_type"

        if confidence < MIN_CONFIDENCE_TO_EMIT:
            self.stats["events_skipped_confidence"] += 1
            return False, f"low_confidence_{confidence}"

        persistence_count = self.persistence.get_persistence_count(service, event_type)
        signal_count = len(signals)
        if signal_count < MIN_SIGNALS_FOR_EVENT:
            if persistence_count < PERSISTENCE_CHECKS_REQUIRED:
                self.stats["events_skipped_persistence"] += 1
                return False, f"insufficient_persistence_{persistence_count}"

        key = f"{event_type}:{service}"
        now = time.time()
        if key in self.last_events:
            if now - self.last_events[key] < self.config.COOLDOWN_SECONDS:
                self.stats["events_skipped_cooldown"] += 1
                return False, "cooldown"

        return True, "ok"

    def build_report(self, service: str, event_type: str, severity: str, raw_state: Dict, confidence: float) -> DiagnosticReport:
        now = int(time.time())
        cs = raw_state.get("container_state", {})
        ss = raw_state.get("system_state", {})
        logs = raw_state.get("filtered_logs", [])
        signals = raw_state.get("signals", [])

        escalation = self.failure_memory.should_escalate(service, event_type)
        repeat_count = self.failure_memory.get_count(service, event_type, window_hours=1)

        data = {
            "event_id": self._generate_event_id(event_type, service, now),
            "event_type": event_type,
            "service": service,
            "severity": "critical" if escalation else severity,
            "summary": {
                "status": cs.get("status", "unknown"),
                "restart_count": cs.get("restart_count", 0),
                "uptime_seconds": raw_state.get("uptime", 0),
            },
            "system_state": ss,
            "container_state": {
                "status": cs.get("status", "unknown"),
                "exit_code": cs.get("exit_code"),
                "exit_reason": cs.get("exit_reason", ""),
            },
            "recent_logs": logs[-LOG_MAX_LINES:],
            "signals": signals,
            "confidence": confidence,
            "timestamp": now,
            "escalation": escalation,
            "repeat_count": repeat_count,
        }

        return DiagnosticReport(data)

    def _generate_event_id(self, event_type: str, service: str, ts: int) -> str:
        window = ts // 60
        key = f"{event_type}:{service}:{window}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _calculate_uptime(self, attrs: Dict) -> int:
        try:
            started = attrs.get("State", {}).get("StartedAt")
            if started:
                ts = datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
                return int(time.time() - ts)
        except Exception:
            pass
        return 0

    def _build_raw_state(self, service: str, container, signals: List[str]) -> Dict:
        return {
            "service": service,
            "container_state": {
                "status": "missing", "exit_code": None,
                "exit_reason": "container_not_found", "restart_count": 0,
            },
            "system_state": self._get_system_metrics(),
            "filtered_logs": [],
            "signals": signals,
            "uptime": 0,
        }

    def send_report(self, report: DiagnosticReport) -> bool:
        if not self.config.AUTO_HEAL:
            return True

        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{self.config.OPENCLAW_URL}/incident",
                    json=report.to_dict(),
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    self.stats["send_success"] += 1
                    return True
            except Exception:
                backoff = 2 ** attempt
                logger.warning(f"Send retry {attempt + 1}/3, waiting {backoff}s")
                time.sleep(backoff)

        self.stats["send_failed"] += 1
        return False

    def process_service(self, service: str):
        raw_state = self.check_service(service)
        if raw_state is None:
            return

        signals = raw_state.get("signals", [])
        if not signals:
            self.persistence.clear(service, "")
            return

        event_type, severity = self._classify_event(
            signals, raw_state.get("system_state", {}), raw_state.get("filtered_logs", []),
        )

        if not event_type:
            return

        confidence = self._calculate_confidence(
            event_type, signals, raw_state.get("filtered_logs", [])
        )

        self.persistence.record(service, signals, event_type)

        emit, reason = self.should_emit(service, event_type, confidence, signals)

        if emit:
            self.failure_memory.record(service, event_type)
            self.stats["events_detected"] += 1
            report = self.build_report(service, event_type, severity, raw_state, confidence)
            if self.send_report(report):
                self.stats["events_emitted"] += 1
                key = f"{event_type}:{service}"
                self.last_events[key] = time.time()
                logger.info(
                    f"[EMIT] {service} {event_type} "
                    f"severity={severity} confidence={confidence} "
                    f"signals={signals} repeat={self.failure_memory.get_count(service, event_type, 1)}"
                )
        else:
            logger.debug(f"[SKIP] {service} {event_type}: {reason}")

    def run_loop(self):
        logger.info(f"Sentinel started (interval={self.config.CHECK_INTERVAL}s)")
        logger.info(f"Monitoring: {self.config.MONITORED_SERVICES}")
        logger.info(f"Rules: min_signals={MIN_SIGNALS_FOR_EVENT} min_confidence={MIN_CONFIDENCE_TO_EMIT} persistence={PERSISTENCE_CHECKS_REQUIRED}")
        logger.info(f"Job monitoring: {self.config.JOB_MONITORING}")

        while True:
            try:
                for service in self.config.MONITORED_SERVICES:
                    self.process_service(service)

                if self.config.JOB_MONITORING:
                    self.check_jobs()

            except Exception as e:
                logger.error(f"Loop error: {e}")

            time.sleep(self.config.CHECK_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="BioDockify Sentinel")
    parser.add_argument("--service", help="Single service to check")
    parser.add_argument("--once", action="store_true", help="Run once")
    parser.add_argument("--jobs", action="store_true", help="Check jobs only")
    args = parser.parse_args()

    config = SentinelConfig()
    if args.service:
        config.MONITORED_SERVICES = [args.service]

    sentinel = Sentinel(config)

    if args.jobs:
        sentinel.check_jobs()
        return

    if args.once:
        for service in config.MONITORED_SERVICES:
            raw = sentinel.check_service(service)
            if raw:
                signals = raw.get("signals", [])
                event_type, severity = sentinel._classify_event(
                    signals, raw.get("system_state", {}), raw.get("filtered_logs", []),
                )
                confidence = sentinel._calculate_confidence(
                    event_type, signals, raw.get("filtered_logs", [])
                )
                print(f"\n=== {service} ===")
                print(f"Signals: {signals}")
                print(f"Event: {event_type} (severity={severity}, confidence={confidence})")
                if event_type and confidence >= MIN_CONFIDENCE_TO_EMIT:
                    report = sentinel.build_report(service, event_type, severity, raw, confidence)
                    print(report.to_json())
                else:
                    print("No actionable event")

        if config.JOB_MONITORING:
            print("\n=== JOBS ===")
            sentinel.check_jobs()
    else:
        sentinel.run_loop()


if __name__ == "__main__":
    main()