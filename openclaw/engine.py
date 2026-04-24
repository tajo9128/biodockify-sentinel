"""
OpenClaw - Execution Engine v2
Production-safe mini orchestration engine.

Flow: validate -> deduplicate -> rate_limit -> build_plan -> execute_plan -> finalize

Key upgrades over v1:
  - Multi-step execution plans with conditional branching
  - Per-step retry with exponential backoff
  - 3-attempt verification with health checks
  - Thread-safe event deduplication
  - Per-service rate limiting
  - Result classification (success/partial/failed) with step tracking
  - Gunicorn-ready WSGI app factory
"""
import os
import json
import time
import threading
import logging
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import docker
except ImportError:
    import subprocess as sp
    sp.run(["pip", "install", "docker"], check=True)
    import docker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OPENCLAW] %(levelname)s %(message)s"
)
logger = logging.getLogger("openclaw")


class Config:
    DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
    SERVICE_POLICIES = os.getenv("SERVICE_POLICIES", "")
    RATE_LIMIT_SECONDS = int(os.getenv("RATE_LIMIT_SECONDS", "300"))
    VERIFY_WAIT_SECONDS = int(os.getenv("VERIFY_WAIT_SECONDS", "8"))
    VERIFY_RETRIES = int(os.getenv("VERIFY_RETRIES", "3"))
    STEP_RETRY_ATTEMPTS = int(os.getenv("STEP_RETRY_ATTEMPTS", "2"))
    STEP_BACKOFF_BASE = int(os.getenv("STEP_BACKOFF_BASE", "5"))
    DEDUP_TTL_SECONDS = int(os.getenv("DEDUP_TTL_SECONDS", "600"))


class EventDedup:
    """Thread-safe deduplication of processed event_ids with TTL expiry."""

    def __init__(self, ttl_seconds: int = 600):
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def check(self, event_id: str) -> bool:
        now = time.time()
        with self._lock:
            expired = [k for k, ts in self._seen.items() if now - ts > self._ttl]
            for k in expired:
                del self._seen[k]
            if event_id in self._seen:
                return True
            self._seen[event_id] = now
            return False

    def size(self) -> int:
        with self._lock:
            return len(self._seen)


class RateLimiter:
    """Per-service rate limiting."""

    def __init__(self, cooldown_seconds: int = 300):
        self._last_action: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._cooldown = cooldown_seconds

    def is_limited(self, service: str) -> bool:
        now = time.time()
        with self._lock:
            if service in self._last_action:
                if now - self._last_action[service] < self._cooldown:
                    remaining = int(self._cooldown - (now - self._last_action[service]))
                    return True
            return False

    def record(self, service: str):
        with self._lock:
            self._last_action[service] = time.time()


class FailureMemory:
    """Track failures per service for escalation and backoff."""

    def __init__(self):
        self._history: Dict[str, List[Dict]] = {}

    def record(self, service: str, action: str, result: str):
        if service not in self._history:
            self._history[service] = []
        self._history[service].append({
            "action": action,
            "result": result,
            "timestamp": time.time(),
        })
        self._history[service] = self._history[service][-20:]

    def get_count(self, service: str, window_hours: int = 1) -> int:
        if service not in self._history:
            return 0
        cutoff = time.time() - (window_hours * 3600)
        return len([e for e in self._history[service] if e["timestamp"] > cutoff])

    def should_escalate(self, service: str) -> bool:
        return self.get_count(service, window_hours=1) >= 3

    def get_backoff_seconds(self, service: str) -> int:
        count = self.get_count(service, window_hours=1)
        return min(2 ** count, 3600)

    def get_last_result(self, service: str) -> Optional[str]:
        if service not in self._history or not self._history[service]:
            return None
        return self._history[service][-1].get("result")


class ExecutionEngine:
    """
    OpenClaw v2 Execution Engine.

    Pipeline: validate -> deduplicate -> rate_limit -> plan -> execute -> verify -> finalize
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.docker_client = docker.from_env()
        self.audit_log: List[Dict] = []
        self.failure_memory = FailureMemory()
        self.event_dedup = EventDedup(ttl_seconds=self.config.DEDUP_TTL_SECONDS)
        self.rate_limiter = RateLimiter(cooldown_seconds=self.config.RATE_LIMIT_SECONDS)
        self.stats = {
            "restart": 0, "cleanup": 0, "alert": 0,
            "skipped": 0, "failed": 0, "partial": 0,
            "escalated": 0, "deduped": 0, "rate_limited": 0,
        }
        self._load_policies()

    def _load_policies(self):
        self.policies: Dict[str, Dict] = {}
        if self.config.SERVICE_POLICIES:
            for line in self.config.SERVICE_POLICIES.split(","):
                if ":" in line:
                    svc, policy = line.split(":", 1)
                    self.policies[svc.strip()] = {"auto_heal": "true" in policy.lower()}
        logger.info(f"Loaded policies for {len(self.policies)} services")

    def handle_incident(self, report: Dict) -> Dict:
        event_id = report.get("event_id", "unknown")
        event_type = report.get("event_type", "UNKNOWN")
        service = report.get("service", "unknown")
        confidence = report.get("confidence", 0.0)
        escalation = report.get("escalation", False)
        repeat_count = report.get("repeat_count", 0)

        logger.info(f"INCIDENT {event_id} | {event_type} | service={service} | conf={confidence} | repeats={repeat_count}")

        if not self._validate(report):
            return {"status": "rejected", "reason": "invalid_report", "event_id": event_id}

        if self.event_dedup.check(event_id):
            logger.info(f"[DEDUP] {event_id} already processed")
            self.stats["deduped"] += 1
            return {"status": "ignored", "reason": "duplicate_event", "event_id": event_id}

        if not self._policy_allows(service):
            self.stats["skipped"] += 1
            return {"status": "skipped", "reason": "policy_disabled", "service": service}

        if escalation and repeat_count >= 3:
            logger.warning(f"[ESCALATE] {service} has {repeat_count} repeats")
            self.stats["escalated"] += 1
            self._audit(event_id, "escalate", service, {"status": "escalated"})
            return {"status": "escalated", "reason": "repeated_failures", "repeat_count": repeat_count}

        if confidence < 0.6:
            logger.info(f"[LOW-CONF] {confidence} < 0.6, alert only")
            self.stats["alert"] += 1
            self._audit(event_id, "alert_low_confidence", service, {"status": "alert"})
            return {"status": "alert", "reason": "low_confidence", "confidence": confidence}

        if self.rate_limiter.is_limited(service):
            remaining = self.config.RATE_LIMIT_SECONDS
            logger.info(f"[RATE-LIMIT] {service} action too recent")
            self.stats["rate_limited"] += 1
            return {"status": "rate_limited", "reason": f"cooldown_active", "service": service}

        backoff = self.failure_memory.get_backoff_seconds(service)
        last_result = self.failure_memory.get_last_result(service)
        if last_result == "failed" and backoff > 60:
            logger.warning(f"[BACKOFF] {service} waiting {backoff}s after failure")
            return {"status": "backoff", "reason": f"failure_backoff_{backoff}s"}

        plan = self.build_plan(report)

        if self.config.DRY_RUN:
            return {"status": "dry_run", "plan": plan, "event_id": event_id}

        self.rate_limiter.record(service)

        result = self.execute_plan(plan, event_id, service, event_type)

        self.failure_memory.record(service, plan[0].get("action", "plan"), result["status"])
        self._audit(event_id, "plan_executed", service, result)

        return result

    def _validate(self, report: Dict) -> bool:
        required = ["event_type", "service", "confidence"]
        if not all(k in report for k in required):
            logger.warning(f"Validation failed: missing required fields")
            return False
        try:
            conf = float(report["confidence"])
            if conf < 0 or conf > 1:
                return False
        except (TypeError, ValueError):
            return False
        return True

    def _policy_allows(self, service: str) -> bool:
        if service in self.policies:
            return self.policies[service].get("auto_heal", True)
        return True

    def build_plan(self, report: Dict) -> List[Dict]:
        event_type = report.get("event_type", "UNKNOWN")
        service = report.get("service", "unknown")
        system_state = report.get("system_state", {})
        container_state = report.get("container_state", {})

        if event_type == "OOM_CRASH":
            if system_state.get("memory_pct", 0) > 90:
                return [
                    {"action": "restart", "target": service, "params": {"memory": "512m"}, "label": "restart_with_mem_limit"},
                    {"action": "verify", "target": service},
                ]
            return [
                {"action": "restart", "target": service, "label": "restart"},
                {"action": "verify", "target": service},
            ]

        if event_type == "RESTART_LOOP":
            return [
                {"action": "inspect", "target": service, "label": "inspect_restart_count"},
                {"action": "restart", "target": service, "params": {"max_retries": 2}, "label": "restart_capped"},
                {"action": "verify", "target": service, "params": {"check_restart_count": True}},
            ]

        if event_type == "API_DOWN":
            return [
                {"action": "restart", "target": service, "label": "restart_api"},
                {"action": "verify", "target": service, "params": {"check_http": True, "http_port": 8000}},
            ]

        if event_type == "CADDY_502":
            upstream = service
            return [
                {"action": "restart", "target": "caddy-reverse", "label": "restart_caddy"},
                {"action": "verify", "target": "caddy-reverse", "label": "verify_caddy"},
                {"action": "restart", "target": upstream, "conditional": True, "label": "restart_upstream_if_needed"},
                {"action": "verify", "target": upstream, "conditional": True, "params": {"check_http": True, "http_port": 8000}, "label": "verify_upstream"},
            ]

        if event_type == "DISK_FULL":
            return [
                {"action": "cleanup", "target": service, "params": {"keep_days": 7}, "label": "cleanup_logs"},
                {"action": "verify", "target": service, "label": "verify_after_cleanup"},
            ]

        if event_type == "JOB_STALLED":
            ctx = report.get("job_context", {})
            hours = ctx.get("hours_stalled", 0)
            if hours > 12:
                return [
                    {"action": "restart", "target": service, "label": "restart_stalled_worker"},
                    {"action": "verify", "target": service},
                ]
            return [
                {"action": "alert", "target": service, "params": {"reason": f"job_stalled_{hours}h"}, "label": "alert_stalled"},
            ]

        if event_type == "JOB_FAILED":
            ctx = report.get("job_context", {})
            failure_type = ctx.get("failure_type", "UNKNOWN")
            count = ctx.get("failure_count", 0)
            if count > 20:
                return [
                    {"action": "restart", "target": service, "label": f"restart_mass_{failure_type}"},
                    {"action": "verify", "target": service},
                ]
            return [
                {"action": "alert", "target": service, "params": {"reason": f"{failure_type}_x{count}"}, "label": "alert_failures"},
            ]

        if event_type == "QUEUE_BACKLOG":
            depth = report.get("job_context", {}).get("queue_depth", 0)
            return [
                {"action": "alert", "target": service, "params": {"reason": "queue_backlog", "queue_depth": depth}, "label": "alert_backlog"},
            ]

        if event_type == "SERVICE_NOT_FOUND":
            return [
                {"action": "alert", "target": service, "params": {"reason": "service_missing"}, "label": "alert_missing"},
            ]

        return [
            {"action": "alert", "target": service, "label": "alert_unknown"},
        ]

    def execute_plan(self, plan: List[Dict], event_id: str, service: str, event_type: str) -> Dict:
        total_steps = len(plan)
        completed = 0
        step_results = []
        conditional_skip_remaining = False
        plan_status = "success"

        for i, step in enumerate(plan):
            label = step.get("label", step["action"])
            action = step["action"]
            target = step.get("target", service)
            is_conditional = step.get("conditional", False)

            if conditional_skip_remaining and is_conditional:
                logger.info(f"[PLAN] Step {i+1}/{total_steps} '{label}' SKIPPED (conditional, previous resolved)")
                step_results.append({"step": label, "status": "skipped", "reason": "previous_step_resolved"})
                continue

            logger.info(f"[PLAN] Step {i+1}/{total_steps}: '{label}' on {target}")

            if action == "verify":
                result = self._verify_with_retries(target, step.get("params", {}))
                step_results.append({"step": label, **result})

                if result["status"] == "success":
                    if is_conditional or self._should_skip_remaining(event_type, i, plan):
                        conditional_skip_remaining = True
                    completed += 1
                else:
                    plan_status = "partial"
                    if is_conditional:
                        pass
                    else:
                        completed += 1
                continue

            result = self._execute_step_with_retry(step)

            step_results.append({"step": label, **result})

            if result.get("status") == "success":
                completed += 1
            elif result.get("status") == "alert_sent":
                completed += 1
            else:
                plan_status = "failed"
                if not is_conditional:
                    break

        if plan_status == "failed" and completed > 0:
            plan_status = "partial"

        self.stats[plan_status] = self.stats.get(plan_status, 0) + 1

        return {
            "status": plan_status,
            "event_id": event_id,
            "service": service,
            "steps_completed": completed,
            "steps_total": total_steps,
            "steps": step_results,
        }

    def _should_skip_remaining(self, event_type: str, current_step: int, plan: List[Dict]) -> bool:
        remaining = plan[current_step + 1:]
        return all(s.get("conditional", False) or s["action"] == "alert" for s in remaining)

    def _execute_step_with_retry(self, step: Dict) -> Dict:
        action = step["action"]
        target = step.get("target")
        params = step.get("params", {})
        attempts = self.config.STEP_RETRY_ATTEMPTS

        for attempt in range(1, attempts + 1):
            result = self._execute_step(action, target, params)
            if result.get("status") in ("success", "alert_sent"):
                return result

            if attempt < attempts:
                backoff = self.config.STEP_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(f"[RETRY] {action} on {target} attempt {attempt}/{attempts} failed, waiting {backoff}s")
                time.sleep(backoff)

        return result

    def _execute_step(self, action: str, target: str, params: Dict) -> Dict:
        try:
            if action == "restart":
                return self._restart_container(target)
            elif action == "inspect":
                return self._inspect_container(target)
            elif action == "cleanup":
                return self._cleanup_logs(target, params)
            elif action == "alert":
                return self._send_alert(target, params)
            else:
                return {"status": "unknown_action", "action": action}
        except Exception as e:
            logger.error(f"[EXEC] {action} on {target} failed: {e}")
            self.stats["failed"] += 1
            return {"status": "failed", "error": str(e)}

    def _restart_container(self, name: str) -> Dict:
        logger.info(f"[EXEC] Restarting {name}...")
        try:
            c = self.docker_client.containers.get(name)
            c.restart(timeout=30)
            self.stats["restart"] += 1
            return {"status": "success", "action": "restart", "target": name}
        except docker.errors.NotFound:
            return {"status": "failed", "error": "container_not_found", "target": name}
        except Exception as e:
            return {"status": "failed", "error": str(e), "target": name}

    def _inspect_container(self, name: str) -> Dict:
        logger.info(f"[EXEC] Inspecting {name}...")
        try:
            c = self.docker_client.containers.get(name)
            c.reload()
            restart_count = c.attrs.get("RestartCount", 0)
            status = c.status
            logger.info(f"[INSPECT] {name}: status={status} restarts={restart_count}")
            return {"status": "success", "action": "inspect", "target": name, "container_status": status, "restart_count": restart_count}
        except docker.errors.NotFound:
            return {"status": "failed", "error": "container_not_found"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def _cleanup_logs(self, name: str, params: Dict) -> Dict:
        keep_days = params.get("keep_days", 7)
        logger.info(f"[EXEC] Cleaning logs for {name} (keep {keep_days}d)...")
        try:
            subprocess.run(
                ["docker", "exec", name, "find", "/var/log", "-name", "*.log",
                 "-mtime", f"+{keep_days}", "-delete"],
                check=False, timeout=30
            )
            self.stats["cleanup"] += 1
            return {"status": "success", "action": "cleanup", "target": name}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def _send_alert(self, target: str, params: Dict) -> Dict:
        reason = params.get("reason", "unknown")
        logger.warning(f"[ALERT] {target}: {reason}")
        self.stats["alert"] += 1
        return {"status": "alert_sent", "target": target, "reason": reason}

    def _verify_with_retries(self, service: str, params: Dict) -> Dict:
        retries = self.config.VERIFY_RETRIES
        wait = self.config.VERIFY_WAIT_SECONDS
        check_http = params.get("check_http", False)
        http_port = params.get("http_port", 8000)
        check_restart_count = params.get("check_restart_count", False)

        logger.info(f"[VERIFY] Checking {service} ({retries} attempts, {wait}s interval)...")

        for attempt in range(1, retries + 1):
            time.sleep(wait)

            healthy, details = self._check_health(service, check_http, http_port, check_restart_count)
            if healthy:
                logger.info(f"[VERIFY] {service} HEALTHY (attempt {attempt})")
                return {"status": "success", "verified_on_attempt": attempt, "details": details}

            logger.warning(f"[VERIFY] {service} not healthy (attempt {attempt}/{retries}): {details}")

        logger.error(f"[VERIFY] {service} FAILED all {retries} verification attempts")
        return {"status": "failed", "reason": "verification_exhausted", "attempts": retries}

    def _check_health(self, service: str, check_http: bool, http_port: int, check_restart_count: bool) -> Tuple[bool, str]:
        try:
            c = self.docker_client.containers.get(service)
            c.reload()

            if c.status != "running":
                return False, f"container_{c.status}"

            if check_restart_count:
                rc = c.attrs.get("RestartCount", 0)
                if rc > 0:
                    return False, f"restart_count={rc}"

            if check_http:
                try:
                    import requests
                    resp = requests.get(f"http://{service}:{http_port}/health", timeout=5)
                    if resp.status_code != 200:
                        return False, f"http_{resp.status_code}"
                except Exception as e:
                    return False, f"http_error: {e}"

            return True, "healthy"
        except docker.errors.NotFound:
            return False, "container_not_found"
        except Exception as e:
            return False, str(e)

    def _audit(self, event_id: str, action: str, target: str, result: Dict):
        entry = {
            "ts": int(time.time()),
            "event_id": event_id,
            "action": action,
            "target": target,
            "result": result.get("status"),
            "dry_run": self.config.DRY_RUN,
        }
        self.audit_log.append(entry)
        if len(self.audit_log) > 500:
            self.audit_log = self.audit_log[-250:]
        logger.info(f"AUDIT {json.dumps(entry)}")

    def get_stats(self) -> Dict:
        return {
            **self.stats,
            "audit_count": len(self.audit_log),
            "dedup_cache": self.event_dedup.size(),
        }


def create_app():
    from flask import Flask, request, jsonify

    config = Config()
    engine = ExecutionEngine(config)

    app = Flask(__name__)

    @app.route("/incident", methods=["POST"])
    def incident_endpoint():
        incident = request.get_json()
        if not incident or "event_type" not in incident:
            return jsonify({"status": "error", "reason": "missing_event_type"}), 400
        result = engine.handle_incident(incident)
        code = 200
        if result.get("status") in ("rejected",):
            code = 400
        return jsonify(result), code

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "engine": "v2", "stats": engine.get_stats()})

    @app.route("/audit", methods=["GET"])
    def audit():
        return jsonify({"audit": engine.audit_log[-100:]})

    @app.route("/stats", methods=["GET"])
    def stats():
        return jsonify(engine.get_stats())

    @app.route("/plan", methods=["POST"])
    def preview_plan():
        report = request.get_json()
        if not report:
            return jsonify({"status": "error", "reason": "empty_body"}), 400
        plan = engine.build_plan(report)
        return jsonify({"plan": plan, "steps": len(plan)}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    logger.info("Starting OpenClaw v2 on port 8001 (dev server — use gunicorn for production)")
    app.run(host="0.0.0.0", port=8001)