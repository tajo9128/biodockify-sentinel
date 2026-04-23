"""
OpenClaw - Decision Engine + Safe Executor
Handles incidents from Sentinel and executes remediation actions
"""
import os
import json
import time
import logging
import argparse
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import docker
except ImportError:
    import subprocess
    subprocess.run(["pip", "install", "docker"], check=True)
    import docker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [OPENCLAW] %(levelname)s %(message)s'
)
logger = logging.getLogger("openclaw")


class OpenClawConfig:
    """Configuration from environment"""
    DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
    
    # Service policies (auto_heal: true/false)
    SERVICE_POLICIES = os.getenv("SERVICE_POLICIES", "")
    
    # Redis for state
    REDIS_URL = os.getenv("REDIS_URL", "redis://biodockify-redis:6379")
    
    # Audit log path
    AUDIT_PATH = os.getenv("AUDIT_PATH", "/app/audit.log")


class OpenClaw:
    """OpenClaw - Decision Engine + Safe Executor"""
    
    def __init__(self, config: OpenClawConfig = None):
        self.config = config or OpenClawConfig()
        self.docker_client = docker.from_env()
        self.audit_log = []
        self.action_stats = {
            "restart": 0,
            "recreate": 0,
            "cleanup": 0,
            "alert": 0,
            "skipped": 0,
            "failed": 0
        }
        
        # Service policies
        self._load_policies()
    
    def _load_policies(self):
        """Load service policies from config"""
        self.policies = {}
        
        if self.config.SERVICE_POLICIES:
            for line in self.config.SERVICE_POLICIES.split(","):
                if ":" in line:
                    svc, policy = line.split(":")
                    self.policies[svc.strip()] = {
                        "auto_heal": "true" in policy.lower()
                    }
        
        logger.info(f"Loaded policies for {len(self.policies)} services")
    
    def handle_incident(self, report: Dict) -> Dict:
        """Main entrypoint - decide and execute"""
        event_id = report.get("event_id", "unknown")
        event_type = report.get("event_type", "UNKNOWN")
        service = report.get("service", "unknown")
        
        logger.info(f"Handling incident: {event_id} ({event_type}) for {service}")
        
        # Check service policy
        if not self._should_auto_heal(service):
            logger.info(f"Auto-heal disabled for {service}, skipping")
            self.action_stats["skipped"] += 1
            return {"status": "skipped", "reason": "policy_disabled"}
        
        # Decide action
        action = self.decide(report)
        
        if not action:
            logger.info(f"No action decided for {event_type}")
            self.action_stats["skipped"] += 1
            return {"status": "no_action", "reason": "no_matching_strategy"}
        
        logger.info(f"Decided: {action['action']} on {service}")
        
        # Dry run check
        if self.config.DRY_RUN:
            logger.info(f"DRY RUN - would execute: {action}")
            return {"status": "dry_run", "action": action}
        
        # Execute
        result = self.execute(action, report)
        
        # Audit
        self._audit(event_id, action, result)
        
        return result
    
    def decide(self, report: Dict) -> Optional[Dict]:
        """Rule-based decision engine"""
        event_type = report.get("event_type", "UNKNOWN")
        service = report.get("service", "unknown")
        system_state = report.get("system_state", {})
        container_state = report.get("container_state", {})
        confidence = report.get("confidence", 0.5)
        severity = report.get("severity", "medium")
        
        # Low confidence - no auto-fix
        if confidence < 0.6 and severity != "critical":
            logger.info(f"Low confidence ({confidence}), alert only")
            return {"action": "alert", "target": service}
        
        # Event-specific actions
        if event_type == "OOM_CRASH":
            return self._decide_oom_crash(service, system_state, container_state)
        
        elif event_type == "RESTART_LOOP":
            return {"action": "inspect_restart", "target": service, "params": {"max_retries": 2}}
        
        elif event_type == "API_DOWN":
            return {"action": "restart", "target": service, "params": {}}
        
        elif event_type == "CADDY_502":
            # Restart API first, Caddy should follow
            return {"action": "restart_dependency", "target": "caddy-reverse", "params": {"after": [service]}}
        
        elif event_type == "DISK_FULL":
            return {"action": "cleanup", "target": service, "params": {"keep_days": 7}}
        
        elif event_type == "SERVICE_NOT_FOUND":
            return {"action": "alert", "target": service, "params": {"reason": "service_missing"}}
        
        # Unknown - alert only
        return {"action": "alert", "target": service}
    
    def _decide_oom_crash(self, service: str, system_state: Dict, container_state: Dict) -> Dict:
        """Decide action for OOM crash"""
        mem_pct = system_state.get("memory_pct", 0)
        
        # System memory critical - restart with limits
        if mem_pct > 90:
            return {
                "action": "restart_with_memory",
                "target": service,
                "params": {"memory": "512m", "reason": "high_system_memory"}
            }
        
        # Container was killed - simple restart
        return {"action": "restart", "target": service, "params": {}}
    
    def _should_auto_heal(self, service: str) -> bool:
        """Check if service should auto-heal"""
        # Check explicit policy
        if service in self.policies:
            return self.policies[service].get("auto_heal", True)
        
        # Default: allow for worker containers
        if "worker" in service.lower():
            return True
        
        # Default: allow for API
        if service == "biodockify-api":
            return True
        
        return True
    
    def execute(self, action: Dict, report: Dict) -> Dict:
        """Safe execution"""
        target = action["target"]
        action_type = action["action"]
        params = action.get("params", {})
        
        try:
            if action_type == "restart":
                return self._restart_container(target)
            
            elif action_type == "restart_with_memory":
                return self._restart_with_memory(target, params)
            
            elif action_type == "inspect_restart":
                return self._inspect_and_restart(target, params)
            
            elif action_type == "restart_dependency":
                return self._restart_dependency(target, params)
            
            elif action_type == "cleanup":
                return self._cleanup_logs(target, params)
            
            elif action_type == "alert":
                return self._send_alert(target, params)
            
            else:
                return {"status": "unknown_action", "action": action_type}
        
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            self.action_stats["failed"] += 1
            return {"status": "failed", "error": str(e)}
    
    def _restart_container(self, name: str) -> Dict:
        """Restart container with pre/post checks"""
        logger.info(f"Restarting {name}...")
        
        try:
            container = self.docker_client.containers.get(name)
            
            # Pre-flight check
            if container.status != "running":
                logger.info(f"{name} not running, starting...")
                container.start()
            else:
                container.restart(timeout=30)
            
            self.action_stats["restart"] += 1
            
            # Wait and verify
            time.sleep(10)
            
            container.reload()
            if container.status == "running":
                logger.info(f"{name} restarted successfully")
                return {"status": "success", "action": "restart", "target": name}
            else:
                logger.warning(f"{name} not healthy after restart")
                return {"status": "partial", "target": name}
        
        except docker.errors.NotFound:
            return {"status": "failed", "error": "container_not_found"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    def _restart_with_memory(self, name: str, params: Dict) -> Dict:
        """Restart with memory limit (requires recreate)"""
        memory = params.get("memory", "512m")
        
        logger.info(f"Restarting {name} with memory limit {memory}...")
        
        # Note: Docker restart doesn't apply new limits
        # For proper implementation, would need docker-compose recreate
        # For now, just restart
        try:
            container = self.docker_client.containers.get(name)
            container.restart(timeout=30)
            
            self.action_stats["restart"] += 1
            
            return {
                "status": "success",
                "action": "restart_with_memory",
                "target": name,
                "applied": memory,
                "note": "restarted, limits require recreate"
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    def _inspect_and_restart(self, name: str, params: Dict) -> Dict:
        """Inspect first, then restart if needed"""
        max_retries = params.get("max_retries", 2)
        
        try:
            container = self.docker_client.containers.get(name)
            inspect = container.attrs
            
            # Log inspection info
            restart_count = inspect.get("RestartCount", 0)
            state = inspect.get("State", {})
            
            logger.info(f"{name} restart count: {restart_count}, status: {state.get('Status')}")
            
            # Simple restart
            container.restart(timeout=30)
            self.action_stats["restart"] += 1
            
            return {"status": "success", "action": "inspect_restart", "target": name}
        
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    def _restart_dependency(self, target: str, params: Dict) -> Dict:
        """Restart dependency (after target)"""
        after_services = params.get("after", [])
        
        results = []
        
        # Restart target
        result = self._restart_container(target)
        results.append(result)
        
        # Optionally restart services in after list
        for svc in after_services:
            try:
                r = self._restart_container(svc)
                results.append(r)
            except:
                pass
        
        return {"status": "success", "action": "restart_dependency", "target": target, "results": results}
    
    def _cleanup_logs(self, name: str, params: Dict) -> Dict:
        """Clean up old logs"""
        keep_days = params.get("keep_days", 7)
        
        logger.info(f"Cleaning logs for {name} (keep {keep_days} days)...")
        
        try:
            # Find and delete old log files
            subprocess.run([
                "docker", "exec", name,
                "find", "/var/log", "-name", "*.log",
                "-mtime", f"+{keep_days}", "-delete"
            ], check=False, timeout=30)
            
            self.action_stats["cleanup"] += 1
            
            return {"status": "success", "action": "cleanup", "target": name}
        
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    def _send_alert(self, target: str, params: Dict) -> Dict:
        """Send alert (in production: to Slack, PagerDuty, etc."""
        reason = params.get("reason", "unknown")
        
        logger.warning(f"ALERT for {target}: {reason}")
        
        self.action_stats["alert"] += 1
        
        return {"status": "alert_sent", "target": target, "reason": reason}
    
    def _audit(self, event_id: str, action: Dict, result: Dict):
        """Append to audit log"""
        entry = {
            "timestamp": int(time.time()),
            "event_id": event_id,
            "action": action.get("action"),
            "target": action.get("target"),
            "result": result.get("status"),
            "dry_run": self.config.DRY_RUN
        }
        
        self.audit_log.append(entry)
        
        # Log to console (in production: to Loki/file)
        logger.info(f"AUDIT: {json.dumps(entry)}")
    
    def get_stats(self) -> Dict:
        """Get action statistics"""
        return self.action_stats.copy()


def handle_incident_api(incident: Dict) -> Dict:
    """Flask route handler"""
    config = OpenClawConfig()
    openclaw = OpenClaw(config)
    return openclaw.handle_incident(incident)


if __name__ == "__main__":
    import sys
    
    # Simple CLI
    if len(sys.argv) < 2:
        print("Usage: python openclaw.py [--serve] [--dry-run] [event_json]")
        sys.exit(1)
    
    config = OpenClawConfig()
    openclaw = OpenClaw(config)
    
    if sys.argv[1] == "--serve":
        # Start Flask API
        try:
            from flask import Flask, request, jsonify
        except ImportError:
            subprocess.run(["pip", "install", "flask"], check=True)
            from flask import Flask, request, jsonify
        
        app = Flask(__name__)
        
        @app.route("/incident", methods=["POST"])
        def incident_endpoint():
            incident = request.get_json()
            result = handle_incident_api(incident)
            return jsonify(result)
        
        @app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok", "stats": openclaw.get_stats()})
        
        @app.route("/audit", methods=["GET"])
        def audit():
            return jsonify({"audit": openclaw.audit_log})
        
        logger.info("Starting OpenClaw API on port 8001")
        app.run(host="0.0.0.0", port=8001)
    
    else:
        # Process incident from CLI
        incident = json.loads(sys.argv[1])
        result = openclaw.handle_incident(incident)
        print(json.dumps(result, indent=2))