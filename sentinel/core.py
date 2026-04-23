"""
Sentinel - Minimal Observer + Diagnostic Report Builder
Follows the DiagnosticReport JSON schema from design spec.
"""
import os
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    import docker
except ImportError:
    print("Installing docker...")
    import subprocess
    subprocess.run(["pip", "install", "docker"], check=True)
    import docker

try:
    import psutil
except ImportError:
    print("Installing psutil...")
    import subprocess
    subprocess.run(["pip", "install", "psutil"], check=True)
    import psutil

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SENTINEL] %(levelname)s %(message)s'
)
logger = logging.getLogger("sentinel")


class SentinelConfig:
    """Configuration from environment"""
    # OpenClaw endpoint
    OPENCLAW_URL = os.getenv("OPENCLAW_URL", "http://biodockify-openclaw:8001")
    
    # Monitoring settings
    CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "120"))
    COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))
    
    # Services to monitor
    MONITORED_SERVICES = os.getenv(
        "MONITORED_SERVICES",
        "biodockify-api,biodockify-docking-worker,biodockify-ranking-worker,biodockify-md-worker"
    ).split(",")
    
    # Auto-heal settings per service
    AUTO_HEAL = os.getenv("AUTO_HEAL", "true").lower() == "true"


class DiagnosticReport:
    """Structured Diagnostic Report following JSON Schema"""
    
    REQUIRED_FIELDS = ["event_id", "event_type", "service", "severity", "timestamp"]
    EVENT_TYPES = ["OOM_CRASH", "RESTART_LOOP", "API_DOWN", "CADDY_502", "QUEUE_BACKLOG", "DISK_FULL", "UNKNOWN"]
    SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
    
    def __init__(self, data: Dict):
        self.data = data
        self._validate()
    
    def _validate(self):
        """Validate required fields"""
        for field in self.REQUIRED_FIELDS:
            if field not in self.data:
                raise ValueError(f"Missing required field: {field}")
        
        if self.data["event_type"] not in self.EVENT_TYPES:
            logger.warning(f"Unknown event_type: {self.data['event_type']}, setting to UNKNOWN")
            self.data["event_type"] = "UNKNOWN"
        
        if self.data["severity"] not in self.SEVERITY_LEVELS:
            self.data["severity"] = "medium"
    
    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)
    
    def to_dict(self) -> Dict:
        return self.data.copy()


class Sentinel:
    """Minimal Sentinel - Observer Only"""
    
    def __init__(self, config: SentinelConfig = None):
        self.config = config or SentinelConfig()
        self.docker_client = docker.from_env()
        self.last_events = {}  # cooldown tracking
        self.stats = {"reports_emit": 0, "reports_skipped": 0}
    
    def collect(self, service_name: str) -> DiagnosticReport:
        """Collect diagnostic data and build report"""
        try:
            container = self.docker_client.containers.get(service_name)
            return self._build_report(service_name, container)
        except docker.errors.NotFound:
            return self._build_report(service_name, None, event_type="SERVICE_NOT_FOUND")
        except Exception as e:
            logger.error(f"Error collecting {service_name}: {e}")
            return self._build_report(service_name, None, event_type="UNKNOWN")
    
    def _build_report(
        self, 
        service: str, 
        container, 
        event_type: str = None,
        override_data: Dict = None
    ) -> DiagnosticReport:
        """Build diagnostic report"""
        now = int(time.time())
        
        # Default data
        data = {
            "event_id": "",
            "event_type": event_type or "UNKNOWN",
            "service": service,
            "severity": "medium",
            "summary": {"status": "unknown", "restart_count": 0, "uptime_seconds": 0},
            "system_state": {"memory_pct": 0, "cpu_pct": 0, "disk_pct": 0},
            "container_state": {"status": "unknown", "exit_code": None, "exit_reason": None},
            "recent_logs": [],
            "signals": [],
            "timeline": [],
            "confidence": 0.3,
            "timestamp": now
        }
        
        if container is None:
            data["severity"] = "critical"
            data["event_type"] = "SERVICE_NOT_FOUND"
            data["signals"].append("CONTAINER_MISSING")
        else:
            # Container state
            attrs = container.attrs
            state = attrs.get("State", {})
            
            data["container_state"] = {
                "status": state.get("Status", "unknown"),
                "exit_code": state.get("ExitCode"),
                "exit_reason": state.get("Error")
            }
            data["summary"] = {
                "status": state.get("Status", "unknown"),
                "restart_count": attrs.get("RestartCount", 0),
                "uptime_seconds": self._calculate_uptime(attrs)
            }
            
            # System metrics
            try:
                mem = psutil.virtual_memory()
                cpu = psutil.cpu_percent(interval=0.5)
                disk = psutil.disk_usage('/')
                
                data["system_state"] = {
                    "memory_pct": round(mem.percent, 1),
                    "cpu_pct": round(cpu, 1),
                    "disk_pct": round(disk.percent, 1)
                }
            except Exception as e:
                logger.warning(f"Failed to get system metrics: {e}")
            
            # Logs
            try:
                logs = container.logs(tail=100, stderr=True, stdout=True).decode('utf-8', errors='ignore')
                error_lines = [
                    l for l in logs.split('\n')[-50:] 
                    if any(k in l.lower() for k in ['error', 'exception', 'fatal', 'oom', 'killed', 'failed'])
                ]
                data["recent_logs"] = error_lines[-20:]  # Max 20 lines
            except Exception as e:
                logger.warning(f"Failed to get logs: {e}")
            
            # Event classification
            event_type, signals, severity = self._classify(
                data["system_state"],
                data["container_state"],
                data["recent_logs"]
            )
            data["event_type"] = event_type
            data["signals"] = signals
            data["severity"] = severity
            
            # Confidence
            data["confidence"] = self._calculate_confidence(event_type, signals, data["recent_logs"])
            
            # Timeline
            data["timeline"] = self._build_timeline(attrs, data["recent_logs"])
        
        # Generate event_id for idempotency
        data["event_id"] = self._generate_event_id(data["event_type"], service, now)
        
        # Override any specific data
        if override_data:
            data.update(override_data)
        
        return DiagnosticReport(data)
    
    def _classify(
        self,
        system_state: Dict,
        container_state: Dict,
        logs: List[str]
    ) -> tuple:
        """Classify event type from signals"""
        event_type = "UNKNOWN"
        signals = []
        severity = "medium"
        
        mem_pct = system_state.get("memory_pct", 0)
        log_text = ' '.join(logs).lower()
        
        # OOM detection
        if mem_pct > 90 or 'oom' in log_text or 'killed' in log_text:
            event_type = "OOM_CRASH"
            signals.append("HIGH_MEMORY")
            severity = "critical"
        
        # Restart loop
        elif container_state.get("status") == "restarting":
            event_type = "RESTART_LOOP"
            signals.append("RESTART_LOOP")
            severity = "high"
        
        # Check exit code
        exit_code = container_state.get("exit_code")
        if exit_code == 137:
            event_type = "OOM_CRASH"
            signals.append("SIGKILL")
            severity = "critical"
        elif exit_code == 1:
            event_type = "API_DOWN"
            signals.append("EXIT_ERROR")
            severity = "high"
        
        # Disk full
        disk_pct = system_state.get("disk_pct", 0)
        if disk_pct > 90:
            event_type = "DISK_FULL"
            signals.append("HIGH_DISK")
            severity = "critical"
        
        return event_type, signals, severity
    
    def _calculate_confidence(self, event_type: str, signals: List[str], logs: List[str]) -> float:
        """Calculate confidence in classification"""
        if event_type == "UNKNOWN":
            return 0.3
        
        signal_count = len(signals)
        
        if signal_count >= 3:
            return 0.95
        elif signal_count >= 2:
            return 0.8
        elif signal_count == 1:
            return 0.6
        
        # Check logs for more evidence
        if logs and any('error' in l.lower() for l in logs[:5]):
            return 0.7
        
        return 0.5
    
    def _generate_event_id(self, event_type: str, service: str, timestamp: int) -> str:
        """Generate idempotent event ID with time window"""
        # 60 second window
        time_window = timestamp // 60
        key = f"{event_type}:{service}:{time_window}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _calculate_uptime(self, attrs: Dict) -> int:
        """Calculate container uptime in seconds"""
        try:
            started = attrs.get("State", {}).get("StartedAt")
            if started:
                start_ts = datetime.fromisoformat(started.replace('Z', '+00:00')).timestamp()
                return int(time.time() - start_ts)
        except:
            pass
        return 0
    
    def _build_timeline(self, attrs: Dict, logs: List[str]) -> List[str]:
        """Build chronological timeline"""
        timeline = []
        
        # Add restart count
        restart_count = attrs.get("RestartCount", 0)
        if restart_count > 0:
            timeline.append(f"restart #{restart_count}")
        
        # Add log signals
        if logs:
            first_error = logs[0][:50] if logs else ""
            if first_error:
                timeline.append(first_error)
        
        return timeline[-5:]  # Last 5 events
    
    def should_emit(self, report: DiagnosticReport) -> bool:
        """Check cooldown and emit conditions"""
        key = f"{report.data['event_type']}:{report.data['service']}"
        now = time.time()
        
        # Don't emit unknown events
        if report.data['event_type'] == "UNKNOWN":
            return False
        
        # Check cooldown
        if key in self.last_events:
            if now - self.last_events[key] < self.config.COOLDOWN_SECONDS:
                self.stats["reports_skipped"] += 1
                return False
        
        self.last_events[key] = now
        self.stats["reports_emit"] += 1
        return True
    
    def send_report(self, report: DiagnosticReport) -> bool:
        """Send report to OpenClaw"""
        import requests
        
        if not self.config.AUTO_HEAL:
            logger.info(f"Auto-heal disabled, skipping OpenClaw")
            return True
        
        try:
            response = requests.post(
                f"{self.config.OPENCLAW_URL}/incident",
                json=report.to_dict(),
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Report sent: {report.data['event_id']}")
                return True
            else:
                logger.warning(f"OpenClaw rejected: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send report: {e}")
            return False
    
    def verify_recovery(self, service: str) -> bool:
        """Verify service recovered after fix"""
        try:
            container = self.docker_client.containers.get(service)
            if container.status == 'running':
                # Additional checks can be added here
                return True
        except:
            pass
        return False
    
    def run_loop(self):
        """Main monitoring loop"""
        logger.info(f"Starting Sentinel loop (interval={self.config.CHECK_INTERVAL}s)")
        logger.info(f"Monitoring: {self.config.MONITORED_SERVICES}")
        
        while True:
            try:
                for service in self.config.MONITORED_SERVICES:
                    service = service.strip()
                    if not service:
                        continue
                    
                    report = self.collect(service)
                    
                    if self.should_emit(report):
                        logger.info(
                            f"[{service}] {report.data['event_type']} "
                            f"(severity={report.data['severity']}, "
                            f"confidence={report.data['confidence']})"
                        )
                        self.send_report(report)
                    else:
                        logger.debug(f"[{service}] OK, no emit")
                
            except Exception as e:
                logger.error(f"Sentinel loop error: {e}")
            
            time.sleep(self.config.CHECK_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="BioDockify Sentinel")
    parser.add_argument("--service", help="Single service to monitor")
    parser.add_argument("--once", action="store_true", help="Run once instead of loop")
    args = parser.parse_args()
    
    config = SentinelConfig()
    
    # Override service list if provided
    if args.service:
        config.MONITORED_SERVICES = [args.service]
    
    sentinel = Sentinel(config)
    
    if args.once:
        # Run once
        for service in config.MONITORED_SERVICES:
            report = sentinel.collect(service.strip())
            print(f"\n=== {service} ===")
            print(report.to_json())
    else:
        # Run loop
        sentinel.run_loop()


if __name__ == "__main__":
    main()