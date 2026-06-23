import json
import os
import re
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

class Redactor:
    """
    Utility for safely redacting API keys, tokens, and common secrets from text or JSON.
    """
    
    PATTERNS = [
        # Groq API keys
        (re.compile(r'gsk_[a-zA-Z0-9]{20,}'), '[REDACTED_GROQ_KEY]'),
        # OpenAI API keys
        (re.compile(r'sk-[a-zA-Z0-9]{40,}'), '[REDACTED_OPENAI_KEY]'),
        # Bearer tokens
        (re.compile(r'Bearer\s+[a-zA-Z0-9\-\._~+/]+=*'), 'Bearer [REDACTED]'),
        # Generic Authorization headers
        (re.compile(r'Authorization:\s*.*', re.IGNORECASE), 'Authorization: [REDACTED]'),
        # .env style secrets
        (re.compile(r'(?i)(api_key|secret|password|token)\s*[:=]\s*["\']?[a-zA-Z0-9\-\._~+/]+["\']?'), r'\1=[REDACTED]'),
    ]

    @classmethod
    def redact_string(cls, text: str) -> str:
        if not isinstance(text, str):
            return text
        for pattern, replacement in cls.PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact strings in a dictionary."""
        redacted = {}
        for k, v in data.items():
            if isinstance(v, str):
                redacted[k] = cls.redact_string(v)
            elif isinstance(v, dict):
                redacted[k] = cls.redact_dict(v)
            elif isinstance(v, list):
                # Only redact elements if they are dicts or strings
                redacted[k] = [cls.redact_dict(i) if isinstance(i, dict) else (cls.redact_string(i) if isinstance(i, str) else i) for i in v]
            else:
                redacted[k] = v
        return redacted

class ObservabilityLogger:
    """
    Manages structured logging for the Wizard Leak Lab runs.
    Creates structured artifacts in reports/redteam/wizard_lab/runs/<run_id>/
    """
    def __init__(self, run_id: Optional[str] = None, base_dir: str = "reports/redteam/wizard_lab/runs"):
        self.run_id = run_id or str(uuid.uuid4())
        self.base_dir = Path(base_dir)
        self.run_dir = self.base_dir / self.run_id
        
        self.run_dir.mkdir(parents=True, exist_ok=True)
        
        self.meta: Dict[str, Any] = {
            "run_id": self.run_id,
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "running",
            "strategy": "unknown",
            "levels_attempted": 0,
            "levels_solved": 0,
            "levels_failed": 0
        }
        self.trajectory: List[Dict[str, Any]] = []
        
        self._write_meta()

    def _append_jsonl(self, filename: str, record: Dict[str, Any]):
        record = Redactor.redact_dict(record)
        if "timestamp" not in record:
            record["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if "run_id" not in record:
            record["run_id"] = self.run_id
            
        filepath = self.run_dir / filename
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _write_meta(self):
        meta_safe = Redactor.redact_dict(self.meta)
        with open(self.run_dir / "run_meta.json", "w", encoding="utf-8") as f:
            json.dump(meta_safe, f, indent=2)

    def log_event(self, component: str, event_type: str, level_id: Optional[int] = None, session_id: Optional[str] = None, message: str = "", payload: Optional[Dict[str, Any]] = None):
        record = {
            "component": component,
            "event_type": event_type,
            "level_id": level_id,
            "session_id": session_id,
            "message": message,
            "payload": payload or {}
        }
        self._append_jsonl("events.jsonl", record)

    def log_decision(self, component: str, level_id: int, message: str, payload: Optional[Dict[str, Any]] = None):
        record = {
            "component": component,
            "level_id": level_id,
            "message": message,
            "payload": payload or {}
        }
        self._append_jsonl("decisions.jsonl", record)

    def log_error(self, component: str, error_message: str, severity: str = "ERROR", payload: Optional[Dict[str, Any]] = None):
        record = {
            "component": component,
            "severity": severity,
            "message": error_message,
            "payload": payload or {}
        }
        self._append_jsonl("errors.jsonl", record)
        
    def add_trajectory_attempt(self, level_id: int, prompt: str, response: str, solved: bool, error: Optional[str] = None):
        attempt = Redactor.redact_dict({
            "level_id": level_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "prompt": prompt,
            "response": response,
            "solved": solved,
            "error": error
        })
        self.trajectory.append(attempt)
        with open(self.run_dir / "trajectory.json", "w", encoding="utf-8") as f:
            json.dump(self.trajectory, f, indent=2)

    def update_meta(self, **kwargs):
        self.meta.update(kwargs)
        self._write_meta()

    def finish_run(self):
        self.meta["end_time"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if self.meta["status"] == "running":
            self.meta["status"] = "completed"
        self._write_meta()
        self.generate_report()
        self.log_event("observability", "run_finished", message="Run finished")

    def generate_report(self):
        report_path = self.run_dir / "report.md"
        meta = self.meta
        
        md = f"# Wizard Leak Lab Run Report\n\n"
        md += f"**Run ID:** {meta.get('run_id')}\n"
        md += f"**Start Time:** {meta.get('start_time')}\n"
        md += f"**End Time:** {meta.get('end_time', 'N/A')}\n"
        md += f"**Status:** {meta.get('status')}\n"
        md += f"**Strategy:** {meta.get('strategy')}\n"
        md += f"**Levels Attempted:** {meta.get('levels_attempted')}\n"
        md += f"**Levels Solved:** {meta.get('levels_solved')}\n"
        md += f"**Levels Failed:** {meta.get('levels_failed')}\n\n"
        
        md += "## Summary\n\n"
        
        # Analyze trajectory to summarize level by level
        level_status = {}
        for attempt in self.trajectory:
            lvl = attempt["level_id"]
            if lvl not in level_status:
                level_status[lvl] = {"solved": False, "attempts": 0}
            level_status[lvl]["attempts"] += 1
            if attempt["solved"]:
                level_status[lvl]["solved"] = True
                
        md += "| Level | Attempts | Solved |\n"
        md += "|---|---|---|\n"
        for lvl in sorted(level_status.keys()):
            stats = level_status[lvl]
            solved_str = "✅ Yes" if stats["solved"] else "❌ No"
            md += f"| Level {lvl} | {stats['attempts']} | {solved_str} |\n"
            
        md += "\n## Notable Errors\n\n"
        errors_path = self.run_dir / "errors.jsonl"
        if errors_path.exists():
            with open(errors_path, "r", encoding="utf-8") as f:
                for line in f:
                    err = json.loads(line)
                    md += f"- **{err.get('component')}** ({err.get('severity')}): {err.get('message')}\n"
        else:
            md += "No errors logged.\n"
            
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md)
