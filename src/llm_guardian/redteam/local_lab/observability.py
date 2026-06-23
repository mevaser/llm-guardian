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
            "levels_failed": 0,
            "total_attempts": 0,
            "unique_prompt_count": 0,
            "duplicate_prompt_count": 0,
            "adaptation_count": 0,
            "refused_count": 0,
            "filtered_count": 0,
            "irrelevant_count": 0
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

    def log_event(self, component: str, event_type: str, level_id: Optional[int] = None, session_id: Optional[str] = None, message: str = "", payload: Optional[Dict[str, Any]] = None, **kwargs):
        record = {
            "component": component,
            "event_type": event_type,
            "level_id": level_id,
            "session_id": session_id,
            "message": message,
            "payload": payload or {}
        }
        record.update(kwargs)
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
        
        if meta.get("strategy") == "autonomous":
            md += "## Trajectory Metrics\n\n"
            md += f"- **Total Attempts:** {meta.get('total_attempts', 0)}\n"
            md += f"- **Unique Prompts:** {meta.get('unique_prompt_count', 0)}\n"
            md += f"- **Duplicate Prompts Blocked:** {meta.get('duplicate_prompt_count', 0)}\n"
            md += f"- **Adaptations Triggered:** {meta.get('adaptation_count', 0)}\n"
            md += f"- **Refusals Encountered:** {meta.get('refused_count', 0)}\n"
            md += f"- **Filters Triggered:** {meta.get('filtered_count', 0)}\n"
            md += f"- **Irrelevant Responses:** {meta.get('irrelevant_count', 0)}\n\n"
        
        # Pull events to build detailed report
        events = []
        events_path = self.run_dir / "events.jsonl"
        if events_path.exists():
            with open(events_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
        
        # Analyze trajectory to summarize level by level
        level_status = {}
        for attempt in self.trajectory:
            lvl = attempt["level_id"]
            if lvl not in level_status:
                level_status[lvl] = {"solved": False, "attempts": 0}
            level_status[lvl]["attempts"] += 1
            if attempt["solved"]:
                level_status[lvl]["solved"] = True
                
        md += "## Summary\n\n"
        md += "| Level | Attempts | Solved |\n"
        md += "|---|---|---|\n"
        for lvl in sorted(level_status.keys()):
            stats = level_status[lvl]
            solved_str = "✅ Yes" if stats["solved"] else "❌ No"
            md += f"| Level {lvl} | {stats['attempts']} | {solved_str} |\n"
            
        if meta.get("strategy") == "autonomous":
            md += "\n## Autonomous Run Details\n\n"
            md += "> [!NOTE]\n"
            md += "> Rationale summaries below are model-generated explanations from the planner, not hidden chain-of-thought.\n\n"
            
            # Group events by level
            for lvl in sorted(level_status.keys()):
                md += f"### Level {lvl}\n"
                lvl_events = [e for e in events if e.get("level_id") == lvl]
                
                # Extract planner details from first decision
                first_decision = next((e for e in lvl_events if e.get("event_type") == "agent_decision"), None)
                if first_decision and first_decision.get("payload", {}).get("planner_model"):
                    md += f"- **Planner Model**: `{first_decision['payload']['planner_model']}`\n"
                    
                md += "\n#### Attempts\n\n"
                
                for attempt_num in range(1, level_status[lvl]["attempts"] + 1):
                    md += f"**Attempt {attempt_num}**\n"
                    
                    decision = next((e for e in lvl_events if e.get("event_type") == "agent_decision" and e.get("payload", {}).get("turn") == attempt_num), None)
                    wizard_resp = next((e for e in lvl_events if e.get("event_type") == "wizard_response" and e.get("payload", {}).get("turn") == attempt_num), None)
                    
                    if decision:
                        payload = decision.get("payload", {})
                        if payload.get("strategy_name"):
                            md += f"- **Strategy:** {payload['strategy_name']}\n"
                        if payload.get("rationale_summary"):
                            md += f"- **Rationale:** {payload['rationale_summary']}\n"
                        if payload.get("selected_prompt"):
                            md += f"- **Prompt:** `{payload['selected_prompt']}`\n"
                        if payload.get("duplicate_prompt_detected"):
                            md += f"- **Duplicate Blocked:** {payload.get('rejected_prompt_reason')}\n"
                        if payload.get("adaptation_reason"):
                            md += f"- **Adaptation Reason:** {payload['adaptation_reason']}\n"
                            
                    if wizard_resp:
                        w_payload = wizard_resp.get("payload", {})
                        md += f"- **Outcome:** {w_payload.get('outcome_type', 'unknown')}\n"
                        md += f"- **Response:** {w_payload.get('response', '')}\n"
                        if w_payload.get("solved"):
                            md += "- **Result:** ✅ Solved\n"
                    md += "\n"
        
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
